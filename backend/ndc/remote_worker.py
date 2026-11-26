"""Locally approved single TCP measurement; fixed subprocess entrypoint."""
import ctypes
import hashlib
import http.client
import ssl
import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pydantic import Field,field_validator
from .remote_contract import Strict,RemoteConfig,RemoteTCP,RemoteHTTP,TCPObservation,ServiceObservation,config_key
from .scope import validate_ip

DEADLINE=12.0

class Approval(Strict):
    config:RemoteConfig
    cidrs:list[str]=Field(min_length=1,max_length=16)

    @field_validator("cidrs")
    @classmethod
    def networks(cls,values):
        nets=[ipaddress.ip_network(v,strict=True) for v in values]
        if any(n.prefixlen==0 for n in nets):raise ValueError("Unrestricted network")
        return [str(n) for n in nets]

def load_approvals(path):
    if not path.exists():return ()
    with path.open("rb") as f: raw=f.read(65537)
    if len(raw)>65536:raise ValueError("Approval file too large")
    rows=json.loads(raw)
    if not isinstance(rows,list) or len(rows)>64:raise ValueError("Invalid approval list")
    items=tuple(Approval.model_validate(r) for r in rows)
    if len({config_key(a.config) for a in items})!=len(items):raise ValueError("Duplicate approval")
    return items

def elapsed(t):return round((time.monotonic()-t)*1000,3)

def probe(cfg,approval):
    start=time.monotonic()
    def observation(**kw):
        kw["total_ms"]=elapsed(start)
        return TCPObservation(**kw) if cfg.kind=="tcp" else ServiceObservation(kind=cfg.kind,**kw)
    family=socket.AF_INET if cfg.family=="ipv4" else socket.AF_INET6
    nets=tuple(ipaddress.ip_network(v) for v in approval.cidrs)
    try:
        answers=socket.getaddrinfo(cfg.host,cfg.port,family,socket.SOCK_STREAM,socket.IPPROTO_TCP)
    except OSError:
        return observation(outcome="unknown",stage="resolve",dns_ms=elapsed(start))
    dns_ms=elapsed(start)
    if not answers:return observation(outcome="unknown",stage="resolve",dns_ms=dns_ms)
    if len(answers)>32:raise PermissionError("Too many addresses")
    addresses=[]
    for af,_,_,_,sockaddr in answers:
        ip=ipaddress.ip_address(sockaddr[0])
        if af!=family or ip.version!=(4 if family==socket.AF_INET else 6) or getattr(ip,"ipv4_mapped",None) is not None or "%" in str(ip):
            raise PermissionError("Wrong address family")
        if not any(ip in n for n in nets):raise PermissionError("Local approval denied")
        try:checked=validate_ip(str(ip))
        except ValueError as exc:raise PermissionError("Global scope denied") from exc
        if checked!=str(ip):raise PermissionError("Address normalization mismatch")
        addresses.append(checked)
    address=addresses[0]
    common={"address":address,"dns_ms":dns_ms}
    with socket.socket(family,socket.SOCK_STREAM,socket.IPPROTO_TCP) as sock:
        sock.settimeout(3)
        t=time.monotonic()
        try:sock.connect((address,cfg.port) if family==socket.AF_INET else (address,cfg.port,0,0))
        except PermissionError:raise
        except OSError:return observation(outcome="failure",stage="connect",**common)
        peer=str(ipaddress.ip_address(sock.getpeername()[0]))
        if peer!=address:raise PermissionError("Unexpected peer")
        common.update(peer_ip=peer,connect_ms=elapsed(t))
        if cfg.kind=="tcp":return observation(outcome="success",stage="complete",**common)
        def head(stream):
            host=("["+cfg.host+"]" if ":" in cfg.host else cfg.host)+":"+str(cfg.port)
            t=time.monotonic()
            try:
                stream.sendall(("HEAD "+cfg.path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\nUser-Agent: NDC-remote/2\r\n\r\n").encode("ascii"))
                with http.client.HTTPResponse(stream,method="HEAD") as response:
                    response.begin()
                    status=response.status
                    if not 200<=status<=599:raise http.client.HTTPException("Unexpected status")
                    if response.version!=11:raise http.client.HTTPException("Unsupported HTTP version")
                return observation(outcome="success" if status<400 else "failure",stage="complete",http_status=status,http_ms=elapsed(t),**common)
            except (OSError,http.client.HTTPException):
                return observation(outcome="failure",stage="http",**common)
        if cfg.kind=="http" and cfg.scheme=="http":return head(sock)
        ctx=ssl.create_default_context(cafile=os.getenv("NDC_CA_FILE") or None)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        if cfg.kind=="http":ctx.set_alpn_protocols(["http/1.1"])
        t=time.monotonic()
        try:secure=ctx.wrap_socket(sock,server_hostname=cfg.host)
        except ssl.SSLCertVerificationError:return observation(outcome="failure",stage="tls",verified=False,**common)
        except (OSError,ssl.SSLError):return observation(outcome="failure",stage="tls",**common)
        with secure:
            common.update(verified=True,fingerprint=hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest(),
                tls_version=secure.version(),tls_ms=elapsed(t))
            if cfg.kind=="tls":return observation(outcome="success",stage="complete",**common)
            if secure.selected_alpn_protocol() not in (None,"http/1.1"):
                return observation(outcome="failure",stage="http",**common)
            return head(secure)

def run_probe(cfg,approvals,cancel,*,deadline=DEADLINE):
    approval=next((a for a in approvals if a.config==cfg),None)
    if approval is None:return None,"local_policy_denied"
    if cancel.is_set():return None,"cancelled"
    end=time.monotonic()+deadline
    proc=subprocess.Popen([sys.executable,"-m","backend.ndc.remote_worker",str(os.getpid())],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
    data=approval.model_dump_json().encode()
    try:
        while True:
            if cancel.is_set():return None,"cancelled"
            remaining=end-time.monotonic()
            if remaining<=0:return None,"deadline"
            try:
                raw,_=proc.communicate(input=data,timeout=min(.1,remaining))
                if cancel.is_set():return None,"cancelled"
                if time.monotonic()>end:return None,"deadline"
                if proc.returncode!=0 or len(raw)>8192:return None,"internal_error"
                result=json.loads(raw)
                if result=={"error":"local_policy_denied"}:return None,"local_policy_denied"
                return (TCPObservation if cfg.kind=="tcp" else ServiceObservation).model_validate(result),None
            except subprocess.TimeoutExpired:
                data=None
            except (ValueError,TypeError):
                return None,"internal_error"
    finally:
        if proc.poll() is None:proc.kill()
        proc.communicate()

def run_tcp(cfg,approvals,cancel,*,deadline=DEADLINE):
    return run_probe(cfg,approvals,cancel,deadline=deadline)

def main():
    # Linux parent-death signal prevents an orphaned probe after agent crash.
    parent=int(sys.argv[1])
    if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:
        raise SystemExit(1)
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise SystemExit(1)
    approval=Approval.model_validate_json(raw)
    try:result=probe(approval.config,approval).model_dump(mode="json")
    except PermissionError:result={"error":"local_policy_denied"}
    print(json.dumps(result,allow_nan=False),flush=True)

if __name__=="__main__":main()
