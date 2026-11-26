"""Explicit, single-session mTLS RTT transport. Not an agent runtime service.

No network bind at import, no remote grant issuance, no arbitrary payloads.
The local caller owns certificates, directional approvals, token delivery,
cancellation and lifecycle. All network operations use absolute deadlines.
"""
import errno
import hashlib
import hmac
import ipaddress
import os
import select
import socket
import ssl
import time
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from .peer_contract import RTTPlan,RTTReport,RTTSample,PeerDirection,FRAME_BYTES,MAX_SESSION_SECONDS
from .scope import validate_ip

MAGIC=b"NDR1"
HEADER_BYTES=4+43+32+1
ACK=b"\x01"
ALPN="ndc-rtt/1"

class PeerDenied(Exception):pass
class PeerDeadline(Exception):pass
class PeerCancelled(Exception):pass

def checked_ip(value):
    ip=str(ipaddress.ip_address(value))
    if "%" in ip or getattr(ipaddress.ip_address(ip),"ipv4_mapped",None) is not None or validate_ip(ip)!=ip:
        raise PeerDenied("Invalid peer address")
    return ip

def family(ip):
    return socket.AF_INET if ipaddress.ip_address(ip).version==4 else socket.AF_INET6

def address(ip,port):
    return (ip,port) if family(ip)==socket.AF_INET else (ip,port,0,0)

def credentials(cert,key,ca,*,server,alpn=ALPN):
    # Explicit trust store only; no system roots or insecure mode.
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    if not server:ctx.check_hostname=True
    ctx.load_verify_locations(cafile=str(ca))
    ctx.load_cert_chain(str(cert),str(key))
    ctx.set_alpn_protocols([alpn])
    if server:ctx.num_tickets=0
    fp=x509.load_pem_x509_certificate(Path(cert).read_bytes()).fingerprint(hashes.SHA256()).hex()
    return ctx,fp

def check(deadline,cancel):
    if cancel.is_set():raise PeerCancelled()
    if time.monotonic()>=deadline:raise PeerDeadline()

def wait(sock,deadline,cancel,*,read=False,write=False):
    while True:
        check(deadline,cancel)
        r,w,_=select.select([sock] if read else [],[sock] if write else [],[],min(.1,max(0,deadline-time.monotonic())))
        if r or w:return

def perform(sock,action,deadline,cancel,*,write=False):
    while True:
        check(deadline,cancel)
        try:return action()
        except ssl.SSLWantReadError:wait(sock,deadline,cancel,read=True)
        except ssl.SSLWantWriteError:wait(sock,deadline,cancel,write=True)
        except BlockingIOError:wait(sock,deadline,cancel,read=not write,write=write)

def read_exact(sock,n,deadline,cancel):
    result=bytearray()
    while len(result)<n:
        data=perform(sock,lambda:sock.recv(n-len(result)),deadline,cancel)
        if not data:raise PeerDenied("Truncated frame")
        result.extend(data)
    return bytes(result)

def write_exact(sock,data,deadline,cancel):
    pos=0
    while pos<len(data):
        n=perform(sock,lambda:sock.send(data[pos:]),deadline,cancel,write=True)
        if n<=0:raise PeerDenied("Incomplete frame")
        pos+=n

def fingerprint(sock,alpn=ALPN):
    cert=sock.getpeercert(binary_form=True)
    if not cert or sock.selected_alpn_protocol()!=alpn:raise PeerDenied("Peer protocol denied")
    return hashlib.sha256(cert).hexdigest()

def header(plan,token):
    if not isinstance(token,str) or len(token)!=43 or not token.isascii() or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in token):
        raise PeerDenied("Invalid authorization")
    return MAGIC+token.encode("ascii")+plan.request_id.encode("ascii")+bytes([plan.samples])

def error_code(exc):
    if isinstance(exc,PeerCancelled):return "cancelled"
    if isinstance(exc,PeerDeadline):return "deadline"
    if isinstance(exc,(PeerDenied,ssl.SSLError,PermissionError,ValueError)):return "authorization_or_protocol_denied"
    return "transport_error"

class Receiver:
    """Local opt-in one-shot listener. Exactly one accepted connection.

    No automatic retry, background thread, public control API or bind wildcard.
    A failed handshake consumes the listener opportunity, not the grant.
    The operator must close/recreate it explicitly.
    """
    alpn=ALPN

    def __init__(self,ip,port,grants,*,cert,key,ca):
        self.ip=checked_ip(ip);self.port=port;self.grants=grants
        self.ctx,self.fp=credentials(cert,key,ca,server=True,alpn=self.alpn)
        self.approvals=tuple(a for a in grants.approvals if a.destination_ip==self.ip and a.port==port and a.destination_certificate==self.fp)
        if not self.approvals:raise PeerDenied("No locally approved listener")
        # Grant clock must be the same monotonic clock as transport.
        if grants.clock is not time.monotonic:raise ValueError("Transport requires real monotonic clock")
        self.listener=socket.socket(family(self.ip),socket.SOCK_STREAM)
        self.used=False
        try:
            # Permit explicit successive one-shot sessions after TCP TIME_WAIT.
            # Never use SO_REUSEPORT: an already listening socket must retain
            # exclusive ownership of the configured endpoint.
            self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            self.listener.bind(address(self.ip,port));self.listener.listen(1);self.listener.setblocking(False)
        except BaseException:
            self.listener.close();raise

    def close(self):self.listener.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

    def serve_once(self,cancel):
        if self.used:raise RuntimeError("One-shot receiver already used")
        self.used=True
        deadline=time.monotonic()+MAX_SESSION_SECONDS
        count=0
        try:
            raw,_=perform(self.listener,self.listener.accept,deadline,cancel)
            # Close listener immediately; no extra accepted connections.
            self.close()
            with raw:
                source=checked_ip(raw.getpeername()[0]);dest=checked_ip(raw.getsockname()[0])
                if not any(a.source_ip==source and a.destination_ip==dest for a in self.approvals):
                    raise PeerDenied("Unapproved socket")
                raw.setblocking(False)
                with self.ctx.wrap_socket(raw,server_side=True,do_handshake_on_connect=False) as tls:
                    perform(tls,tls.do_handshake,deadline,cancel)
                    remote=fingerprint(tls)
                    candidates=[a for a in self.approvals if a.source_ip==source and a.destination_ip==dest and a.source_certificate==remote]
                    if len(candidates)!=1:raise PeerDenied("Peer identity not unique or approved")
                    # Identity is derived only from configured pins and actual
                    # endpoints, not from any agent IDs sent over the wire.
                    d=candidates[0]
                    raw_header=read_exact(tls,HEADER_BYTES,deadline,cancel)
                    if raw_header[:4]!=MAGIC:raise PeerDenied("Wrong protocol")
                    token=raw_header[4:47].decode("ascii")
                    plan=RTTPlan(request_id=raw_header[47:79].decode("ascii"),direction=d,samples=raw_header[79])
                    authorized=self.grants.consume(token,plan,verified_direction=d)
                    if authorized is None:raise PeerDenied("Grant denied")
                    deadline=min(deadline,authorized)
                    write_exact(tls,ACK,deadline,cancel)
                    for _ in range(plan.samples):
                        frame=read_exact(tls,FRAME_BYTES,deadline,cancel)
                        write_exact(tls,frame,deadline,cancel)
                        count+=1
                    return count,None
        except (OSError,ValueError,PeerDenied,PeerDeadline,PeerCancelled) as exc:
            return count,error_code(exc)
        finally:self.close()

def measure(plan,token,approvals,cancel,*,cert,key,ca):
    """Client performs a fixed number of nonce echoes after verified mTLS.

    RTT excludes connect/handshake and includes TLS/application echo overhead.
    No packet loss, one-way latency or bandwidth inference.
    """
    plan=RTTPlan.model_validate(plan.model_dump(mode="json"))
    d=plan.direction;samples=[]
    deadline=time.monotonic()+MAX_SESSION_SECONDS
    try:
        if d not in approvals:raise PeerDenied("Local outbound approval required")
        source=checked_ip(d.source_ip);dest=checked_ip(d.destination_ip)
        ctx,fp=credentials(cert,key,ca,server=False)
        if not hmac.compare_digest(fp,d.source_certificate):raise PeerDenied("Local certificate mismatch")
        frame_header=header(plan,token)
        check(deadline,cancel)
        with socket.socket(family(dest),socket.SOCK_STREAM) as raw:
            raw.setblocking(False)
            raw.bind(address(source,0))
            code=raw.connect_ex(address(dest,d.port))
            if code not in (0,errno.EINPROGRESS,errno.EWOULDBLOCK,errno.EALREADY):raise OSError(code,"Connect failed")
            if code:
                wait(raw,deadline,cancel,write=True)
                if raw.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR):raise OSError("Connect failed")
            if checked_ip(raw.getsockname()[0])!=source or checked_ip(raw.getpeername()[0])!=dest:
                raise PeerDenied("Socket direction mismatch")
            with ctx.wrap_socket(raw,server_hostname=dest,do_handshake_on_connect=False) as tls:
                perform(tls,tls.do_handshake,deadline,cancel)
                if not hmac.compare_digest(fingerprint(tls),d.destination_certificate):raise PeerDenied("Destination pin mismatch")
                write_exact(tls,frame_header,deadline,cancel)
                if read_exact(tls,1,deadline,cancel)!=ACK:raise PeerDenied("Grant not acknowledged")
                for i in range(1,plan.samples+1):
                    nonce=os.urandom(FRAME_BYTES);start=time.monotonic()
                    write_exact(tls,nonce,deadline,cancel)
                    echoed=read_exact(tls,FRAME_BYTES,deadline,cancel)
                    if not hmac.compare_digest(echoed,nonce):raise PeerDenied("Echo mismatch")
                    check(deadline,cancel)
                    samples.append(RTTSample(index=i,status="echo",rtt_ms=round((time.monotonic()-start)*1000,3)))
        return RTTReport(plan=plan,samples=samples),None
    except (OSError,ValueError,PeerDenied,PeerDeadline,PeerCancelled) as exc:
        return RTTReport(plan=plan,samples=samples),error_code(exc)
