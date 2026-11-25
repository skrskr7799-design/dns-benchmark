"""Small, scoped diagnostics; no shell, redirects, proxy or raw sockets."""
import ipaddress
import os
import socket
import ssl
import statistics
import struct
import time
from contextlib import ExitStack
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from ..scope import validate_ip

def ms(start):
    return round((time.monotonic()-start)*1000,3)

def error(exc):
    return (type(exc).__name__+": "+str(exc))[:250]

def resolve_host(host,port,family):
    af=socket.AF_INET if family=="ipv4" else socket.AF_INET6
    addresses=socket.getaddrinfo(host,port,af,socket.SOCK_STREAM)
    checked=[validate_ip(a[4][0]) for a in addresses]
    if not checked:
        raise OSError("No address for selected family")
    return checked[0]

def families(family):
    return ["ipv4","ipv6"] if family=="both" else [family]

def certificate(der):
    cert=x509.load_der_x509_certificate(der)
    try:
        san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names=[str(n.value) for n in san if isinstance(n,(x509.DNSName,x509.IPAddress))]
    except x509.ExtensionNotFound:
        names=[]
    from datetime import datetime,timezone
    expiry=cert.not_valid_after_utc
    return {"subject":cert.subject.rfc4514_string(),"issuer":cert.issuer.rfc4514_string(),
            "serial":format(cert.serial_number,"x"),"not_before":cert.not_valid_before_utc.isoformat(),
            "not_after":expiry.isoformat(),"days_remaining":round((expiry-datetime.now(timezone.utc)).total_seconds()/86400,2),
            "sha256":cert.fingerprint(hashes.SHA256()).hex(),"san":names}

def base(host,port,family):
    return {"host":host,"port":port,"family":family,"ip":None,"peer_ip":None,"source_ip":None,
            "dns_ms":None,"connect_ms":None,"handshake_ms":None,"ttfb_ms":None,
            "headers_ms":None,"total_ms":None,"http_status":None,"tls_version":None,
            "alpn":None,"cipher":None,"certificate":None,"chain":None,
            "verified":None,"stage":"resolve","error":None,"ok":False}

def tls_wrap(raw,host,stack,protocols):
    ctx=ssl.create_default_context(cafile=os.getenv("NDC_CA_FILE"))
    ctx.set_alpn_protocols(protocols)
    return stack.enter_context(ctx.wrap_socket(raw,server_hostname=host))

def probe_once(host,port,family,kind,path="/",ip=None,dns_ms=None):
    out=base(host,port,family)
    start=time.monotonic()
    try:
        if ip is None:
            t=time.monotonic()
            try:
                ip=resolve_host(host,port,family)
            finally:
                out["dns_ms"]=ms(t)
        else:
            out["dns_ms"]=dns_ms
        out["ip"]=validate_ip(ip)
        out["stage"]="tcp"
        with ExitStack() as stack:
            t=time.monotonic()
            raw=stack.enter_context(socket.create_connection((out["ip"],port),timeout=3))
            out["connect_ms"]=ms(t)
            out["peer_ip"]=validate_ip(raw.getpeername()[0])
            out["source_ip"]=raw.getsockname()[0]
            if out["peer_ip"]!=out["ip"]:
                raise ValueError("Unexpected peer")
            conn=raw
            if kind in ("https","tls"):
                out["stage"]="tls"
                t=time.monotonic()
                try:
                    conn=tls_wrap(raw,host,stack,["http/1.1"] if kind=="https" else ["h2","http/1.1"])
                except ssl.SSLCertVerificationError:
                    out["verified"]=False
                    raise
                out["handshake_ms"]=ms(t)
                out["verified"]=True
                out["tls_version"]=conn.version()
                out["alpn"]=conn.selected_alpn_protocol()
                out["cipher"]=conn.cipher()[0]
                out["certificate"]=certificate(conn.getpeercert(binary_form=True))
                if hasattr(conn,"get_verified_chain"):
                    out["chain"]=[certificate(der) for der in conn.get_verified_chain()]
            if kind in ("http","https"):
                out["stage"]="http"
                # HEAD only; no redirect following or body reads. Absolute read deadline.
                authority=f"[{host}]" if ":" in host else host
                authority+=f":{port}"
                request=f"HEAD {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: NDC/0.3\r\n\r\n".encode("ascii")
                t=time.monotonic()
                conn.sendall(request)
                deadline=t+3
                data=bytearray()
                while b"\r\n\r\n" not in data:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:
                        raise TimeoutError("HTTP header deadline")
                    conn.settimeout(remaining)
                    chunk=conn.recv(min(4096,32769-len(data)))
                    if not chunk:
                        raise ValueError("Incomplete HTTP headers")
                    if not data:
                        out["ttfb_ms"]=ms(t)
                    data.extend(chunk)
                    if len(data)>32768:
                        raise ValueError("HTTP header limit exceeded")
                line=bytes(data).split(b"\r\n",1)[0].split()
                if len(line)<2 or line[0] not in (b"HTTP/1.0",b"HTTP/1.1") or len(line[1])!=3 or not line[1].isdigit():
                    raise ValueError("Invalid HTTP status")
                status=int(line[1])
                if not 200<=status<=599:
                    raise ValueError("Unsupported HTTP status")
                out["http_status"]=status
                out["headers_ms"]=ms(t)
            out["stage"]="complete"
            out["ok"]=True
    except Exception as exc:
        out["error"]=error(exc)
    out["total_ms"]=ms(start)
    return out

def ping_socket(family):
    af=socket.AF_INET if family=="ipv4" else socket.AF_INET6
    proto=socket.IPPROTO_ICMP if family=="ipv4" else socket.IPPROTO_ICMPV6
    return socket.socket(af,socket.SOCK_DGRAM,proto)

def ping_capabilities():
    result={}
    for family in ("ipv4","ipv6"):
        try:
            with ping_socket(family):
                result[family]=True
        except OSError:
            result[family]=False
    return result

def ping_one(host,family,count):
    out={"family":family,"ip":None,"source_ip":None,"dns_ms":None,"samples":[],
         "available":True,"error":None,"sent":0,"received":0,"loss_pct":None,
         "mean_ms":None,"variation_ms":None}
    try:
        sock=ping_socket(family)
    except OSError as exc:
        out.update(available=False,error=error(exc))
        return out
    try:
        with sock:
            t=time.monotonic()
            try:
                ip=resolve_host(host,0,family)
            finally:
                out["dns_ms"]=ms(t)
            out["ip"]=ip
            sock.connect((ip,0))
            out["source_ip"]=sock.getsockname()[0]
            for seq in range(count):
                nonce=os.urandom(16)
                echo=8 if family=="ipv4" else 128
                reply=0 if family=="ipv4" else 129
                packet=struct.pack("!BBHHH",echo,0,0,0,seq)+nonce
                t=time.monotonic()
                try:
                    sock.send(packet)
                    out["sent"]+=1
                    deadline=t+2
                    while True:
                        remaining=deadline-time.monotonic()
                        if remaining<=0:
                            raise TimeoutError("ICMP echo deadline")
                        sock.settimeout(remaining)
                        data=sock.recv(1024)
                        if len(data)>=24 and data[0]==reply and data[1]==0 and struct.unpack("!H",data[6:8])[0]==seq and data[8:24]==nonce:
                            out["samples"].append({"ok":True,"duration_ms":ms(t),"error":None})
                            break
                except OSError as exc:
                    out["samples"].append({"ok":False,"duration_ms":None,"error":error(exc)})
    except Exception as exc:
        out["error"]=error(exc)
    values=[s["duration_ms"] for s in out["samples"] if s["ok"]]
    out["received"]=len(values)
    if out["sent"]:
        out["loss_pct"]=round(100*(out["sent"]-len(values))/out["sent"],2)
    if values:
        out["mean_ms"]=round(statistics.mean(values),3)
        out["variation_ms"]=round(statistics.pstdev(values),3)
    return out

def connectivity(config):
    if config.kind=="icmp":
        return {"kind":"icmp","host":config.host,"vantage":"container",
                "results":[ping_one(config.host,f,config.count) for f in families(config.family)]}
    results=[]
    for family in families(config.family):
        t=time.monotonic()
        try:
            ip=resolve_host(config.host,config.port,family)
        except Exception as exc:
            row=base(config.host,config.port,family)
            row.update(dns_ms=ms(t),error=error(exc))
            results.append({"family":family,"ip":None,"samples":[row],"attempted":0,"success":0,"mean_ms":None,"variation_ms":None})
            continue
        dns_ms=ms(t)
        samples=[probe_once(config.host,config.port,family,config.kind,config.path,ip,dns_ms) for _ in range(config.count)]
        values=[s["connect_ms"] for s in samples if s["connect_ms"] is not None]
        results.append({"family":family,"ip":ip,"samples":samples,"attempted":len(samples),
                        "success":sum(s["ok"] for s in samples),"mean_ms":round(statistics.mean(values),3) if values else None,
                        "variation_ms":round(statistics.pstdev(values),3) if values else None})
    return {"kind":config.kind,"host":config.host,"vantage":"container","results":results}

def inspect_tls(config):
    return {"host":config.host,"vantage":"container",
            "results":[probe_once(config.host,config.port,f,"tls") for f in families(config.family)]}
