"""Linux UDP traceroute using kernel extended errors; no raw socket."""
import ipaddress
import os
import select
import socket
import struct
import sys
import time
from .connectivity import resolve_host, families, ms, error
from ..scope import validate_ip

def options(family):
    if family=="ipv4":
        return socket.AF_INET,socket.IPPROTO_IP,11,socket.IP_TTL
    return socket.AF_INET6,socket.IPPROTO_IPV6,25,socket.IPV6_UNICAST_HOPS

def route_socket(family):
    if not sys.platform.startswith("linux") or not hasattr(socket,"MSG_ERRQUEUE"):
        raise OSError("Linux extended error queue unavailable")
    af,level,opt,_=options(family)
    sock=socket.socket(af,socket.SOCK_DGRAM)
    try:
        sock.setsockopt(level,opt,1)
        return sock
    except BaseException:
        sock.close()
        raise

def route_capabilities():
    caps={}
    for family in ("ipv4","ipv6"):
        try:
            with route_socket(family):
                caps[family]=True
        except OSError:
            caps[family]=False
    return caps

def decode_error(ancillary,family):
    _,level,opt,_=options(family)
    for lev,typ,data in ancillary:
        if lev!=level or typ!=opt or len(data)<16:
            continue
        errno,origin,itype,code,_,info,_=struct.unpack_from("=IBBBBII",data)
        if origin!=(2 if family=="ipv4" else 3):
            return {"status":"local_error","address":None,"icmp_type":itype,"icmp_code":code,"errno":errno}
        addr=None
        if len(data)>=18:
            af=struct.unpack_from("=H",data,16)[0]
            if af==socket.AF_INET and len(data)>=24:
                addr=socket.inet_ntop(af,data[20:24])
            elif af==socket.AF_INET6 and len(data)>=40:
                addr=socket.inet_ntop(af,data[24:40])
        expired=(itype==11 and code==0) if family=="ipv4" else (itype==3 and code==0)
        unreachable=(itype==3 and code==3) if family=="ipv4" else (itype==1 and code==4)
        return {"status":"hop" if expired else "port_unreachable" if unreachable else "icmp_error",
                "address":addr,"icmp_type":itype,"icmp_code":code,"errno":errno}
    return None

def probe(ip,family,ttl):
    # Fresh socket per probe avoids stale ICMP errors and keeps correlation simple.
    # ECMP may select different routes for different source ports.
    row={"status":"timeout","address":None,"rtt_ms":None,"icmp_type":None,"icmp_code":None,"errno":None,"error":None}
    try:
        _,level,_,ttl_opt=options(family)
        with route_socket(family) as sock:
            sock.setsockopt(level,ttl_opt,ttl)
            sock.connect((validate_ip(ip),33434))
            sock.setblocking(False)
            nonce=os.urandom(16)
            start=time.monotonic()
            sock.send(nonce)
            deadline=start+1.0
            poll=select.poll()
            poll.register(sock,select.POLLERR)
            while True:
                remain=deadline-time.monotonic()
                if remain<=0 or not poll.poll(max(1,int(remain*1000))):
                    return row
                try:
                    payload,ancillary,flags,_=sock.recvmsg(1024,512,socket.MSG_ERRQUEUE|socket.MSG_DONTWAIT)
                except BlockingIOError:
                    continue
                if flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC):
                    continue
                if payload!=nonce:
                    continue
                event=decode_error(ancillary,family)
                if event is None:
                    continue
                row.update(event,rtt_ms=ms(start))
                if row["status"]=="port_unreachable" and row["address"]:
                    if ipaddress.ip_address(row["address"])==ipaddress.ip_address(ip):
                        row["status"]="destination"
                return row
    except OSError as exc:
        row.update(status="local_error",error=error(exc))
    return row

def trace_family(config,family):
    result={"family":family,"ip":None,"dns_ms":None,"available":True,"reached":False,"hops":[],"error":None}
    try:
        with route_socket(family):
            pass
    except OSError as exc:
        result.update(available=False,error=error(exc))
        return result
    start=time.monotonic()
    try:
        ip=resolve_host(config.host,33434,family)
        result.update(ip=ip,dns_ms=ms(start))
    except Exception as exc:
        result.update(dns_ms=ms(start),error=error(exc))
        return result
    for ttl in range(1,config.max_hops+1):
        samples=[]
        for _ in range(config.attempts):
            sample=probe(ip,family,ttl)
            samples.append(sample)
            if sample["status"]=="destination":
                result["reached"]=True
            if sample["status"]=="local_error":
                result["error"]=sample["error"] or "Local socket error"
                break
        result["hops"].append({"ttl":ttl,"samples":samples})
        if result["reached"] or result["error"]:
            break
    return result

def trace(config):
    return {"host":config.host,"method":"udp-error-queue","vantage":"container",
            "results":[trace_family(config,f) for f in families(config.family)]}
