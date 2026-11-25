"""Opt-in, operator-pinned integrations. No arbitrary URL fetching from API."""
import ipaddress
import json
import math
import os
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit
import httpx
import dns.query
from .scope import validate_ip
from .models import NetworkTarget, Connectivity

MAX_JSON=2*1024*1024
MAX_DOWNLOAD=8*1024*1024

def config_file(root,name):
    path=Path(root)/name
    if not path.exists():
        return None
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_mode&0o077 or path.stat().st_size>16384:
        raise ValueError("Integration configuration must be a regular private file")
    cfg=json.loads(path.read_text())
    if not isinstance(cfg,dict):
        raise ValueError("Invalid integration configuration")
    return cfg

class Target:
    def __init__(self,cfg):
        u=urlsplit(cfg["origin"])
        if u.scheme not in ("http","https") or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ("","/"):
            raise ValueError("Invalid integration origin")
        host=NetworkTarget(host=u.hostname).host
        if host!=u.hostname:
            raise ValueError("Use canonical ASCII host")
        if u.port is not None and not 1<=u.port<=65535:
            raise ValueError("Invalid port")
        self.ip=validate_ip(cfg["ip"])
        try:
            literal=ipaddress.ip_address(host)
        except ValueError:
            literal=None
        if literal is not None and str(literal)!=self.ip:
            raise ValueError("Origin IP and pinned IP differ")
        if u.scheme=="http" and (cfg.get("allow_http") is not True or ipaddress.ip_address(self.ip).is_global):
            raise ValueError("HTTPS required; explicit HTTP only on trusted private network")
        self.origin=cfg["origin"].rstrip("/")
        self.verify=os.getenv("NDC_CA_FILE") or True
        self.username=cfg.get("username")
        self.password=cfg.get("password")
        if (self.username is None)!=(self.password is None):
            raise ValueError("Both username and password required")
        if self.username is not None and (not isinstance(self.username,str) or not isinstance(self.password,str) or ":" in self.username or len(self.username)>256 or len(self.password)>1024):
            raise ValueError("Invalid credentials")

    def client(self):
        validate_ip(self.ip)
        transport=dns.query._HTTPTransport(bootstrap_address=self.ip,http1=True,http2=False,verify=self.verify,trust_env=False)
        return httpx.Client(transport=transport,trust_env=False,follow_redirects=False,timeout=httpx.Timeout(3),auth=(self.username,self.password) if self.username is not None else None,headers={"Accept-Encoding":"identity"})

def read_json(target,path):
    with target.client() as client,client.stream("GET",target.origin+path) as r:
        if r.status_code!=200:
            raise ValueError("Upstream HTTP "+str(r.status_code))
        if r.headers.get("content-encoding","identity").lower()!="identity":
            raise ValueError("Unexpected encoding")
        data=bytearray()
        deadline=time.monotonic()+8
        for chunk in r.iter_raw(chunk_size=16384):
            if time.monotonic()>deadline or len(data)+len(chunk)>MAX_JSON:
                raise ValueError("Response budget exceeded")
            data.extend(chunk)
        value=json.loads(data)
        if not isinstance(value,dict):
            raise ValueError("Unexpected response")
        return value

def number(v):
    return v if type(v) in (float,int) and 0<=v<=1e15 and math.isfinite(v) else None

def safe_upstream(value):
    # Strip paths, query parameters, user info and conditional domain names.
    if not isinstance(value,str) or len(value)>2048 or value.startswith(("[/","#")):
        return None
    try:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
        u=urlsplit(value if "://" in value else "//"+value)
        if u.scheme not in ("","udp","tcp","tls","https","h3","quic") or not u.hostname:
            return None
        host=NetworkTarget(host=u.hostname).host
        if ":" in host:
            host="["+host+"]"
        return (u.scheme+"://" if u.scheme else "")+host+(":"+str(u.port) if u.port else "")
    except ValueError:
        return None

def snapshot(target):
    sections={}
    errors={}
    for name,path in (("status","/control/status"),("stats","/control/stats"),("dns","/control/dns_info")):
        try:
            sections[name]=read_json(target,path)
        except Exception as exc:
            # Never return exception strings containing URLs or credentials.
            errors[name]=type(exc).__name__
    status=sections.get("status",{})
    stats=sections.get("stats",{})
    dns=sections.get("dns",{})
    upstreams=dns.get("upstream_dns")
    safe=[safe_upstream(v) for v in upstreams[:100]] if isinstance(upstreams,list) else []
    times=stats.get("top_upstreams_avg_time")
    timings=[]
    if isinstance(times,list):
        for item in times[:100]:
            if isinstance(item,dict):
                for key,val in list(item.items())[:10]:
                    addr=safe_upstream(key)
                    n=number(val)
                    if addr and n is not None:
                        timings.append({"upstream":addr,"mean_ms":round(n*1000,3)})
    avg=number(stats.get("avg_processing_time"))
    return {"configured":True,"errors":errors,"at":time.time(),
            "version":status.get("version")[:80] if isinstance(status.get("version"),str) else None,
            "protection_enabled":status.get("protection_enabled") if type(status.get("protection_enabled")) is bool else None,
            "running":status.get("running") if type(status.get("running")) is bool else None,
            "queries":number(stats.get("num_dns_queries")),"blocked":number(stats.get("num_blocked_filtering")),
            "mean_ms":round(avg*1000,3) if avg is not None else None,
            "upstreams":list(dict.fromkeys(v for v in safe if v)),"upstreams_omitted":len(upstreams)-len([v for v in safe if v]) if isinstance(upstreams,list) else None,
            "upstream_timings":timings,"time_units":stats.get("time_units") if stats.get("time_units") in ("hours","days") else None}

def throughput(target,path):
    # Fixed, operator-approved GET; no uploads, redirects or decompression.
    path=Connectivity(host="localhost",path=path).path
    started=time.monotonic()
    count=0
    reason="complete"
    body_start=None
    try:
        with target.client() as client,client.stream("GET",target.origin+path) as r:
            if r.status_code!=200 or r.headers.get("content-encoding","identity").lower()!="identity":
                raise ValueError("Expected HTTP 200 identity response")
            body_start=time.monotonic()
            for chunk in r.iter_raw(chunk_size=16384):
                count+=len(chunk)
                if count>=MAX_DOWNLOAD:
                    reason="byte_limit"
                    break
                if time.monotonic()-started>=10:
                    reason="time_limit"
                    break
    except Exception as exc:
        reason=type(exc).__name__
    elapsed=time.monotonic()-started
    return {"bytes":count,"duration_ms":round(elapsed*1000,3),"mbps":round(count*8/elapsed/1e6,3) if count and elapsed>0 else None,"reason":reason,"body_started":body_start is not None,"byte_limit":MAX_DOWNLOAD,"vantage":"container","method":"bounded-http-download"}

def load(root,name):
    cfg=config_file(root,name)
    if cfg is None:
        return None,None
    return Target(cfg),cfg
