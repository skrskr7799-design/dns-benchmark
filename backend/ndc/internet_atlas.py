"""Opt-in fixed-provider public Internet metadata, not active path discovery."""
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from collections import OrderedDict
from typing import Literal
from urllib.parse import urlsplit
import http.client
import socket
import ssl
from contextlib import nullcontext
from urllib.parse import urlencode
from .bounded_worker import bounded_worker
from pydantic import BaseModel,ConfigDict,Field,model_validator
from .models import NetworkTarget
from .scope import validate_ip
from .probes.connectivity import resolve_host

MAX_SECONDS=30
TTL=600
CACHE=OrderedDict()
RIPE="https://stat.ripe.net/data/"
IANA="https://data.iana.org/rdap/"
# Only fixed, explicitly supported RIR endpoints, even if bootstrap changes.
RIR={"https://rdap.arin.net/registry/","https://rdap.db.ripe.net/",
    "https://rdap.apnic.net/","https://rdap.lacnic.net/rdap/","https://rdap.afrinic.net/rdap/"}

def public_ip(value):
    ip=ipaddress.ip_address(value)
    if not ip.is_global or str(ip)!=validate_ip(str(ip)):raise ValueError("Public IP required")
    return ip

class AtlasRequest(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    target:str=Field(min_length=1,max_length=253)
    family:Literal["ipv4","ipv6"]="ipv4"
    @model_validator(mode="after")
    def normalize(self):
        v=self.target.strip()
        if re.fullmatch(r"(?i:AS)[0-9]{1,10}",v):
            n=int(v[2:])
            if not 1<=n<=4294967295:raise ValueError("Invalid ASN")
            self.target="AS"+str(n)
        else:
            try:ipaddress.ip_address(v)
            except ValueError:self.target=NetworkTarget(host=v).host
            else:self.target=str(public_ip(v))
        return self

def enabled():
    return os.getenv("NDC_ATLAS_ENABLED","0")=="1"

PROVIDER_HOSTS=frozenset(urlsplit(u).hostname for u in (RIPE,IANA,*RIR))

def provider_ip(host):
    if host not in PROVIDER_HOSTS:raise ValueError("Unknown provider host")
    addresses=socket.getaddrinfo(host,443,socket.AF_UNSPEC,socket.SOCK_STREAM)
    if not addresses:raise ValueError("Provider DNS unavailable")
    # Reject the entire DNS answer if any candidate is nonpublic, even if
    # controller LAN scopes would otherwise permit it.
    checked=[str(public_ip(a[4][0])) for a in addresses]
    return checked[0]

class ProviderConnection(http.client.HTTPSConnection):
    def connect(self):
        ip=provider_ip(self.host)
        raw=socket.create_connection((ip,443),timeout=self.timeout)
        try:
            if str(public_ip(raw.getpeername()[0]))!=ip:raise ValueError("Unexpected provider peer")
            self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
        except BaseException:
            raw.close();raise

def get(client,url,params=None):
    u=urlsplit(url)
    if u.scheme!="https" or u.hostname not in PROVIDER_HOSTS or u.port not in (None,443) or u.username is not None or u.password is not None or u.query or u.fragment:
        raise ValueError("Invalid provider destination")
    path=u.path+("?" + urlencode(params) if params else "")
    conn=ProviderConnection(u.hostname,443,timeout=4,context=ssl.create_default_context())
    try:
        conn.request("GET",path,headers={"Accept":"application/json, application/rdap+json",
            "User-Agent":"NDC-Atlas/1","Accept-Encoding":"identity","Connection":"close"})
        with conn.getresponse() as r:
            if r.status!=200:raise ValueError("Provider HTTP status")
            if r.getheader("Content-Encoding","identity").lower()!="identity":raise ValueError("Compressed provider response rejected")
            raw=r.read(1048577)
            if len(raw)>1048576:raise ValueError("Provider response limit")
        data=json.loads(raw)
        if not isinstance(data,dict):raise ValueError("Provider object required")
        return data
    finally:conn.close()

def iana_base(client,ip=None,asn=None):
    file="asn.json" if asn is not None else ("ipv4.json" if ip.version==4 else "ipv6.json")
    obj=get(client,IANA+file);matches=[]
    for ranges,urls in obj.get("services",[]):
        for key in ranges:
            if asn is not None:
                a,sep,b=key.partition("-")
                if int(a)<=asn<=int(b if sep else a):matches.append((-(int(b if sep else a)-int(a)),urls))
            else:
                net=ipaddress.ip_network(key)
                if ip in net:matches.append((net.prefixlen,urls))
    if not matches:return None
    for _,urls in sorted(matches,key=lambda x:x[0],reverse=True):
        for url in urls:
            if url in RIR:return url
        break
    return None

def text(v,maxlen=256):
    return v[:maxlen] if isinstance(v,str) else None

def rdap(client,ip=None,asn=None):
    base=iana_base(client,ip,asn)
    if base is None:raise ValueError("Unsupported RIR endpoint")
    d=get(client,base+("autnum/"+str(asn) if asn is not None else "ip/"+str(ip)))
    if asn is not None:
        start,end=d.get("startAutnum"),d.get("endAutnum")
        if d.get("objectClassName")!="autnum" or type(start) is not int or type(end) is not int or not 1<=start<=asn<=end<=4294967295:
            raise ValueError("RDAP ASN mismatch")
    else:
        start,end=ipaddress.ip_address(d["startAddress"]),ipaddress.ip_address(d["endAddress"])
        if d.get("objectClassName")!="ip network" or start.version!=ip.version or end.version!=ip.version or not start<=ip<=end:
            raise ValueError("RDAP IP mismatch")
    return {"provider":base,"handle":text(d.get("handle")),"name":text(d.get("name")),
        "type":text(d.get("type")),"country_registration":text(d.get("country"),8),
        "start_address":text(d.get("startAddress"),64),"end_address":text(d.get("endAddress"),64),
        "start_as":d.get("startAutnum") if isinstance(d.get("startAutnum"),int) else None,
        "end_as":d.get("endAutnum") if isinstance(d.get("endAutnum"),int) else None,
        "status":[text(x,80) for x in d.get("status",[])[:10] if isinstance(x,str)]}

def ripe(client,resource,kind):
    obj=get(client,RIPE+kind+"/data.json",{"resource":resource})
    if obj.get("status")!="ok" or not isinstance(obj.get("data"),dict):raise ValueError("RIPEstat unavailable")
    return obj["data"]

def execute(config):
    if not enabled():raise PermissionError("Atlas disabled")
    started=time.time();ip=None;asn=None;data={};errors={}
    target=config.target
    if target.startswith("AS") and target[2:].isdigit():asn=int(target[2:])
    else:
        try:ip=public_ip(target)
        except ValueError:
            # A literal nonpublic IP is never converted into a DNS lookup.
            try:ipaddress.ip_address(target)
            except ValueError:ip=public_ip(resolve_host(target,443,config.family))
            else:raise
    def capture(name,fn):
        try:
            value=fn();data[name]={"retrieved_at":time.time(),"value":value}
        except Exception as exc:errors[name]=type(exc).__name__
    with nullcontext(None) as client:
        capture("rdap",lambda:rdap(client,ip,asn))
        if ip is not None:
            def network():
                d=ripe(client,str(ip),"network-info");prefix=ipaddress.ip_network(d["prefix"])
                if ip not in prefix:raise ValueError("Prefix mismatch")
                origins=sorted({int(x) for x in d.get("asns",[]) if str(x).isdigit() and 1<=int(x)<=4294967295})
                return {"prefix":str(prefix),"origin_asns":origins[:8],"origins_truncated":len(origins)>8}
            capture("ripe_network_info",network)
            if "ripe_network_info" in data:
                value=data["ripe_network_info"]["value"]
                def rpki():
                    out=[]
                    for n in value["origin_asns"][:2]:
                        obj=get(client,RIPE+"rpki-validation/data.json",{"resource":"AS"+str(n),"prefix":value["prefix"]})
                        if obj.get("status")!="ok":raise ValueError("RPKI unavailable")
                        status=obj["data"].get("status")
                        out.append({"asn":n,"prefix":value["prefix"],"status":text(status,64)})
                    return {"results":out,"truncated":len(value["origin_asns"])>2 or value["origins_truncated"]}
                capture("ripe_rpki",rpki)
        else:
            def overview():
                d=ripe(client,"AS"+str(asn),"as-overview")
                return {"asn":asn,"holder":text(d.get("holder")),"announced":d.get("announced") if isinstance(d.get("announced"),bool) else None}
            capture("ripe_as_overview",overview)
    return {"methodology":"internet-atlas-v1","target":target,"family":config.family,"resolved_ip":str(ip) if ip else None,
        "asn":asn,"started_at":started,"finished_at":time.time(),"data":data,"errors":errors,"cached":False,
        "limitations":["registration_country_not_geolocation","ripe_stat_observation_not_global_bgp_truth","no_live_path_inference",
            "system_dns_single_selected_address","provider_metadata_not_independently_verified","no_contact_data"]}

def run(config):
    if not enabled():raise PermissionError("Atlas disabled")
    key=(config.target,config.family);now=time.monotonic()
    # API serializes this cache with the shared inspection semaphore.
    for k,(stamp,_) in list(CACHE.items()):
        if now-stamp>=TTL:del CACHE[k]
    if key in CACHE:
        CACHE.move_to_end(key);return CACHE[key][1]|{"cached":True}
    try:
        raw=bounded_worker([sys.executable,"-m","backend.ndc.internet_atlas"],config.model_dump_json(),timeout=MAX_SECONDS,max_output=131072)
    except subprocess.TimeoutExpired:raise RuntimeError("Atlas provider deadline") from None
    report=json.loads(raw)
    if report["data"] and not report["errors"]:
        CACHE[key]=(time.monotonic(),report)
        while len(CACHE)>64:CACHE.popitem(last=False)
    return report

if __name__=="__main__":
    print(json.dumps(execute(AtlasRequest.model_validate_json(sys.stdin.read(4096))),allow_nan=False))
