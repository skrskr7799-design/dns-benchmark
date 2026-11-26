"""Scoped, body-free website diagnostics. No browser or credentials."""
import json
import subprocess
from .bounded_worker import bounded_worker
import sys
import time
from urllib.parse import urlsplit,urljoin,urlunsplit
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator
from .models import NetworkTarget,Connectivity
from .probes.connectivity import probe_once

MAX_HOPS=4
MAX_SECONDS=40
REDIRECT={301,302,303,307,308}
SAFE_HEADERS={"cache-control","age","content-type","content-length","strict-transport-security",
    "x-frame-options","x-content-type-options","referrer-policy","permissions-policy"}
PRESENCE_HEADERS={"content-security-policy","content-security-policy-report-only","set-cookie","etag"}

def canonical_url(value):
    if not isinstance(value,str) or len(value)>2048 or any(ord(c)<33 or ord(c)>126 or c in "\\?#" for c in value):
        raise ValueError("Plain HTTP(S) URL without query or fragment required")
    u=urlsplit(value)
    if u.scheme not in ("http","https") or not u.hostname or u.username is not None or u.password is not None:
        raise ValueError("HTTP(S) origin required")
    port=443 if u.scheme=="https" else 80
    if u.port is not None and u.port!=port:raise ValueError("Only standard web ports permitted")
    host=NetworkTarget(host=u.hostname,port=port).host
    path=Connectivity(host=host,port=port,path=u.path or "/").path
    return urlunsplit((u.scheme,"["+host+"]" if ":" in host else host,path,"",""))

class XRayRequest(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    url:str=Field(min_length=1,max_length=2048)
    family:Literal["ipv4","ipv6"]="ipv4"
    follow_redirects:bool=False
    @model_validator(mode="after")
    def canonical(self):
        self.url=canonical_url(self.url);return self

def header_projection(raw):
    headers={};presence=set();locations=[]
    for line in raw.split(b"\r\n")[1:]:
        if b":" not in line or line.startswith((b" ",b"\t")):raise ValueError("Malformed HTTP header")
        name,value=line.split(b":",1);name=name.decode("ascii").lower()
        if not name or any(c not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz" for c in name):
            raise ValueError("Invalid HTTP header name")
        value=value.strip()
        if any(c<32 and c!=9 or c==127 for c in value):raise ValueError("Invalid HTTP header value")
        if name=="location":locations.append(value.decode("ascii",errors="replace"))
        if name in SAFE_HEADERS:
            headers.setdefault(name,[])
            if len(headers[name])<4:headers[name].append(value.decode("latin1")[:512])
        if name in PRESENCE_HEADERS:presence.add(name)
    return {"selected_headers":headers,"header_presence":sorted(presence),
        "_redirect_location":locations[0] if len(locations)==1 else None,"redirect_ambiguous":len(locations)>1}

def execute(config):
    started=time.time();hops=[];seen=set();url=config.url;stop="complete"
    for i in range(MAX_HOPS):
        seen.add(url);u=urlsplit(url);port=443 if u.scheme=="https" else 80
        r=probe_once(u.hostname,port,config.family,u.scheme,u.path,capture_headers=True)
        location=r.pop("_redirect_location",None)
        r["url"]=url;hops.append(r)
        if not r["ok"]:stop="probe_failed";break
        if r["http_status"] not in REDIRECT:break
        if not config.follow_redirects:stop="redirect_not_followed";break
        if r.get("redirect_ambiguous") or not location:stop="redirect_missing_or_ambiguous";break
        try:
            if not location or any(ord(c)<33 or ord(c)>126 or c in "\\?#" for c in location):raise ValueError("Unsafe location")
            target=canonical_url(urljoin(url,location))
        except ValueError:stop="redirect_policy_denied";break
        if u.scheme=="https" and urlsplit(target).scheme!="https":stop="https_downgrade_denied";break
        if target in seen:stop="redirect_loop";break
        if i==MAX_HOPS-1:stop="redirect_limit";break
        # probe_once independently resolves and validates all candidate IPs,
        # pins the selected address and checks the connected peer per hop.
        url=target
    return {"methodology":"website-xray-head-v1","request":config.model_dump(mode="json"),"vantage":"controller",
        "started_at":started,"finished_at":time.time(),"status":stop,"hops":hops,
        "limitations":["head_only_no_body_or_subresources","http_1_1_requested_not_h2_h3_capability_test",
            "no_cookies_or_credentials_sent","header_presence_not_security_verdict","system_dns_not_client_dns","single_sample_per_hop"]}

def run(config):
    start=time.time()
    try:
        raw=bounded_worker([sys.executable,"-m","backend.ndc.web_xray"],config.model_dump_json(),timeout=MAX_SECONDS,max_output=262144)
    except subprocess.TimeoutExpired:
        return {"methodology":"website-xray-head-v1","request":config.model_dump(mode="json"),"vantage":"controller",
            "started_at":start,"finished_at":time.time(),"status":"deadline","hops":[],"limitations":["child_terminated_no_partial_results"]}
    return json.loads(raw)

if __name__=="__main__":
    print(json.dumps(execute(XRayRequest.model_validate_json(sys.stdin.read(8192))),allow_nan=False))
