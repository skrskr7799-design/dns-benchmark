"""Explicit, scoped captures using existing controller probes."""
import ipaddress
import re
from typing import Literal,Annotated
from urllib.parse import urlsplit
from pydantic import Field,ConfigDict
import dns.name,dns.rdata,dns.rdatatype,dns.rdataclass,dns.exception
from .models import Inspect,NetworkTarget,RouteTarget
from .evidence import canonical,digest
from .probes.inspector import inspect_one
from .probes.connectivity import inspect_tls
from .probes.routes import trace

VERSION="probe-snapshot-v1"
TYPES={"A","AAAA","CNAME","MX","NS","PTR","SOA","SRV","CAA"}

class DNSCapture(Inspect):
    model_config=ConfigDict(extra="forbid")
    kind:Literal["dns"]="dns"
    qtype:Literal["A","AAAA","CNAME","MX","NS","PTR","SOA","SRV","CAA"]="A"
    endpoints:list[str]=Field(min_length=1,max_length=1)
    family:Literal["ipv4","ipv6"]="ipv4"

class TLSCapture(NetworkTarget):
    model_config=ConfigDict(extra="forbid")
    kind:Literal["tls"]="tls"
    family:Literal["ipv4","ipv6"]="ipv4"

class RouteCapture(RouteTarget):
    model_config=ConfigDict(extra="forbid")
    kind:Literal["route"]="route"
    family:Literal["ipv4","ipv6"]="ipv4"
    max_hops:int=Field(default=8,ge=1,le=8)
    attempts:Literal[1]=1

Capture=Annotated[DNSCapture|TLSCapture|RouteCapture,Field(discriminator="kind")]

def ip(v):
    try: return str(ipaddress.ip_address(v)) if isinstance(v,str) and "%" not in v else None
    except ValueError: return None

def config_key(cfg):
    return digest({"version":VERSION,"config":cfg.model_dump(mode="json")})

def normalize_dns(row):
    outcome=row["outcome"]
    result={"resolver_ip":ip(row.get("ip")),"protocol":row.get("protocol"),"outcome":outcome,
        "rcode":row.get("rcode"),"rrsets":None,"answer_complete":False,"reason":None}
    if (outcome not in ("answer","nxdomain","no_data") or not result["resolver_ip"]
        or not result["protocol"] or "TC" in row.get("flags",[])):
        result["reason"]="incomplete_or_failed_response";return result
    if outcome in ("nxdomain","no_data") and not any(r["type"]=="SOA" for r in row.get("authority",[])):
        result["reason"]="negative_response_without_soa";return result
    answer=row.get("answer",[])
    if len(answer)>32 or sum(len(r["values"]) for r in answer)>128:
        result["reason"]="answer_limit";return result
    sets={}
    try:
        for r in answer:
            if r["type"]=="RRSIG": continue
            if r["type"] not in TYPES or r["class"]!="IN": raise ValueError("Unsupported answer")
            name=dns.name.from_text(r["name"]).canonicalize().to_text()
            key=(name,r["class"],r["type"])
            if key in sets: raise ValueError("Duplicate RRset")
            rdtype=dns.rdatatype.from_text(r["type"])
            values=set()
            for value in r["values"]:
                d=dns.rdata.from_text(dns.rdataclass.IN,rdtype,value,origin=dns.name.root)
                wire=d.to_digestable()
                values.add(dns.rdata.from_wire(dns.rdataclass.IN,rdtype,wire,0,len(wire)).to_text())
            ttl=r["ttl"]
            if type(ttl) is not int or not 0<=ttl<=2147483647: raise ValueError("Invalid TTL")
            sets[key]={"name":name,"class":r["class"],"type":r["type"],"ttl":ttl,"values":sorted(values)}
        rrsets=[sets[k] for k in sorted(sets)]
        if len(canonical(rrsets).encode("ascii"))>24*1024: raise ValueError("Answer limit")
    except (ValueError,TypeError,KeyError,dns.exception.DNSException):
        result["reason"]="answer_unsupported_or_oversized";return result
    result.update(rrsets=rrsets,answer_complete=True)
    return result

def normalize_tls(row):
    cert=row.get("certificate")
    fp=cert.get("sha256") if isinstance(cert,dict) else None
    verified=row.get("verified")
    verified=verified if type(verified) is bool else None
    known=bool(row.get("ok") and verified is True and isinstance(fp,str) and re.fullmatch("[a-f0-9]{64}",fp))
    return {"address":ip(row.get("ip")),"verified":verified,"stage":row.get("stage"),
        "fingerprint":fp if known else None,"not_after":cert.get("not_after") if known else None,
        "tls_version":row.get("tls_version") if known else None,"alpn":row.get("alpn") if known else None}

def normalize_route(row):
    hops=[]
    for h in row["hops"]:
        samples=h["samples"];sample=samples[0] if len(samples)==1 else {}
        address=ip(sample.get("address")) if sample.get("status") in ("hop","destination") else None
        hops.append({"ttl":h["ttl"],"address":address,"status":sample.get("status","unknown")})
    return {"address":ip(row.get("ip")),"available":row["available"],"reached":row["reached"],"hops":hops}

def capture(cfg,clock):
    start=clock()
    if cfg.kind=="dns":
        row,_=inspect_one(cfg.endpoints[0],cfg)
        data=normalize_dns(row);u=urlsplit(cfg.endpoints[0])
        target={"name":cfg.name,"qtype":cfg.qtype,"resolver_host":u.hostname,"resolver_scheme":u.scheme,"resolver_port":u.port,"family":cfg.family}
    elif cfg.kind=="tls":
        data=normalize_tls(inspect_tls(cfg)["results"][0])
        target={"host":cfg.host,"port":cfg.port,"family":cfg.family}
    else:
        data=normalize_route(trace(cfg)["results"][0])
        target={"host":cfg.host,"family":cfg.family,"max_hops":cfg.max_hops}
    return {"schema_version":1,"methodology":VERSION,"scope":cfg.kind,"captured_at":clock(),"started_at":start,
        "config_key":config_key(cfg),"target":target,"vantage":"controller","observation":data,
        "limitations":["single_controller_probe","not_continuous_history","dns_answers_not_authoritative_zone_inventory",
        "ttl_may_reflect_cache_age","certificate_identity_change_not_proof_of_renewal","trust_policy_may_change",
        "udp_hops_not_complete_physical_path","no_causal_inference"]}

def field(name,a,b,compatible=True):
    return {"field":name,"before":a,"after":b,"status":"unknown" if a is None or b is None else
        "not_comparable" if not compatible else "changed" if a!=b else "unchanged"}

def compare_probes(a,b):
    x,y=a["snapshot"],b["snapshot"]
    if x["scope"]!=y["scope"] or x["methodology"]!=y["methodology"] or x["config_key"]!=y["config_key"]:
        raise ValueError("Choose matching probe configurations")
    kind=x["scope"];p,q=x["observation"],y["observation"];changes=[]
    if kind=="dns":
        comparable=bool(p["answer_complete"] and q["answer_complete"] and p["resolver_ip"]==q["resolver_ip"] and p["protocol"]==q["protocol"])
        changes.extend([field("resolver_ip",p["resolver_ip"],q["resolver_ip"]),field("protocol",p["protocol"],q["protocol"]),
            field("response_outcome",p["outcome"],q["outcome"],comparable)])
        if comparable:
            def index(r): return {(s["name"],s["class"],s["type"]):s for s in r["rrsets"]}
            left,right=index(p),index(q)
            for k in sorted(set(left)|set(right)):
                old,new=left.get(k),right.get(k)
                changes.append({"field":"rrset","key":list(k),"before":old["values"] if old else [],
                    "after":new["values"] if new else [],"status":"observed_added" if old is None else
                    "observed_removed" if new is None else "changed" if old["values"]!=new["values"] else "unchanged"})
                if old and new: changes.append(field("ttl:"+"/".join(k),old["ttl"],new["ttl"]))
        else:
            changes.append({"field":"rrsets","before":p["rrsets"],"after":q["rrsets"],
                "status":"unknown" if not p["answer_complete"] or not q["answer_complete"] else "not_comparable"})
    elif kind=="tls":
        for k in ("address","verified","fingerprint","not_after","tls_version","alpn"):
            changes.append(field(k,p[k],q[k]))
    else:
        changes.append(field("address",p["address"],q["address"]))
        changes.append(field("destination_reached",p["reached"] if p["available"] and p["address"] else None,
            q["reached"] if q["available"] and q["address"] else None))
        comparable=bool(p["available"] and q["available"] and p["address"] and p["address"]==q["address"])
        left={h["ttl"]:h["address"] for h in p["hops"]};right={h["ttl"]:h["address"] for h in q["hops"]}
        for ttl in sorted(set(left)|set(right)): changes.append(field("ttl:"+str(ttl),left.get(ttl),right.get(ttl),comparable))
    return {"methodology":"probe-diff-v1","scope":kind,"before_id":a["id"],"after_id":b["id"],
        "changes":changes,"limitations":x["limitations"]}
