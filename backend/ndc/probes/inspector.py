"""Bounded DNS record inspection using the same scoped transport as benchmark."""
import time
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.rdataclass
from contextlib import ExitStack
from urllib.parse import urlsplit
from .dns import bootstrap, query, describe

def records(section):
    return [{"name":rr.name.to_text(),"type":dns.rdatatype.to_text(rr.rdtype),
             "class":dns.rdataclass.to_text(rr.rdclass),"ttl":rr.ttl,
             "values":[r.to_text() for r in rr]} for rr in section]

def signature(response):
    # Ignore TTL and answer ordering, canonicalize names embedded in RDATA.
    return (response.rcode(),tuple(sorted(
        (rr.name.canonicalize().to_text(),rr.rdclass,rr.rdtype,
         tuple(sorted(r.to_digestable() for r in rr)))
        for rr in response.answer if rr.rdtype!=dns.rdatatype.RRSIG)))

def inspect_one(endpoint,config):
    ip,bootstrap_ms,error=bootstrap(endpoint,config.family)
    out={"endpoint":endpoint,"ip":ip,"bootstrap_ms":bootstrap_ms,
         "duration_ms":None,"protocol":None,"peer_ip":None,"error":error,
         "rcode":None,"flags":[],"edns":None,"dnssec":None,
         "answer":[],"authority":[],"additional":[],"cname_chain":[],
         "fallback":False,"outcome":"transport_error","comparison_group":None}
    if ip is None:
        return out,None
    start=time.monotonic()
    try:
        with ExitStack() as stack:
            resources={}
            r=query(endpoint,config.name,ip,stack,resources,qtype=config.qtype,
                    dnssec=config.dnssec,checking_disabled=config.checking_disabled)
            observation=resources.get("observation",{})
            if (r.flags & dns.flags.TC and config.tcp_fallback
                    and urlsplit(endpoint).scheme=="udp"):
                u=urlsplit(endpoint)
                host=f"[{ip}]" if ":" in ip else ip
                out["fallback"]=True
                resources={}
                r=query(f"tcp://{host}:{u.port or 53}",config.name,ip,stack,resources,
                        qtype=config.qtype,dnssec=config.dnssec,
                        checking_disabled=config.checking_disabled)
                observation=resources.get("observation",{})
            out["duration_ms"]=round((time.monotonic()-start)*1000,3)
        flags=r.flags
        out.update(protocol=observation.get("protocol"),peer_ip=observation.get("peer_ip"),
                   rcode=dns.rcode.to_text(r.rcode()),flags=dns.flags.to_text(flags).split(),
                   edns={"version":r.edns,"payload":r.payload} if r.edns>=0 else None,
                   dnssec={"requested_do":config.dnssec,"response_do":bool(r.ednsflags&dns.flags.DO),
                           "ad":bool(flags&dns.flags.AD),"cd":bool(flags&dns.flags.CD),
                           "independently_validated":False},
                   answer=records(r.answer),authority=records(r.authority),additional=records(r.additional))
        out["cname_chain"]=[{"name":rr.name.to_text(),"target":d.target.to_text()}
                            for rr in r.answer if rr.rdtype==dns.rdatatype.CNAME for d in rr]
        if flags&dns.flags.TC:
            out["outcome"]="truncated"
        elif r.rcode()==dns.rcode.NXDOMAIN:
            out["outcome"]="nxdomain"
        elif r.rcode()!=dns.rcode.NOERROR:
            out["outcome"]="dns_error"
        elif any(rr.rdtype==dns.rdatatype.from_text(config.qtype) for rr in r.answer):
            out["outcome"]="answer"
        elif out["cname_chain"]:
            out["outcome"]="alias_only"
        elif any(rr.rdtype==dns.rdatatype.NS for rr in r.authority) and not any(rr.rdtype==dns.rdatatype.SOA for rr in r.authority):
            out["outcome"]="referral"
        else:
            out["outcome"]="no_data"
        return out,signature(r) if out["outcome"]!="truncated" else None
    except Exception as exc:
        out["duration_ms"]=round((time.monotonic()-start)*1000,3)
        out["error"]=describe(exc)
        return out,None

def inspect(config):
    groups={}
    results=[]
    for endpoint in config.endpoints:
        result,sig=inspect_one(endpoint,config)
        if sig is not None:
            result["comparison_group"]=groups.setdefault(sig,len(groups)+1)
        results.append(result)
    comparable=sum(r["comparison_group"] is not None for r in results)
    return {"name":config.name,"qtype":config.qtype,"results":results,
            "comparable":comparable,"groups":len(groups),
            "agreement":None if comparable<2 else len(groups)==1,
            "note":"Answer differences alone do not prove filtering, poisoning or DNSSEC failure."}
