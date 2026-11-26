"""Bounded resolver agreement and controlled DNSSEC checks.

No automatic public test target, resolver ranking, DNS leak or chain claim.
The optional independent verification uses an owner-supplied public DNSKEY,
not a key obtained from the tested resolver.
"""
import ipaddress
import time
from typing import Literal
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.dnssec
from pydantic import BaseModel,ConfigDict,Field,model_validator
from .models import Inspect,Run
from .probes.inspector import inspect_one
from .probes.dns import bootstrap

class Strict(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)

class Agreement(Strict):
    name:str=Field(min_length=1,max_length=253)
    qtype:Literal["A","AAAA","CNAME","MX","TXT","NS","SOA","CAA","HTTPS","SVCB"]="A"
    endpoints:list[str]=Field(min_length=2,max_length=4)
    family:Literal["ipv4","ipv6"]="ipv4"
    @model_validator(mode="after")
    def canonical(self):
        cfg=Inspect(name=self.name,qtype=self.qtype,endpoints=self.endpoints,family=self.family)
        self.name=cfg.name
        if len(set(self.endpoints))!=len(self.endpoints):raise ValueError("Distinct endpoints required")
        return self

class Control(Strict):
    name:str=Field(min_length=1,max_length=253)
    expected_ipv4:str=Field(min_length=7,max_length=15)

class Anchor(Strict):
    signer:str=Field(min_length=1,max_length=253)
    dnskey:str=Field(min_length=10,max_length=2048)

def key_material(anchor):
    signer=dns.name.from_text(anchor.signer).canonicalize()
    key=dns.rdata.from_text("IN","DNSKEY",anchor.dnskey)
    if key.protocol!=3 or not key.flags&256:raise ValueError("DNS zone key required")
    return signer,key

class DNSSECCheck(Strict):
    endpoint:str=Field(min_length=1,max_length=2048)
    family:Literal["ipv4","ipv6"]="ipv4"
    positive:Control
    bogus:Control
    anchor:Anchor|None=None
    @model_validator(mode="after")
    def canonical(self):
        Run(endpoints=[self.endpoint])
        for control in (self.positive,self.bogus):
            control.name=Inspect(name=control.name,endpoints=[self.endpoint],family=self.family).name
            control.expected_ipv4=str(ipaddress.IPv4Address(control.expected_ipv4))
        if self.positive.name==self.bogus.name:raise ValueError("Distinct control names required")
        if self.anchor is not None:
            try:
                signer,key=key_material(self.anchor)
                if not dns.name.from_text(self.positive.name).is_subdomain(signer):raise ValueError("Anchor outside positive name")
                self.anchor.signer=signer.to_text();self.anchor.dnskey=key.to_text()
            except Exception as exc:raise ValueError("Invalid public DNSKEY anchor") from exc
        return self

def agreement(config):
    cfg=Inspect(name=config.name,qtype=config.qtype,endpoints=config.endpoints,family=config.family,dnssec=True)
    start=time.time();groups={};rows=[]
    for endpoint in cfg.endpoints:
        row,sig=inspect_one(endpoint,cfg)
        # SERVFAIL, referral, truncation and transport error do not constitute
        # a comparable answer. Alias-only and NODATA are observed answers,
        # not proof of filtering, and only compared within this explicit query.
        if sig is not None and row["outcome"] in ("answer","alias_only","no_data","nxdomain"):
            row["comparison_group"]=groups.setdefault(sig,len(groups)+1)
        rows.append(row)
    n=sum(r["comparison_group"] is not None for r in rows)
    return {"methodology":"resolver-agreement-v1","name":cfg.name,"qtype":cfg.qtype,"family":cfg.family,
        "vantage":"controller","started_at":start,"finished_at":time.time(),"comparable":n,"groups":len(groups),
        "agreement":None if n<2 else len(groups)==1,"results":rows,
        "limitations":["single_query_per_endpoint","ttl_and_rrset_order_ignored","cdn_geo_cache_and_split_dns_can_differ",
            "different_answers_not_proof_of_filtering_or_hijack","not_client_dns_leak_test"]}

def expected(row,control):
    if row["outcome"]!="answer" or row["rcode"]!="NOERROR" or row["cname_chain"]:return False
    if any(rr["type"]=="A" and (rr["class"]!="IN" or dns.name.from_text(rr["name"]).canonicalize().to_text()!=control.name) for rr in row["answer"]):return False
    values={v for rr in row["answer"] if rr["type"]=="A" and rr["class"]=="IN"
        and dns.name.from_text(rr["name"]).canonicalize().to_text()==control.name for v in rr["values"]}
    return values=={control.expected_ipv4}

def verify_pinned(row,control,anchor,now):
    if anchor is None:return {"status":"not_requested","key_tag":None}
    signer,key=key_material(anchor);tag=dns.dnssec.key_id(key)
    result={"status":"insufficient_evidence","key_tag":tag}
    if not expected(row,control):return result
    try:
        owner=dns.name.from_text(control.name)
        answers=[r for r in row["answer"] if r["type"]=="A" and r["class"]=="IN"
            and dns.name.from_text(r["name"]).canonicalize()==owner]
        if len(answers)!=1:return result
        a=answers[0];rrset=dns.rrset.from_text(owner,a["ttl"],"IN","A",*a["values"])
        sigs=dns.rrset.RRset(owner,dns.rdataclass.IN,dns.rdatatype.RRSIG,dns.rdatatype.A)
        for r in row["answer"]:
            if r["type"]!="RRSIG" or r["class"]!="IN" or dns.name.from_text(r["name"]).canonicalize()!=owner:continue
            for value in r["values"]:
                sig=dns.rdata.from_text("IN","RRSIG",value)
                if sig.covers()==dns.rdatatype.A and sig.signer.canonicalize()==signer and sig.key_tag==tag:
                    sigs.add(sig,r["ttl"])
        if not len(sigs):return result
        keys=dns.rrset.RRset(signer,dns.rdataclass.IN,dns.rdatatype.DNSKEY);keys.add(key,0)
        dns.dnssec.validate(rrset,sigs,{signer:keys},now=now)
        result["status"]="valid_under_supplied_key"
    except dns.dnssec.ValidationFailure:
        result["status"]="signature_not_validated"
    except Exception:
        result["status"]="verification_unavailable"
    return result

def dnssec_check(config):
    started=time.time()
    # Pin one bootstrap result for all three queries: changing physical
    # anycast instances remains possible even at the same literal IP.
    pinned=bootstrap(config.endpoint,config.family)
    rows=[]
    for label,control,cd in (("positive",config.positive,False),("bogus",config.bogus,False),("bogus_cd",config.bogus,True)):
        cfg=Inspect(name=control.name,endpoints=[config.endpoint],family=config.family,qtype="A",dnssec=True,checking_disabled=cd)
        row,_=inspect_one(config.endpoint,cfg,pinned=pinned)
        rows.append({"control":label,"name":control.name,"checking_disabled_requested":cd,
            "expected_answer":expected(row,control),"response":row})
    p,b,c=rows
    ad=(p["response"]["dnssec"] or {}).get("ad") is True
    blocked=b["response"]["rcode"]=="SERVFAIL" and b["response"]["outcome"]=="dns_error"
    if p["expected_answer"] and ad and blocked and c["expected_answer"]:
        behavior="consistent_with_validation"
    elif p["expected_answer"] and b["expected_answer"]:
        behavior="bogus_answer_returned"
    else:
        behavior="inconclusive"
    return {"methodology":"controlled-dnssec-v1","endpoint":config.endpoint,"vantage":"controller",
        "started_at":started,"finished_at":time.time(),"behavior":behavior,"checks":rows,
        "signature":verify_pinned(p["response"],config.positive,config.anchor,time.time()),
        "chain_validated":False,"limitations":["owner_supplied_control_expectations_not_independently_attested",
            "ad_is_resolver_claim","servfail_alone_not_validation_proof","pinned_key_not_root_chain_validation",
            "no_client_dns_leak_inference","three_sequential_queries_no_fallback"]}
