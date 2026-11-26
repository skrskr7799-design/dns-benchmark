"""Positive DNSSEC chain verification from a separately supplied root DNSKEY.

The recursive resolver supplies untrusted records only. No AD trust, denial
proof, automated zone discovery, insecure delegation or rollover management.
"""
import json
import subprocess
import sys
import time
from typing import Literal
import dns.name
import dns.dnssec
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from pydantic import Field,model_validator
from .dns_integrity import Strict,Anchor,key_material
from .models import Inspect,Run
from .probes.dns import bootstrap
from .probes.inspector import inspect_one
from .bounded_worker import bounded_worker

MAX_SECONDS=45
class ChainRequest(Strict):
    endpoint:str=Field(min_length=1,max_length=2048)
    family:Literal["ipv4","ipv6"]="ipv4"
    name:str=Field(min_length=1,max_length=253)
    zones:list[str]=Field(min_length=1,max_length=4)
    root_dnskey:str=Field(min_length=10,max_length=2048)
    @model_validator(mode="after")
    def normalize(self):
        Run(endpoints=[self.endpoint])
        def name(v):return Inspect(name=v,endpoints=[self.endpoint]).name
        self.name=name(self.name);self.zones=[name(z) for z in self.zones]
        previous=dns.name.root
        for z in self.zones:
            current=dns.name.from_text(z)
            if current==previous or not current.is_subdomain(previous):raise ValueError("Zones must form a strict descending chain")
            previous=current
        if not dns.name.from_text(self.name).is_subdomain(previous):raise ValueError("Name outside final zone")
        try:
            _,key=key_material(Anchor(signer=".",dnskey=self.root_dnskey))
            self.root_dnskey=key.to_text()
        except Exception as exc:raise ValueError("Invalid root DNSKEY") from exc
        return self

def extract(row,owner,kind,signer):
    if row["outcome"]!="answer" or row["rcode"]!="NOERROR" or row["cname_chain"]:raise ValueError("No direct positive RRset")
    owner=dns.name.from_text(owner);signer=dns.name.from_text(signer)
    rdtype=dns.rdatatype.from_text(kind)
    matches=[r for r in row["answer"] if r["type"]==kind and r["class"]=="IN" and dns.name.from_text(r["name"])==owner]
    if len(matches)!=1 or not 1<=len(matches[0]["values"])<=32:raise ValueError("Missing or oversized RRset")
    r=matches[0]
    rr=dns.rrset.from_text(owner,r["ttl"],"IN",kind,*r["values"])
    sigs=dns.rrset.RRset(owner,dns.rdataclass.IN,dns.rdatatype.RRSIG,rdtype)
    for record in row["answer"]:
        if record["type"]!="RRSIG" or record["class"]!="IN" or dns.name.from_text(record["name"])!=owner:continue
        if len(record["values"])>32:raise ValueError("Too many signatures")
        for v in record["values"]:
            sig=dns.rdata.from_text("IN","RRSIG",v)
            if sig.covers()==rdtype and sig.signer==signer and sig.labels==len(owner.labels)-1:sigs.add(sig,record["ttl"])
    if not len(sigs):raise ValueError("Missing signatures")
    return rr,sigs

def keyset(owner,keys):
    rr=dns.rrset.RRset(dns.name.from_text(owner),dns.rdataclass.IN,dns.rdatatype.DNSKEY)
    for key in keys:rr.add(key,0)
    return rr

def matched_keys(zone,keys,ds):
    out=[]
    for key in keys:
        if key.protocol!=3 or not key.flags&256 or key.flags&128:continue
        for record in ds:
            if record.digest_type not in (2,4):continue
            if record.key_tag!=dns.dnssec.key_id(key) or record.algorithm!=key.algorithm:continue
            try:match=dns.dnssec.make_ds(zone,key,record.digest_type,validating=True)==record
            except (dns.dnssec.UnsupportedAlgorithm,dns.dnssec.DeniedByPolicy):continue
            if match:out.append(key);break
    if not out:raise ValueError("No supported DS-to-DNSKEY match")
    return keyset(zone,out)

def execute(cfg,clock=time.time):
    start=clock();steps=[];stage="bootstrap";values=[]
    pinned=bootstrap(cfg.endpoint,cfg.family)
    def fetch(owner,kind,signer):
        config=Inspect(name=owner,qtype=kind,endpoints=[cfg.endpoint],family=cfg.family,dnssec=True,checking_disabled=True)
        row,_=inspect_one(cfg.endpoint,config,pinned=pinned)
        rr,sigs=extract(row,owner,kind,signer)
        return rr,sigs,row
    def verified(owner,kind,signer,rr,sigs,keys,row):
        dns.dnssec.validate(rr,sigs,{dns.name.from_text(signer):keys},now=start)
        steps.append({"owner":owner,"type":kind,"signer":signer,"status":"validated","key_tags":sorted({dns.dnssec.key_id(k) for k in keys}),
            "observed_peer":row.get("peer_ip"),"protocol":row.get("protocol")})
    try:
        if pinned[0] is None:raise ValueError("Bootstrap failed")
        stage="root DNSKEY"
        _,anchor=key_material(Anchor(signer=".",dnskey=cfg.root_dnskey))
        keys,sigs,row=fetch(".","DNSKEY",".")
        if anchor not in keys or anchor.flags&128:raise ValueError("Root anchor absent or revoked")
        verified(".","DNSKEY",".",keys,sigs,keyset(".",[anchor]),row)
        parent="."
        for zone in cfg.zones:
            stage=zone+" DS"
            ds,sigs,row=fetch(zone,"DS",parent);verified(zone,"DS",parent,ds,sigs,keys,row)
            stage=zone+" DNSKEY"
            child,sigs,row=fetch(zone,"DNSKEY",zone)
            matched=matched_keys(zone,child,ds)
            verified(zone,"DNSKEY",zone,child,sigs,matched,row)
            keys=child;parent=zone
        stage=cfg.name+" A"
        rr,sigs,row=fetch(cfg.name,"A",parent);verified(cfg.name,"A",parent,rr,sigs,keys,row)
        values=sorted(r.to_text() for r in rr);status="validated_under_supplied_root"
    except Exception:
        status="not_validated"
    return {"methodology":"positive-dnssec-chain-v1","endpoint":cfg.endpoint,"name":cfg.name,"zones":cfg.zones,
        "started_at":start,"finished_at":clock(),"status":status,"steps":steps,"failed_stage":None if status=="validated_under_supplied_root" else stage,
        "addresses":values,"root_anchor_source":"owner_supplied","limitations":["positive_A_only","explicit_zone_chain","trusted_root_key_not_independently_attested","no_negative_proof_or_aliases","no_automatic_anchor_rollover","AD_not_trusted","not_a_client_leak_test"]}

def run(cfg):
    try:return json.loads(bounded_worker([sys.executable,"-m","backend.ndc.dns_chain"],cfg.model_dump_json(),timeout=MAX_SECONDS,max_output=65536))
    except subprocess.TimeoutExpired:return {"methodology":"positive-dnssec-chain-v1","endpoint":cfg.endpoint,"name":cfg.name,"zones":cfg.zones,
        "started_at":None,"finished_at":time.time(),"status":"deadline","steps":[],"failed_stage":None,"addresses":[],"root_anchor_source":"owner_supplied","limitations":["child_terminated_no_partial_results"]}

if __name__=="__main__":
    print(json.dumps(execute(ChainRequest.model_validate_json(sys.stdin.read(16385))),allow_nan=False))
