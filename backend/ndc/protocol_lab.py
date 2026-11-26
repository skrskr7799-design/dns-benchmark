"""Opt-in protocol experiments over fixed configured resolver endpoints.

A separate bounded child process owns all network IO, including bootstrap.
No shell, caller-selected executable, arbitrary corpus, fallback or retries.
"""
import json
import math
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel,ConfigDict,Field,model_validator
from .models import Run
from .evidence import digest
from .probes.dns import domains,bootstrap,measure

MAX_QUERIES=24
MAX_SECONDS=45
MAX_OUTPUT=262144
EXPECTED={"udp":"udp","tcp":"tcp","tls":"dot","https":"h2","quic":"doq","h3":"h3"}

def configured():
    raw=os.getenv("NDC_LAB_ENDPOINTS","[]")
    if len(raw)>16384:raise ValueError("Invalid laboratory allowlist")
    endpoints=json.loads(raw)
    if not isinstance(endpoints,list) or len(endpoints)>8 or any(not isinstance(e,str) for e in endpoints):
        raise ValueError("Invalid laboratory allowlist")
    if endpoints:
        Run(endpoints=endpoints)
    if len(set(endpoints))!=len(endpoints):raise ValueError("Duplicate laboratory endpoint")
    return endpoints

class LabProfile(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    endpoints:list[str]=Field(min_length=1,max_length=2)
    families:list[Literal["ipv4","ipv6"]]=Field(min_length=1,max_length=2)
    modes:list[Literal["cold","warm"]]=Field(min_length=1,max_length=2)
    count:int=Field(default=3,ge=1,le=6)
    parallel:Literal[1,2]=1
    @property
    def planned_queries(self):
        return len(self.endpoints)*len(self.families)*(len(self.modes)*self.count+int("warm" in self.modes))
    @model_validator(mode="after")
    def budget(self):
        for seq in (self.endpoints,self.families,self.modes):
            if len(set(seq))!=len(seq):raise ValueError("Duplicate profile selection")
        Run(endpoints=self.endpoints)
        if self.planned_queries>MAX_QUERIES:raise ValueError("Query budget exceeded")
        if self.parallel>len(self.endpoints)*len(self.families):raise ValueError("Concurrency exceeds independent lanes")
        return self

def authorize(profile):
    allowed=configured()
    if any(e not in allowed for e in profile.endpoints):raise PermissionError("Endpoint not authorized")

def capability():
    return {"endpoints":configured(),"max_queries":MAX_QUERIES,"max_seconds":MAX_SECONDS,
        "max_parallel":2,"max_count":6,"corpus":list(domains[:6]),"warmup":"example.net"}

def complete(row,expected):
    return (row is not None and row["count"]==row["requested_count"] and row["ok"]==row["count"]
        and row["protocols"]==[expected] and (row["mode"]!="warm" or (row["warmup"] or {}).get("ok") is True))

def lane(endpoint,family,profile):
    pinned=bootstrap(endpoint,family)
    expected=EXPECTED[urlsplit(endpoint).scheme]
    rows=[];cancel=threading.Event()
    # Fixed mode order, one IP selection per lane, no implicit retry or fallback.
    for mode in ("cold","warm"):
        if mode not in profile.modes:continue
        row=measure(endpoint,profile.count,mode,family,cancel,pinned=pinned)
        if row is None:raise RuntimeError("Missing laboratory result")
        row["expected_protocol"]=expected
        row["transport_matched"]=complete(row,expected)
        rows.append(row)
    return rows

def execute(profile):
    authorize(profile)
    started=time.time()
    pairs=[(e,f) for e in profile.endpoints for f in profile.families]
    with ThreadPoolExecutor(max_workers=profile.parallel) as pool:
        groups=list(pool.map(lambda pair:lane(*pair,profile),pairs))
    comparisons=[]
    for rows in groups:
        if len(rows)!=2:continue
        cold,warm=rows
        comparable=(cold["transport_matched"] and warm["transport_matched"] and cold["ip"] is not None
            and cold["ip"]==warm["ip"] and cold["peer_ips"]==warm["peer_ips"]
            and len(cold["peer_ips"])==1 and cold["peer_ips"][0]==cold["ip"]
            and all(s["peer_ip"]==cold["ip"] for s in cold["samples"]+warm["samples"])
            and all(s["reused"] is False for s in cold["samples"])
            and all(s["reused"] is True for s in warm["samples"])
            and [s["domain"] for s in cold["samples"]]==[s["domain"] for s in warm["samples"]])
        comparisons.append({"endpoint":cold["endpoint"],"family":cold["family"],
            "status":"matched_transport_reuse" if comparable else "not_comparable",
            "warm_minus_cold_p50_ms":round(warm["p50"]-cold["p50"],2) if comparable else None})
    config=profile.model_dump(mode="json")
    return {"methodology":"protocol-laboratory-v1","profile":config,"profile_key":digest({"version":1,"profile":config,"corpus":list(domains[:profile.count]),"warmup":"example.net"}),
        "vantage":"controller","status":"completed","started_at":started,"finished_at":time.time(),
        "planned_queries":profile.planned_queries,"rows":[r for rows in groups for r in rows],"comparisons":comparisons,
        "limitations":["fixed_corpus_A_only","cold_connection_not_cold_resolver_cache","warmup_separate_from_samples",
            "parallel_across_endpoint_family_lanes_not_intra_connection","no_cross_endpoint_rank",
            "sequential_modes_not_synchronized","udp_peer_and_reuse_unavailable","same_ip_may_be_anycast",
            "no_inference_about_encrypted_dns_privacy"]}

def run(profile):
    authorize(profile)
    start=time.time()
    try:
        # No process creation inside the child. subprocess.run kills and waits
        # on timeout; all sockets/worker threads belong to that process.
        result=subprocess.run([sys.executable,"-m","backend.ndc.protocol_lab"],
            input=profile.model_dump_json(),text=True,capture_output=True,timeout=MAX_SECONDS,check=False)
    except subprocess.TimeoutExpired:
        return {"methodology":"protocol-laboratory-v1","profile":profile.model_dump(mode="json"),
            "profile_key":None,"vantage":"controller","status":"deadline","started_at":start,"finished_at":time.time(),
            "planned_queries":profile.planned_queries,"rows":[],"comparisons":[],
            "limitations":["child_terminated_no_partial_results","attempted_query_count_unknown"]}
    if result.returncode!=0 or len(result.stdout)>MAX_OUTPUT:raise RuntimeError("Laboratory worker failed")
    return json.loads(result.stdout)

if __name__=="__main__":
    profile=LabProfile.model_validate_json(sys.stdin.read(16385))
    print(json.dumps(execute(profile),allow_nan=False,separators=(",",":")))
