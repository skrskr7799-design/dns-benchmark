"""Projection of authenticated, accepted remote DNS task results.

Remote measurements remain agent claims even after structural validation.
No arbitrary agent summary fields, credentials, or error texts are projected.
"""
import ipaddress
import math
import statistics
import json
from .benchmark_evidence import project,PROTOCOLS
from .evidence import Observation,canonical

STREAM="agent-v1"

def clean_ip(value):
    if not isinstance(value,str) or len(value)>64 or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None

def sanitize(cfg,row):
    # validate_result has already verified sample count, corpus, index, latency,
    # and successful count against the immutable leased task.
    samples=row["samples"]
    successes=[s for s in samples if s["ok"]]
    values=sorted(s["duration_ms"] for s in successes)
    def pct(p):
        return round(values[max(0,math.ceil(len(values)*p)-1)],2) if values else None
    known_protocols=[s.get("protocol") for s in successes]
    protocols=sorted(set(known_protocols)) if known_protocols and all(
        isinstance(p,str) and p in PROTOCOLS for p in known_protocols) else []
    peers=[clean_ip(s.get("peer_ip")) for s in successes]
    peer_ips=sorted(set(peers)) if peers and all(p is not None for p in peers) else []
    warmup=row.get("warmup")
    warm_ok=isinstance(warmup,dict) and warmup.get("ok") is True and not row.get("warmup_error")
    return {
        "endpoint":cfg.endpoints[0],"mode":row["mode"],"family":cfg.family,
        "engine":"python-dns02","ip":clean_ip(row.get("ip")),
        "count":len(samples),"requested_count":cfg.count,"ok":len(values),
        "samples":[{k:s[k] for k in ("index","domain","qtype","ok")} for s in samples],
        "mean":round(statistics.mean(values),2) if values else None,
        "p50":pct(.5),"p95":pct(.95),"p99":pct(.99),
        "jitter":round(statistics.pstdev(values),2) if values else None,
        "bootstrap_ms":None,"protocols":protocols,"peer_ips":peer_ips,
        "warmup":{"ok":warm_ok},"warmup_error":None if warm_ok else "unverified",
        "reuse":{"yes":sum(s.get("reused") is True for s in successes),
                 "no":sum(s.get("reused") is False for s in successes),
                 "unknown":sum(type(s.get("reused")) is not bool for s in successes)}
    }

def records(task_id,agent_id,batch_id,cfg,body):
    config=cfg.model_dump()
    rows=[sanitize(cfg,r) for r in body.results] if body.status=="completed" else [{}]
    output=[]
    for ordinal,row in enumerate(rows):
        base=project(task_id,ordinal,config,row,None)
        limits=tuple(x for x in base.limitations if x!="result_commit_time")+(
            "agent_claim_not_attested","remote_observation_time_unavailable")
        if body.status=="failed":
            limits+=("agent_task_failed_without_samples",)
        output.append(base.model_copy(update={
            "source_kind":"agent","vantage_id":"agent:"+agent_id,
            "correlation_id":batch_id,"provenance":"agent_claim",
            "observed_at":None,"limitations":limits}))
    return tuple(output)

def encode(observations):
    return canonical([x.model_dump(mode="json") for x in observations])

def decode(raw):
    values=json.loads(raw)
    if not isinstance(values,list) or not 1<=len(values)<=2:
        raise ValueError("Invalid agent evidence batch")
    return tuple(Observation.model_validate_json(canonical(x)) for x in values),()
