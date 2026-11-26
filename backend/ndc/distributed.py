"""Read-only comparison of a single immutable remote batch.
No clock synchronization, global ranks or inferred geographic claims.
"""
from collections import Counter,defaultdict
from itertools import combinations
from .remote_contract import config_key

DISPATCH_WINDOW=120
LEASE_SECONDS=300
METHOD="distributed-remote-v2"

def field(a,b):
    if a is None or b is None:return {"left":a,"right":b,"status":"unknown"}
    return {"left":a,"right":b,"status":"same_observed" if a==b else "different_observed"}

def pair(config,left,right,cohort_ids):
    a,b=left["observation"],right["observation"]
    result={"left_agent_id":left["agent_id"],"right_agent_id":right["agent_id"],
        "left_task_id":left["id"],"right_task_id":right["id"],
        "status":"unknown","fields":{},"phase_deltas_ms":{},"hops":[]}
    if not a or not b:
        result["reason"]="observation_missing";return result
    if not left["controller_window_verified"] or not right["controller_window_verified"]:
        result["reason"]="controller_window_unverified";return result
    f=result["fields"]
    f["address"]=field(a.get("address"),b.get("address"))
    f["outcome"]=field(a.get("outcome"),b.get("outcome"))
    if config.kind in ("tls","http"):
        f["tls_verified"]=field(a.get("verified"),b.get("verified"))
        f["fingerprint"]=field(a.get("fingerprint") if a.get("verified") is True else None,
            b.get("fingerprint") if b.get("verified") is True else None)
        f["tls_version"]=field(a.get("tls_version") if a.get("verified") is True else None,
            b.get("tls_version") if b.get("verified") is True else None)
    if config.kind=="http":f["http_status"]=field(a.get("http_status"),b.get("http_status"))
    result["status"]="observations_only"
    if config.kind=="route":
        # A missing TTL, timeout or non-hop ICMP response does not prove a
        # changed/missing router. Compare only address-bearing hop/destination.
        if f["address"]["status"]!="same_observed":
            result["reason"]="destination_not_matched";return result
        if a.get("stage")!="trace" or b.get("stage")!="trace":
            result["reason"]="trace_missing";return result
        am={h["ttl"]:h for h in a["hops"]};bm={h["ttl"]:h for h in b["hops"]}
        for ttl in sorted(am.keys()|bm.keys()):
            x,y=am.get(ttl),bm.get(ttl)
            def observed(h):
                return h.get("address") if h and h["status"] in ("hop","destination") else None
            hx,hy=observed(x),observed(y)
            result["hops"].append({"ttl":ttl,"left_status":x["status"] if x else None,
                "right_status":y["status"] if y else None,
                "address":field(hx,hy),"left_rtt_ms":x.get("rtt_ms") if hx is not None else None,
                "right_rtt_ms":y.get("rtt_ms") if hy is not None else None})
        result["reason"]="route_samples_not_stable_paths"
        return result
    if cohort_ids.get(left["id"]) is None or cohort_ids.get(left["id"])!=cohort_ids.get(right["id"]):
        result["reason"]="not_in_same_success_cohort";return result
    result["status"]="matched_single_samples"
    result["reason"]="not_synchronized_or_repeated"
    for key in ("dns_ms","connect_ms","tls_ms","http_ms","total_ms"):
        x,y=a.get(key),b.get(key)
        result["phase_deltas_ms"][key]=round(y-x,3) if x is not None and y is not None else None
    return result

def compare(config,created,dispatch_until,rows):
    members=[];groups=defaultdict(list);counts=Counter()
    for r in rows:
        payload=r.pop("payload")
        obs=payload.get("observation") if payload else None
        claim=r.pop("lease_until")
        leased_at=claim-LEASE_SECONDS if claim is not None else None
        finished=r["finished"]
        timing_ok=bool(leased_at is not None and finished is not None and
            created<=leased_at<dispatch_until and leased_at<=finished<=(leased_at+LEASE_SECONDS))
        r.update(leased_at=leased_at,queue_seconds=leased_at-created if leased_at is not None and leased_at>=created else None,
            receipt_seconds=finished-leased_at if timing_ok else None,controller_window_verified=timing_ok,
            observation=obs,execution_error=payload.get("execution_error") if payload else None,
            provenance="agent_claim" if obs is not None else "unmeasured")
        outcome=obs["outcome"] if obs else "unknown"
        counts[outcome]+=1
        reason=None
        if not obs:reason="no_observation"
        elif not timing_ok:reason="controller_window_unverified"
        elif outcome!="success":reason="not_successful"
        elif config.kind=="route":reason="route_not_latency_ranked"
        elif not obs.get("address"):reason="address_unknown"
        else:
            # Same config by construction. For TLS/HTTPS also match the
            # negotiated version and verified leaf; HTTP status must match.
            key=(obs["address"],obs.get("tls_version"),obs.get("fingerprint"),obs.get("http_status"))
            groups[key].append(r)
        r["comparison_exclusion"]=reason
        members.append(r)
    cohorts=[];cohort_ids={}
    for key,group in sorted(groups.items(),key=lambda kv:str(kv[0])):
        rows=[]
        for r in group:
            o=r["observation"]
            rows.append({"agent_id":r["agent_id"],"task_id":r["id"],
                "dns_ms":o.get("dns_ms"),"connect_ms":o.get("connect_ms"),
                "tls_ms":o.get("tls_ms"),"http_ms":o.get("http_ms"),"total_ms":o.get("total_ms")})
        if len(group)>=2:
            for r in group:cohort_ids[r["id"]]=key
        cohorts.append({"address":key[0],"tls_version":key[1],"fingerprint":key[2],"http_status":key[3],
            "comparable":len(group)>=2,"members":rows,
            "receipt_spread_seconds":max(r["finished"] for r in group)-min(r["finished"] for r in group)})
    return {"methodology":METHOD,"profile_revision":config_key(config),
        "window":{"created_at":created,"dispatch_until":dispatch_until,"latest_possible_receipt":dispatch_until+LEASE_SECONDS,
            "time_basis":"controller_lease_and_receipt","simultaneous_verified":False},
        "counts":{k:counts[k] for k in ("success","failure","partial","unknown")},
        "members":members,"cohorts":cohorts,
        "pairs":[pair(config,a,b,cohort_ids) for a,b in combinations(members,2)],
        "limitations":["single_sample_per_agent","agent_claim_not_attested","remote_observation_time_unavailable",
            "no_global_ranking","different_addresses_not_latency_compared","route_hops_not_stable_paths","phase_deltas_right_minus_left_not_rankings","same_ip_may_be_anycast"]}
