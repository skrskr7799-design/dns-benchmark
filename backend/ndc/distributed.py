"""Read-only comparison of a single immutable remote batch.
No clock synchronization, global ranks or inferred geographic claims.
"""
from collections import Counter,defaultdict
from .remote_contract import config_key

DISPATCH_WINDOW=120
LEASE_SECONDS=300
METHOD="distributed-remote-v1"

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
    cohorts=[]
    for key,group in sorted(groups.items(),key=lambda kv:str(kv[0])):
        rows=[]
        for r in group:
            o=r["observation"]
            rows.append({"agent_id":r["agent_id"],"task_id":r["id"],
                "dns_ms":o.get("dns_ms"),"connect_ms":o.get("connect_ms"),
                "tls_ms":o.get("tls_ms"),"http_ms":o.get("http_ms"),"total_ms":o.get("total_ms")})
        cohorts.append({"address":key[0],"tls_version":key[1],"fingerprint":key[2],"http_status":key[3],
            "comparable":len(group)>=2,"members":rows,
            "receipt_spread_seconds":max(r["finished"] for r in group)-min(r["finished"] for r in group)})
    return {"methodology":METHOD,"profile_revision":config_key(config),
        "window":{"created_at":created,"dispatch_until":dispatch_until,"latest_possible_receipt":dispatch_until+LEASE_SECONDS,
            "time_basis":"controller_lease_and_receipt","simultaneous_verified":False},
        "counts":{k:counts[k] for k in ("success","failure","partial","unknown")},
        "members":members,"cohorts":cohorts,
        "limitations":["single_sample_per_agent","agent_claim_not_attested","remote_observation_time_unavailable",
            "no_global_ranking","different_addresses_not_latency_compared","route_hops_not_stable_paths"]}
