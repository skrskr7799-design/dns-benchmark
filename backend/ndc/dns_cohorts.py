"""Coverage-aware descriptive DNS cohorts, not a provider ranking.

Use immutable projected summaries. Never pool percentiles or silently merge
vantages, workloads, families or actual protocols.
"""
from collections import Counter,defaultdict
from statistics import median
import math

VERSION="dns-cohorts-v1"
MAX_RECORDS=2000
MAX_GROUPS=100
BLOCKERS={"incomplete_source_metadata","sample_coverage_unverified","warmup_unverified_or_failed","bootstrap_ip_unavailable","agent_task_failed_without_samples"}
PROTOCOLS={"udp","tcp","dot","h2","h3","doq"}

class NarrowQuery(ValueError):
    pass

def metrics(record):
    return {x["name"]:(x["unit"],x["value"]) for x in record["measurements"]}

def value(m,key,unit):
    actual,v=m.get(key,(None,None))
    if actual!=unit or type(v) not in (int,float) or not math.isfinite(v) or v<0:
        return None
    if unit=="count" and int(v)!=v:
        return None
    return v

def eligibility(r):
    reasons=set(r["limitations"])&BLOCKERS
    if r["source_kind"] not in ("benchmark","agent") or r["probe_kind"]!="dns":
        reasons.add("unsupported_source")
    if r["family"] not in ("ipv4","ipv6"):
        reasons.add("unknown_family")
    if r["outcome"] not in ("success","failure","partial"):
        reasons.add("unknown_outcome")
    m=metrics(r)
    attempted,successful,requested=(value(m,k,"count") for k in ("attempted","successful","requested"))
    if any(x is None for x in (attempted,successful,requested)) or not 1<=requested<=100 or not 0<=successful<=attempted<=requested:
        reasons.add("invalid_counts")
    elif attempted!=requested:
        reasons.add("incomplete_series")
    elif (r["outcome"]=="success" and successful!=requested) or (r["outcome"]=="failure" and successful!=0) or (r["outcome"]=="partial" and not 0<successful<requested):
        reasons.add("inconsistent_outcome")
    return sorted(reasons),(attempted,successful,requested),m

def aggregate(rows):
    if len(rows)>MAX_RECORDS:
        raise NarrowQuery("Narrow time range, vantage or profile")
    cohorts={}
    excluded=Counter()
    total_excluded=0
    for item in rows:
        r=item["record"]
        reasons,counts,m=eligibility(r)
        if reasons:
            excluded.update(reasons)
            total_excluded+=1
            continue
        # The profile hash already binds engine, cold/warm, corpus, requested
        # family, sample count, concurrency and projection version.
        key=(r["source_kind"],r["vantage_id"],r["profile_revision"],r["family"],r["provenance"])
        if key not in cohorts:
            if len(cohorts)>=MAX_GROUPS:
                raise NarrowQuery("Too many comparable cohorts")
            cohorts[key]={}
        targets=cohorts[key]
        if r["target_id"] not in targets:
            if sum(len(x) for x in cohorts.values())>=MAX_GROUPS:
                raise NarrowQuery("Too many target groups")
            targets[r["target_id"]]={"attempted":0,"successful":0,"series":0,"latency":defaultdict(list),
                "latency_exclusions":Counter(),"limitations":set(),"first_received_at":item["received_at"],
                "last_received_at":item["received_at"],"example_evidence_id":item["id"]}
        t=targets[r["target_id"]]
        attempted,successful,_=counts
        t["attempted"]+=int(attempted);t["successful"]+=int(successful);t["series"]+=1
        t["limitations"].update(r["limitations"])
        t["first_received_at"]=min(t["first_received_at"],item["received_at"])
        t["last_received_at"]=max(t["last_received_at"],item["received_at"])
        if successful==0:
            t["latency_exclusions"]["no_successful_queries"]+=1
            continue
        if r["protocol"] not in PROTOCOLS or "protocol_unverified_or_mixed" in r["limitations"]:
            t["latency_exclusions"]["unknown_or_mixed_protocol"]+=1
            continue
        vals={k:value(m,k,"ms") for k in ("mean","p50","p95","p99","jitter")}
        if any(v is None for v in vals.values()) or not vals["p50"]<=vals["p95"]<=vals["p99"]:
            t["latency_exclusions"]["missing_or_inconsistent_latency"]+=1
            continue
        t["latency"][r["protocol"]].append((int(successful),vals))
    output=[]
    for key,targets in sorted(cohorts.items()):
        source,vantage,profile,family,provenance=key
        group={"source":source,"vantage":vantage,"profile_revision":profile,"family":family,"provenance":provenance,"targets":[]}
        for target,t in sorted(targets.items()):
            lat=[]
            for protocol,series in sorted(t.pop("latency").items()):
                n=sum(x[0] for x in series)
                lat.append({"protocol":protocol,"series":len(series),"successful_queries":n,
                    "approx_weighted_mean_ms":round(sum(count*x["mean"] for count,x in series)/n,3),
                    "median_series_p50_ms":median(x["p50"] for _,x in series),
                    "median_series_p95_ms":median(x["p95"] for _,x in series),
                    "median_series_p99_ms":median(x["p99"] for _,x in series),
                    "median_series_jitter_ms":median(x["jitter"] for _,x in series)})
            group["targets"].append({"target_id":target,**t,"limitations":sorted(t["limitations"]),
                "latency_exclusions":dict(t["latency_exclusions"]),"observed_success_ratio":t["successful"]/t["attempted"],
                "latency_by_protocol":lat})
        output.append(group)
    return {"methodology":VERSION,"records_read":len(rows),"eligible_records":len(rows)-total_excluded,
        "excluded_records":total_excluded,"exclusion_reasons":dict(sorted(excluded.items())),
        "cohorts":output,"ranking":None,"limitations":[
            "received_time_not_remote_measurement_time","retained_complete_series_only",
            "bootstrap_failures_without_target_ip_excluded","success_ratio_not_continuous_availability",
            "latency_successful_queries_only","series_percentiles_not_pooled_percentiles",
            "rounded_series_means_weighted_approximately","agent_claims_not_independently_attested",
            "same_ip_not_same_physical_anycast_node"]}
