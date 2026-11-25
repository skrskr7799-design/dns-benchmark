"""DNS Intelligence v1: matched local runs, transparent conditional score."""
from collections import Counter,defaultdict
from statistics import median
from urllib.parse import urlsplit
import ipaddress
from .dns_cohorts import eligibility,value,NarrowQuery,MAX_RECORDS
from .evidence import digest

VERSION="dns-intelligence-v1"
PRESETS={"balanced":{"reliability":60,"p50":15,"p95":20,"jitter":5},
         "reliability":{"reliability":80,"p50":5,"p95":10,"jitter":5},
         "speed":{"reliability":40,"p50":25,"p95":30,"jitter":5}}
BUDGETS={"p50":20.0,"p95":50.0,"jitter":10.0}
MIN_RUNS=3
MIN_ATTEMPTS=30
MIN_SUCCESS=20
MIN_RELIABILITY=.95
SCHEMES={"udp":"udp","tcp":"tcp","tls":"dot","https":"h2","h3":"h3","quic":"doq"}
MAX_RUNS=200
MAX_GROUPS=100

def protocol(endpoint):
    return SCHEMES.get(urlsplit(endpoint).scheme)

def component(ms,budget):
    return 100/(1+ms/budget)

def calculate(target,weights):
    reasons=[]
    if target["series"]<MIN_RUNS: reasons.append("insufficient_matched_runs")
    if target["attempted"]<MIN_ATTEMPTS: reasons.append("insufficient_attempts")
    if target["successful"]<MIN_SUCCESS: reasons.append("insufficient_successful_queries")
    if target["latency_series"]!=target["successful_series"]: reasons.append("incomplete_latency_coverage")
    target["observed_success_ratio"]=target["successful"]/target["attempted"]
    values={k:median(v) if v else None for k,v in target.pop("latencies").items()}
    target["median_series_ms"]=values
    if any(v is None for v in values.values()): reasons.append("missing_latency")
    target["score"]=None
    target["components"]=None
    target["unranked_reasons"]=reasons
    if not reasons:
        components={"reliability":100*target["observed_success_ratio"],
            **{k:component(values[k],b) for k,b in BUDGETS.items()}}
        target["components"]={k:{"weight":weights[k],"normalized":round(v,3),
            "contribution":round(v*weights[k]/100,3)} for k,v in components.items()}
        target["score"]=round(sum(v*weights[k]/100 for k,v in components.items()),2)
    return target

def rank(rows,metadata,preset="balanced",*,pending=0,stream_error=None):
    if preset not in PRESETS:
        raise ValueError("Invalid scoring preset")
    if len(rows)>MAX_RECORDS or len(metadata)>MAX_RUNS:
        raise NarrowQuery("Narrow ranking window")
    weights=PRESETS[preset]
    by_run=defaultdict(dict)
    duplicated=set()
    for item in rows:
        r=item["record"]
        if r["source_kind"]!="benchmark" or r["vantage_id"]!="controller" or r["provenance"]!="controller":
            continue
        run=r["run_id"]
        if not run: continue
        try: ordinal=int(r["source_part"])
        except (ValueError,TypeError): continue
        if ordinal in by_run[run]: duplicated.add(run)
        by_run[run][ordinal]=item
    if len(by_run)>MAX_RUNS: raise NarrowQuery("Too many runs")
    groups={}
    excluded=Counter()
    for run,observed in sorted(by_run.items()):
        meta=metadata.get(run)
        if not meta or meta["status"]!="completed" or run in duplicated:
            excluded["missing_or_noncompleted_source_run"]+=1
            continue
        cfg=meta["config"]
        endpoints=cfg["endpoints"]
        modes=("cold","warm") if cfg["mode"]=="both" else (cfg["mode"],)
        for offset,mode in enumerate(modes):
            # A filtered window may contain only one mode. Never invent its counterpart.
            expected={i*len(modes)+offset:e for i,e in enumerate(endpoints)}
            for intended in sorted({protocol(e) for e in endpoints if protocol(e)}):
                subset={i:e for i,e in expected.items() if protocol(e)==intended}
                present=set(subset)&set(observed)
                if not present: continue
                if len(subset)<2:
                    excluded["fewer_than_two_same_protocol_targets"]+=1
                    continue
                if present!=set(subset) or len(set(subset.values()))!=len(subset):
                    excluded["unmatched_or_duplicate_target_set"]+=1
                    continue
                batch=[];invalid=False
                for ordinal,endpoint in subset.items():
                    item=observed[ordinal];r=item["record"]
                    mdata=meta["results"].get(ordinal)
                    reasons,counts,m=eligibility(r)
                    if not mdata or reasons or mdata["endpoint"]!=endpoint or mdata["mode"]!=mode:
                        invalid=True;break
                    try: address=ipaddress.ip_address(mdata["ip"])
                    except (ValueError,TypeError): invalid=True;break
                    if r["target_id"]!=digest({"endpoint":endpoint,"bootstrap_ip":str(address)}) or r["family"]!=("ipv4" if address.version==4 else "ipv6"):
                        invalid=True;break
                    attempted,successful,requested=counts
                    if requested!=cfg["count"] or (successful and (r["protocol"]!=intended or "protocol_unverified_or_mixed" in r["limitations"])):
                        invalid=True;break
                    vals={k:value(m,k,"ms") for k in BUDGETS}
                    p99=value(m,"p99","ms")
                    valid_latency=successful>0 and all(v is not None for v in vals.values()) and p99 is not None and vals["p50"]<=vals["p95"]<=p99
                    batch.append((r,item,endpoint,str(address),int(attempted),int(successful),vals if valid_latency else None))
                if invalid or len({(r["profile_revision"],r["family"]) for r,*_ in batch})!=1:
                    excluded["ineligible_or_mismatched_series"]+=1
                    continue
                identities=tuple(sorted(r["target_id"] for r,*_ in batch))
                if len(set(identities))!=len(identities):
                    excluded["duplicate_target_identity"]+=1;continue
                profile,family=batch[0][0]["profile_revision"],batch[0][0]["family"]
                key=(mode,intended,family,profile,identities)
                if key not in groups:
                    if len(groups)>=MAX_GROUPS: raise NarrowQuery("Too many comparison groups")
                    groups[key]={"runs":0,"targets":{},"first_received_at":None,"last_received_at":None}
                g=groups[key];g["runs"]+=1
                for r,item,endpoint,ip,attempted,successful,vals in batch:
                    ts=item["received_at"]
                    g["first_received_at"]=ts if g["first_received_at"] is None else min(ts,g["first_received_at"])
                    g["last_received_at"]=ts if g["last_received_at"] is None else max(ts,g["last_received_at"])
                    t=g["targets"].setdefault(r["target_id"],{"target_id":r["target_id"],"endpoint":endpoint,"bootstrap_ip":ip,
                        "series":0,"attempted":0,"successful":0,"successful_series":0,"latency_series":0,
                        "latencies":{k:[] for k in BUDGETS},"example_evidence_id":item["id"]})
                    t["series"]+=1;t["attempted"]+=attempted;t["successful"]+=successful
                    t["successful_series"]+=int(successful>0)
                    if vals is not None:
                        t["latency_series"]+=1
                        for k,v in vals.items():t["latencies"][k].append(v)
    output=[]
    for key,g in sorted(groups.items()):
        mode,intended,family,profile,identities=key
        targets=[calculate(t,weights) for t in g["targets"].values()]
        targets.sort(key=lambda t:(t["score"] is None,-(t["score"] or 0),t["target_id"]))
        ranked=[t for t in targets if t["score"] is not None]
        for i,t in enumerate(ranked):
            t["rank"]=i+1 if i==0 or t["score"]!=ranked[i-1]["score"] else ranked[i-1]["rank"]
        for t in targets:
            t.setdefault("rank",None)
        recommended=None
        why=[]
        if pending or stream_error: why.append("producer_backlog_or_error")
        if len(ranked)<2: why.append("fewer_than_two_scored_targets")
        if ranked and ranked[0]["observed_success_ratio"]<MIN_RELIABILITY: why.append("best_target_below_reliability_floor")
        if len(ranked)>=2 and ranked[0]["score"]==ranked[1]["score"]: why.append("tied_top_score")
        if not why:
            recommended=ranked[0]["target_id"]
        output.append({"group_id":digest(key),"mode":mode,"protocol":intended,"family":family,
            "profile_revision":profile,"matched_runs":g["runs"],"first_received_at":g["first_received_at"],
            "last_received_at":g["last_received_at"],"targets":targets,"recommended_target_id":recommended,
            "recommendation_blockers":why})
    return {"methodology":VERSION,"preset":preset,"weights":weights,"latency_reference_ms":BUDGETS,
        "minimum":{"matched_runs":MIN_RUNS,"attempted_queries":MIN_ATTEMPTS,"successful_queries":MIN_SUCCESS,
            "recommendation_success_ratio":MIN_RELIABILITY},
        "records_read":len(rows),"runs_considered":len(by_run),"excluded_run_groups":dict(sorted(excluded.items())),
        "groups":output,"coverage":{"producer_pending":pending,"stream_error":stream_error,"complete_window_verified":False},
        "limitations":["local_controller_only","same_protocol_family_workload_and_target_set","conditional_on_retained_matched_runs",
            "excluded_runs_may_bias_scores","series_percentiles_not_pooled_percentiles","reference_budgets_are_policy_not_standards",
            "observed_success_not_continuous_availability","same_ip_not_same_physical_anycast_node",
            "no_privacy_security_or_filtering_score","no_automatic_dns_configuration","no_failover_independence_claim"]}
