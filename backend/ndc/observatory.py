"""Read-only, bounded monitor latency analysis.

Signals are reconstructed from retained evidence, not durable incident transitions.
Never infer uptime or historical maintenance from missing checks.
"""
from collections import Counter,deque
from statistics import median
from .dns_cohorts import metrics,value,NarrowQuery

VERSION="observatory-v1"
MAX_ROWS=2000
MIN_BASELINE=12
BASELINE_SIZE=30
MAX_WINDOW=7*86400
BASELINE_AGE=86400
CONFIRM=2

def comparable(r):
    # Non-DNS monitor transport is implicit in immutable probe profile.
    if (r["source_kind"]!="monitor" or r["vantage_id"]!="controller" or
        r["provenance"]!="controller" or r["family"] not in ("ipv4","ipv6") or
        "bootstrap_ip_unavailable" in r["limitations"] or
        (r["probe_kind"]=="dns" and r["protocol"] is None)):
        return None
    return (r["target_id"],r["profile_revision"],r["family"],r["protocol"],r["probe_kind"])

def analyze(rows,monitor,*,since,before,now):
    if len(rows)>MAX_ROWS: raise NarrowQuery("Narrow observatory window")
    interval=monitor["config"]["interval_seconds"]
    # Fixed-delay scheduling and a shared execution lane: a gap is unobserved,
    # not a count of failed scheduled checks.
    gap_threshold=3*interval
    baseline=deque(maxlen=BASELINE_SIZE)
    counts=Counter()
    signals=[]
    points=[]
    prev=None;identity=None;bad=good=0;active=False
    def interrupt(reason,at):
        nonlocal bad,good,active
        if active:
            signals.append({"type":"anomaly.interrupted","at":at,"reason":reason,"evidence_id":None})
        baseline.clear();bad=good=0;active=False

    for item in rows:
        r=item["record"]
        if r["source_id"]!=monitor["id"] or r["source_kind"]!="monitor":
            continue
        at=r["observed_at"]
        if at is None or not since<=at<before:
            continue
        outcome=r["outcome"]
        counts[outcome]+=1
        latency=value(metrics(r),"latency","ms")
        current=comparable(r)
        gap=prev is not None and (at-prev>gap_threshold or at<=prev)
        if gap:
            interrupt("observation_gap_or_clock_discontinuity",at)
        if identity is not None and current!=identity:
            interrupt("comparison_identity_changed",at)
        identity=current
        prev=at
        while baseline and at-baseline[0][0]>BASELINE_AGE:
            baseline.popleft()
        center=mad=threshold=None
        state="unknown"
        if outcome not in ("success","partial") or current is None or latency is None:
            interrupt("noncomparable_or_missing_latency",at)
            state="unavailable" if outcome=="failure" else "unknown"
        else:
            # Baseline only admits healthy, non-anomalous checks. Freeze during
            # candidate/active anomaly and recovery; never train on degradation.
            if len(baseline)>=MIN_BASELINE:
                center=median(v for _,v in baseline)
                mad=median(abs(v-center) for _,v in baseline)
                threshold=center+max(5.0,.5*center,6*1.4826*mad)
                if latency>threshold:
                    bad+=1;good=0
                    if bad>=CONFIRM and not active:
                        active=True
                        signals.append({"type":"anomaly.detected","at":at,"reason":"consecutive_high_latency","evidence_id":item["id"]})
                    state="anomaly" if active else "candidate"
                elif active:
                    bad=0;good=good+1 if outcome=="success" else 0
                    state="recovering" if good else "anomaly"
                    if good>=CONFIRM:
                        active=False;good=0;state="normal"
                        signals.append({"type":"anomaly.recovered","at":at,"reason":"consecutive_healthy_latency","evidence_id":item["id"]})
                        baseline.append((at,latency))
                else:
                    bad=good=0;state="normal" if outcome=="success" else "degraded"
                    if outcome=="success": baseline.append((at,latency))
            else:
                # Expiration during an active anomaly cannot imply recovery.
                if active: interrupt("baseline_expired",at)
                bad=good=0;state="learning"
                if outcome=="success": baseline.append((at,latency))
        points.append({"at":at,"received_at":item["received_at"],"evidence_id":item["id"],"outcome":outcome,
            "latency_ms":latency,"baseline_ms":center,"mad_ms":mad,"threshold_ms":threshold,
            "baseline_samples":len(baseline),"state":state,"gap_before":gap})
    known=sum(counts[k] for k in ("success","partial","failure"))
    total=len(points)
    last=points[-1] if points else None
    # Historical query status is not the current scheduler state.
    live_window=abs(before-now)<=gap_threshold
    stale=last is None or before-last["at"]>gap_threshold
    current_state=("paused" if not monitor["enabled"] else "stale" if stale else last["state"]) if live_window else None
    return {"methodology":VERSION,"monitor":{"id":monitor["id"],"name":monitor["config"]["name"],
            "kind":monitor["config"]["kind"],"enabled":monitor["enabled"],"interval_seconds":interval,
            "source_state":monitor["state"],"last_at":monitor["last_at"]},
        "window":{"since":since,"before":before,"time_basis":"observed_at_check_commit"},
        "counts":{"total":total,"success":counts["success"],"degraded":counts["partial"],"failure":counts["failure"],
            "unknown":total-known,"known":known},
        "observed_healthy_ratio":counts["success"]/known if known else None,
        "gap_count":sum(p["gap_before"] for p in points),"last_point_state":last["state"] if last else None,
        "current_state":current_state,"stale_at_window_end":stale,"points":points,"signals":signals,
        "policy":{"baseline_minimum":MIN_BASELINE,"baseline_maximum":BASELINE_SIZE,"baseline_max_age_seconds":BASELINE_AGE,
            "confirmation_checks":CONFIRM,"recovery_checks":CONFIRM,"gap_seconds":gap_threshold,
            "threshold":"median + max(5 ms, 0.5 * median, 6 * 1.4826 * MAD)"},
        "limitations":["retained_window_only","not_continuous_uptime","historical_pause_intervals_unknown",
            "missing_checks_not_failures","signals_recomputed_not_persisted","latency_signal_not_root_cause",
            "no_cross_monitor_correlation","no_new_network_probes"]}
