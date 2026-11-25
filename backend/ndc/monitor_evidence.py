"""Projection of committed monitor checks and actual incident transitions."""
import json
import ipaddress
from .evidence import Observation,Measurement,Event,digest,canonical
from .benchmark_evidence import number,PROTOCOLS

STREAM="monitor-v1"

def project(monitor_id,seq,cfg,result,at,transition=None):
    kind=cfg.kind
    source_outcome=result.get("outcome")
    outcome={"healthy":"success","degraded":"partial","failed":"failure","unknown":"unknown"}.get(source_outcome,"unknown")
    details=result.get("details")
    details=details if isinstance(details,dict) else {}
    limitations=["check_commit_time","observed_probe_not_continuous_uptime"]
    ip=details.get("ip")
    try:
        address=ipaddress.ip_address(ip) if isinstance(ip,str) else None
    except ValueError:
        address=None
    if address is None:
        limitations.append("bootstrap_ip_unavailable")
    protocol=details.get("protocol")
    if not isinstance(protocol,str) or protocol not in PROTOCOLS or kind!="dns":
        protocol=None
        limitations.append("protocol_unverified")
    metrics=[Measurement(name="latency",unit="ms",value=number(result.get("latency_ms")))]
    if kind in ("http","https"):
        status=number(details.get("http_status"),True)
        metrics.append(Measurement(name="http_status",unit="count",value=status if status is not None and 100<=status<=599 else None))
    if kind in ("tls","https"):
        days=details.get("certificate_days")
        if type(days) in (int,float) and days<0:
            limitations.append("certificate_expired")
        metrics.append(Measurement(name="certificate_days_remaining",unit="days",value=number(days)))
    metrics.append(Measurement(name="probe_healthy",unit="boolean",value=None if outcome=="unknown" else float(outcome=="success")))
    profile=digest({"projection":"monitor-v1","kind":kind,"family":cfg.family,
        "interval_seconds":cfg.interval_seconds,"failure_count":cfg.failure_count,
        "recovery_count":cfg.recovery_count,"latency_ms":cfg.latency_ms,"expiry_days":cfg.expiry_days})
    target=digest({"kind":kind,"host":cfg.host,"port":cfg.port if kind!="dns" else None,
        "path":cfg.path if kind in ("http","https") else None,"endpoint":cfg.endpoint if kind=="dns" else None,
        "bootstrap_ip":str(address) if address else None})
    observation=Observation(source_kind="monitor",source_id=monitor_id,source_revision=seq,source_part="check",
        vantage_id="controller",observed_at=at,target_id=target,profile_revision=profile,
        probe_kind="http" if kind=="https" else kind,outcome=outcome,provenance="controller",
        measurements=tuple(metrics),protocol=protocol,family=("ipv4" if address.version==4 else "ipv6") if address else None,
        limitations=tuple(limitations))
    events=()
    if transition:
        events=(Event(event_type=transition,source_kind="monitor",source_id=monitor_id,source_revision=seq,
            deduplication_key="transition",rule_version="monitor-state-v1",observed_at=at,
            severity="warning" if transition=="incident.opened" else "info",confidence="observed",
            evidence_ids=(observation.identity,)),)
    return observation,events

def encode(observation,events):
    return canonical({"observation":observation.model_dump(mode="json"),"events":[x.model_dump(mode="json") for x in events]})

def decode(raw):
    value=json.loads(raw)
    return Observation.model_validate_json(canonical(value["observation"])),tuple(
        Event.model_validate_json(canonical(x)) for x in value["events"])
