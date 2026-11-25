"""Compact, versioned benchmark projection and durable outbox consumer."""
import ipaddress
import logging
import math
import threading
import time
from .evidence import Observation,Measurement,digest,Capacity

log=logging.getLogger(__name__)
STREAM="benchmark-v1"
PROTOCOLS={"udp","tcp","dot","h2","h3","doq"}

def number(value,integer=False):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0:
        return None
    if integer and int(value)!=value:
        return None
    return float(value)

def project(job_id,ordinal,config,result,recorded_at):
    # The source only records completion/commit time, not per-query wall time.
    endpoint=result.get("endpoint")
    mode=result.get("mode")
    family=result.get("family")
    engine=result.get("engine")
    samples=result.get("samples")
    samples=samples if isinstance(samples,list) else []
    count=number(result.get("count"),True)
    ok=number(result.get("ok"),True)
    requested=number(result.get("requested_count"),True)
    limits=["result_commit_time"]
    expected_index=ordinal//2 if config.get("mode")=="both" else ordinal
    endpoints=config.get("endpoints",[])
    expected=endpoints[expected_index] if 0<=expected_index<len(endpoints) else None
    expected_mode=("cold" if ordinal%2==0 else "warm") if config.get("mode")=="both" else config.get("mode")
    known=(isinstance(endpoint,str) and endpoint==expected and mode==expected_mode
           and family==config.get("family") and engine=="python-dns02"
           and count is not None and ok is not None and requested is not None
           and 1<=requested<=100 and requested==config.get("count") and 0<=ok<=count<=requested)
    if not known:
        limits.append("incomplete_source_metadata")
    valid_samples=(known and len(samples)==count and all(isinstance(x,dict) and type(x.get("ok")) is bool
        and isinstance(x.get("domain"),str) and x.get("qtype")=="A" and x.get("index")==i
        for i,x in enumerate(samples)) and sum(x["ok"] for x in samples)==ok)
    if not valid_samples:
        limits.append("sample_coverage_unverified")
    warmup=result.get("warmup")
    warm_valid=mode!="warm" or (isinstance(warmup,dict) and warmup.get("ok") is True and not result.get("warmup_error"))
    if not warm_valid:
        limits.append("warmup_unverified_or_failed")
    protocols=result.get("protocols")
    protocol=protocols[0] if isinstance(protocols,list) and len(protocols)==1 and protocols[0] in PROTOCOLS else None
    if protocol is None:
        limits.append("protocol_unverified_or_mixed")
    ip=result.get("ip")
    try:
        address=ipaddress.ip_address(ip) if isinstance(ip,str) else None
    except ValueError:
        address=None
    if address is None:
        limits.append("bootstrap_ip_unavailable")
    peer_ips=result.get("peer_ips")
    if not isinstance(peer_ips,list) or not peer_ips:
        limits.append("peer_ip_unverified")
    else:
        # Even a verified peer IP is not proof of physical anycast identity.
        limits.append("anycast_identity_unverified")
    if known and valid_samples:
        outcome="failure" if count>0 and ok==0 else "success" if count==requested and ok==count and warm_valid else "partial" if count>0 else "unknown"
    else:
        outcome="unknown"
    metrics=[Measurement(name=name,unit="count",value=value) for name,value in
             (("attempted",count),("successful",ok),("requested",requested)) if known]
    if known and valid_samples:
        metrics.append(Measurement(name="success_ratio",unit="ratio",value=ok/count if count else None))
        for name in ("mean","p50","p95","p99","jitter","bootstrap_ms"):
            metrics.append(Measurement(name=name,unit="ms",value=number(result.get(name))))
        reuse=result.get("reuse")
        if isinstance(reuse,dict):
            for name in ("yes","no","unknown"):
                metrics.append(Measurement(name="reuse_"+name,unit="count",value=number(reuse.get(name),True)))
    # Profile identity excludes endpoint and includes actual corpus and settings.
    corpus=[x["domain"] for x in samples] if valid_samples else None
    profile=digest({"projection":"benchmark-v1","engine":engine if known else None,
        "mode":expected_mode,"family":config.get("family"),"count":config.get("count"),
        "parallel":config.get("parallel"),"corpus":corpus,"qtype":"A" if valid_samples else None})
    target=digest({"endpoint":expected,"bootstrap_ip":str(address) if address else None})
    return Observation(source_kind="benchmark",source_id=job_id,source_revision=1,source_part=str(ordinal),
        run_id=job_id,vantage_id="controller",observed_at=recorded_at,target_id=target,profile_revision=profile,
        probe_kind="dns",outcome=outcome,provenance="controller",measurements=tuple(metrics),protocol=protocol,
        family=("ipv4" if address.version==4 else "ipv6") if address else None,limitations=tuple(limits))

class BenchmarkDrain:
    def __init__(self,source,evidence,clock=time.time):
        self.source=source
        self.evidence=evidence
        self.clock=clock
        self.stop_event=threading.Event()
        self.thread=None
        self.last_error=None
        self.next_prune=0

    def once(self,after_commit=None):
        row=self.source.pending_evidence()
        if row is None:
            return False
        record=Observation.model_validate_json(row["payload"])
        self.evidence.ingest(STREAM,row["seq"],(record,))
        if after_commit:
            after_commit()
        self.source.ack_evidence(row["seq"])
        return True

    def start(self):
        self.thread=threading.Thread(target=self.loop,name="ndc-evidence-drain",daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(17)

    def loop(self):
        while not self.stop_event.is_set():
            try:
                now=self.clock()
                if now>=self.next_prune:
                    self.evidence.prune(before=max(0,now-30*86400))
                    self.next_prune=now+60
                for _ in range(32):
                    if self.stop_event.is_set() or not self.once():
                        break
                self.last_error=None
                self.stop_event.wait(.5)
            except Exception as exc:
                error=type(exc).__name__
                if self.last_error!=error:
                    log.warning("Benchmark evidence drain blocked: %s",error)
                self.last_error=error
                self.stop_event.wait(5)
