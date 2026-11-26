"""Disposable in-memory fault model. No network sockets, host changes or privileges."""
import hashlib
import json
import os
import subprocess
import sys
import time
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field
MAX_SECONDS=5
class Experiment(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    seed:int=Field(ge=0,le=2147483647)
    samples:int=Field(default=20,ge=1,le=100)
    baseline_ms:int=Field(default=20,ge=1,le=1000)
    delay_ms:int=Field(default=0,ge=0,le=5000)
    loss_pct:int=Field(default=0,ge=0,le=100)
    dns:Literal["normal","servfail","timeout"]="normal"
    timeout_ms:int=Field(default=1000,ge=1,le=10000)

def execute(cfg):
    rows=[]
    for i in range(cfg.samples):
        # Reproducible pseudo-random sampling independent of Python RNG version.
        bucket=int.from_bytes(hashlib.sha256(f"{cfg.seed}:{i}".encode()).digest()[:8],"big")%10000
        if cfg.dns=="servfail":outcome="dns_servfail";elapsed=None
        elif cfg.dns=="timeout":outcome="dns_timeout";elapsed=cfg.timeout_ms
        elif bucket<cfg.loss_pct*100:outcome="simulated_loss";elapsed=cfg.timeout_ms
        elif cfg.baseline_ms+cfg.delay_ms>cfg.timeout_ms:outcome="simulated_deadline";elapsed=cfg.timeout_ms
        else:outcome="success";elapsed=cfg.baseline_ms+cfg.delay_ms
        rows.append({"index":i,"outcome":outcome,"modeled_ms":elapsed})
    counts={k:sum(r["outcome"]==k for r in rows) for k in ("success","dns_servfail","dns_timeout","simulated_loss","simulated_deadline")}
    return {"status":"completed","methodology":"synthetic_fault_model_v1","profile":cfg.model_dump(mode="json"),
        "rows":rows,"counts":counts,"baseline_success":cfg.samples if cfg.baseline_ms<=cfg.timeout_ms else 0,
        "limitations":["synthetic_not_live_network_measurement","no_packets_sent","no_host_or_interface_changes","not_kernel_netem","no_throughput_capacity_model"]}

def run(cfg):
    try:
        # Minimal environment, no controller secrets or data path passed to worker.
        env={k:v for k,v in os.environ.items() if k in ("PATH","LANG","LC_ALL","PYTHONPATH")}
        r=subprocess.run([sys.executable,"-m","backend.ndc.chaos_lab"],input=cfg.model_dump_json(),
            text=True,capture_output=True,timeout=MAX_SECONDS,env=env,check=False)
    except subprocess.TimeoutExpired:raise RuntimeError("Chaos model deadline") from None
    if r.returncode or len(r.stdout)>65536:raise RuntimeError("Chaos model failed")
    return json.loads(r.stdout)

if __name__=="__main__":
    print(json.dumps(execute(Experiment.model_validate_json(sys.stdin.read(4096))),allow_nan=False))
