"""Local goodput execution boundary; controller dispatch deliberately absent.

Call only while holding the existing exclusive agent.lock, including across
process restarts. The local operator owns the private policy and state files.
"""
import json
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .peer_runtime import private_regular, MAX_LOCAL_IDS
from .peer_transport import checked_ip, credentials
from .peer_throughput import (ThroughputPolicy, ThroughputPlan, ThroughputGrants,
    ThroughputReceiver, measure_throughput, MAX_BYTES)

WINDOW_NS=60_000_000_000
MAX_WINDOW_BYTES=16*1024*1024
MAX_WINDOW_SESSIONS=4
BOOT_PATTERN=r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"

class BudgetDenied(RuntimeError):pass

def boot_identity():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()

class TrafficBudget:
    """Reserve planned payload before any network operation, never refund.
    
    Monotonic time is shared across processes on Linux within a boot.
    A reboot cannot reset the window early: wait one full window after boot.
    Request IDs survive reboot and are never pruned automatically.
    """
    def __init__(self,path,atomic,*,clock=time.monotonic_ns,boot=boot_identity):
        self.path=Path(path);self.atomic=atomic;self.clock=clock;self.boot=boot
        self.lock=threading.Lock();self.poisoned=False
        self.boot_id=boot()
        if not isinstance(self.boot_id,str) or not re.fullmatch(BOOT_PATTERN,self.boot_id):
            raise ValueError("Invalid boot identity")
        if self.path.exists() or self.path.is_symlink():
            private_regular(self.path,262144)
            self.data=json.loads(self.path.read_text())
            self.validate(self.data)
        else:
            self.data={"version":1,"boot":self.boot_id,"last":0,"ids":[],"entries":[]}

    @staticmethod
    def validate(d):
        if not isinstance(d,dict) or set(d)!={"version","boot","last","ids","entries"}:
            raise ValueError("Invalid traffic budget")
        if type(d["version"]) is not int or d["version"]!=1 or not isinstance(d["boot"],str) or not re.fullmatch(BOOT_PATTERN,d["boot"]):
            raise ValueError("Invalid traffic budget identity")
        last=d["last"];ids=d["ids"];entries=d["entries"]
        if type(last) is not int or last<0 or not isinstance(ids,list) or len(ids)>MAX_LOCAL_IDS:
            raise ValueError("Invalid traffic budget history")
        if any(not isinstance(i,str) or not re.fullmatch(r"[a-f0-9]{32}",i) for i in ids) or len(set(ids))!=len(ids):
            raise ValueError("Invalid traffic budget IDs")
        if not isinstance(entries,list) or len(entries)>MAX_WINDOW_SESSIONS:
            raise ValueError("Invalid traffic window")
        total=0;previous=-1
        for e in entries:
            if not isinstance(e,list) or len(e)!=2 or any(type(x) is not int for x in e):
                raise ValueError("Invalid traffic entry")
            stamp,count=e
            if not 0<=stamp<=last or stamp<previous or not 65536<=count<=MAX_BYTES or count%16384:
                raise ValueError("Invalid traffic entry")
            total+=count;previous=stamp
        if total>MAX_WINDOW_BYTES or len(entries)>len(ids):
            raise ValueError("Invalid traffic total")

    def reserve(self,plan):
        plan=ThroughputPlan.model_validate(plan.model_dump(mode="json"))
        with self.lock:
            if self.poisoned:raise BudgetDenied("Budget persistence failed")
            d=self.data;now=self.clock()
            if type(now) is not int or now<0:raise BudgetDenied("Invalid monotonic clock")
            if plan.request_id in d["ids"]:raise BudgetDenied("Request already reserved")
            if len(d["ids"])>=MAX_LOCAL_IDS:raise BudgetDenied("Traffic journal capacity")
            if d["boot"]!=self.boot_id:
                if now<WINDOW_NS:raise BudgetDenied("Reboot quarantine")
                entries=[]
            else:
                if now<d["last"]:raise BudgetDenied("Monotonic clock rollback")
                entries=[e for e in d["entries"] if e[0]>now-WINDOW_NS]
            count=plan.policy.byte_count
            if len(entries)>=MAX_WINDOW_SESSIONS or sum(e[1] for e in entries)+count>MAX_WINDOW_BYTES:
                raise BudgetDenied("Traffic window exhausted")
            value={"version":1,"boot":self.boot_id,"last":now,
                   "ids":d["ids"]+[plan.request_id],"entries":entries+[[now,count]]}
            self.validate(value)
            # A failed write may have replaced the file before fsync failed;
            # this instance must never permit a subsequent network operation.
            try:self.atomic(self.path,value)
            except Exception:
                self.poisoned=True
                raise
            self.data=value

class ThroughputRuntime:
    """Explicit local policy, independent of RTT; no background listener."""
    def __init__(self,root,agent_id,atomic,*,clock=time.monotonic_ns,boot=boot_identity):
        self.root=Path(root);self.agent_id=agent_id
        path=self.root/"peer-throughput.json"
        private_regular(path,65536)
        rows=json.loads(path.read_text())
        if not isinstance(rows,list) or not 1<=len(rows)<=64:raise ValueError("Provide exact throughput policies")
        self.policies=tuple(ThroughputPolicy.model_validate(row) for row in rows)
        if len({p.model_dump_json() for p in self.policies})!=len(rows):raise ValueError("Duplicate throughput policy")
        self.files={k:self.root/v for k,v in (("cert","peer-cert.pem"),("key","peer-key.pem"),("ca","peer-ca.pem"))}
        for k,p in self.files.items():private_regular(p,262144,private=k=="key")
        _,fp=credentials(**self.files,server=False)
        for p in self.policies:
            d=p.direction
            if agent_id==d.source_agent_id:expected=d.source_certificate
            elif agent_id==d.destination_agent_id:expected=d.destination_certificate
            else:raise ValueError("Unrelated throughput direction")
            if expected!=fp:raise ValueError("Local certificate pin mismatch")
            checked_ip(d.source_ip);checked_ip(d.destination_ip)
        self.budget=TrafficBudget(self.root/"peer-throughput-budget.json",atomic,clock=clock,boot=boot)
        self.active=threading.Lock()

    @contextmanager
    def execution(self,plan,role,cancel):
        plan=ThroughputPlan.model_validate(plan.model_dump(mode="json"))
        if role not in ("source","receiver"):raise ValueError("Invalid throughput role")
        d=plan.direction
        expected=d.source_agent_id if role=="source" else d.destination_agent_id
        if expected!=self.agent_id or plan.policy not in self.policies:
            raise PermissionError("Local throughput policy rejected")
        if not self.active.acquire(blocking=False):raise BudgetDenied("Throughput already active")
        try:
            if cancel.is_set():raise BudgetDenied("Execution cancelled")
            if getattr(self.budget,"poisoned",False):raise BudgetDenied("Budget persistence failed")
            self.budget.reserve(plan)
            yield plan
        finally:self.active.release()

    def source(self,plan,token,cancel):
        with self.execution(plan,"source",cancel) as p:
            return measure_throughput(p,token,self.policies,cancel,**self.files)

    def receiver(self,plan,cancel,ready):
        # ready(token) must be a bounded synchronous handoff by the caller.
        # The timer covers listener setup, handoff and transport; the caller
        # must still return/raise from ready for the listener to be closed.
        with self.execution(plan,"receiver",cancel) as p:
            timer=threading.Timer(10,cancel.set);timer.daemon=True
            grants=ThroughputGrants(self.agent_id,[p.policy])
            timer.start()
            try:
                d=p.direction
                with ThroughputReceiver(d.destination_ip,d.port,grants,**self.files) as receiver:
                    if cancel.is_set():raise BudgetDenied("Execution cancelled")
                    ready(grants.issue(p,ttl=10))
                    return receiver.serve_once(cancel)
            finally:
                grants.revoke_all();timer.cancel()
