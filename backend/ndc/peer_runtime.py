"""Explicit local peer RTT opt-in, serialized within the existing agent lock.

No controller-provided file paths, bind addresses outside exact local policy,
or durable grant tokens. A lost execution response is never retried.
"""
import json
import os
import re
import stat
import threading
import time
from pathlib import Path
import httpx
from .peer_contract import PeerDirection,RTTPlan,LocalGrants
from .peer_transport import Receiver,measure,credentials,checked_ip

MAX_LOCAL_IDS=2048
CLAIM_REFRESH_SECONDS=12
PEER_IDLE_SECONDS=4

class ClaimRefresh:
    """Rate-bound successful and disabled claim refreshes; never cache credentials."""
    def __init__(self,clock=time.monotonic):
        self.clock=clock;self.next_at=None;self.enabled=False

    def refresh(self,post,body):
        now=self.clock()
        if self.next_at is not None and now<self.next_at:return self.enabled
        response=post('claims',body)
        if response.status_code==409:
            self.enabled=False
        else:
            response.raise_for_status();self.enabled=True
        self.next_at=self.clock()+CLAIM_REFRESH_SECONDS
        return self.enabled

    def invalidate(self):
        self.next_at=None;self.enabled=False

def private_regular(path,limit,private=True):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size>limit or (private and st.st_mode&0o077):
        raise ValueError("Invalid local peer file")

class Journal:
    # The outer agent.lock serializes all operations. Atomic write fsyncs file
    # and directory. No auto-pruning: fail closed when the bounded ledger fills.
    def __init__(self,path,atomic,finish_model=None):
        self.path=path;self.atomic=atomic;self.poisoned=False
        if finish_model is None:
            from .peer_api import Finish
            finish_model=Finish
        self.finish_model=finish_model
        if path.exists() or path.is_symlink():
            private_regular(path,2*1024*1024)
            self.data=json.loads(path.read_text())
            ids=self.data.get("ids")
            if (self.data.get("version")!=1 or not isinstance(ids,list) or len(ids)>MAX_LOCAL_IDS
                or any(not isinstance(i,str) or not re.fullmatch(r"[a-f0-9]{32}",i) for i in ids)
                or len(set(ids))!=len(ids) or set(self.data)!={"version","ids","pending"}):
                raise ValueError("Invalid peer journal")
            if self.data["pending"] is not None:
                p=self.finish_model.model_validate(self.data["pending"])
                if p.id not in ids:raise ValueError("Untracked peer result")
        else:self.data={"version":1,"ids":[],"pending":None}

    def commit(self,value):
        if self.poisoned:raise RuntimeError("Peer journal persistence failed")
        try:self.atomic(self.path,value)
        except Exception:
            self.poisoned=True
            raise
        self.data=value

    def begin(self,id):
        if not isinstance(id,str) or not re.fullmatch(r"[a-f0-9]{32}",id):raise ValueError("Invalid peer request")
        if id in self.data["ids"]:return False
        if len(self.data["ids"])>=MAX_LOCAL_IDS:raise RuntimeError("Peer journal capacity")
        if self.data["pending"] is not None:raise RuntimeError("Pending peer result")
        self.commit(self.data|{"ids":self.data["ids"]+[id]})
        return True

    def finish(self,body):
        b=self.finish_model.model_validate(body)
        if b.id not in self.data["ids"] or self.data["pending"] is not None:raise RuntimeError("Invalid peer result")
        self.commit(self.data|{"pending":b.model_dump(mode="json")})

    def clear(self):
        self.commit(self.data|{"pending":None})

class PeerRuntime:
    def __init__(self,root,agent_id,post,atomic):
        self.root=Path(root);self.agent_id=agent_id;self.post=post
        self.claim_refresh=ClaimRefresh()
        path=self.root/"peer-directions.json"
        private_regular(path,65536)
        rows=json.loads(path.read_text())
        if not isinstance(rows,list) or not 1<=len(rows)<=64:raise ValueError("Provide explicit peer directions")
        self.approvals=tuple(PeerDirection.model_validate(r) for r in rows)
        keys={d.model_dump_json() for d in self.approvals}
        if len(keys)!=len(rows):raise ValueError("Duplicate peer direction")
        self.files={k:self.root/v for k,v in (("cert","peer-cert.pem"),("key","peer-key.pem"),("ca","peer-ca.pem"))}
        for k,p in self.files.items():private_regular(p,262144,private=k=="key")
        _,fp=credentials(**self.files,server=False)
        for d in self.approvals:
            if self.agent_id==d.source_agent_id:expected=d.source_certificate
            elif self.agent_id==d.destination_agent_id:expected=d.destination_certificate
            else:raise ValueError("Unrelated peer direction")
            if expected!=fp:raise ValueError("Local certificate pin mismatch")
            checked_ip(d.source_ip);checked_ip(d.destination_ip)
        self.grants=LocalGrants(agent_id,[d for d in self.approvals if d.destination_agent_id==agent_id])
        self.journal=Journal(self.root/"peer-journal.json",atomic)

    def call(self,path,body):
        response=self.post(path,body)
        response.raise_for_status()
        return response.json()

    def flush(self):
        body=self.journal.data["pending"]
        if body is None:return True
        response=self.post("finish",body)
        if response.status_code in (200,404,409,422):
            self.journal.clear()
            return True
        response.raise_for_status()
        return False

    def step(self):
        if not self.flush():return True
        if not self.claim_refresh.refresh(self.post,{"directions":[d.model_dump(mode="json") for d in self.approvals]}):return False
        response=self.post("offer",{})
        if response.status_code==409:
            self.claim_refresh.invalidate();return False
        response.raise_for_status();offer=response.json()["offer"]
        if offer is None:return False
        id=offer["id"];role=offer["role"]
        if role not in ("receiver","source"):raise ValueError("Unknown peer role")
        if not self.journal.begin(id):return True
        # Mark before the ambiguous network handoff. No second lease attempt
        # for this request ID even after a crash or lost HTTP response.
        start=time.monotonic()
        reply=self.call("prepare" if role=="receiver" else "start",{"id":id})
        plan=RTTPlan.model_validate(reply["plan"]);d=plan.direction;lease=reply["lease"]
        from .peer_api import Leased
        Leased(id=id,lease=lease)
        if plan.request_id!=id or d not in self.approvals or (d.destination_agent_id if role=="receiver" else d.source_agent_id)!=self.agent_id:
            raise ValueError("Local peer policy rejected")
        cancel=threading.Event();done=threading.Event()
        def active():
            try:return self.call("status",{"id":id,"lease":lease})["active"] is True
            except Exception:return False
        def monitor():
            while not done.wait(.5):
                if not active():
                    cancel.set();return
        # Local hard deadline includes handoff, and is independent of controller
        # wall clock. Receiver/source transports also enforce their own 10s cap.
        timer=threading.Timer(max(0,10-(time.monotonic()-start)),cancel.set)
        worker=threading.Thread(target=monitor,daemon=True)
        timer.start()
        worker.start()
        result=None
        try:
            if not active():return True
            if role=="receiver":
                grant=self.grants.issue(plan,ttl=15)
                with Receiver(d.destination_ip,d.port,self.grants,**self.files) as receiver:
                    if cancel.is_set():return True
                    self.call("ready",{"id":id,"lease":lease,"grant":grant})
                    echoes,_=receiver.serve_once(cancel)
                    result={"id":id,"lease":lease,"echoes":echoes}
            else:
                report,_=measure(plan,reply["grant"],self.approvals,cancel,**self.files)
                result={"id":id,"lease":lease,"report":report.model_dump(mode="json")}
        finally:
            self.grants.revoke_all()
            timer.cancel();done.set();worker.join(3)
        if not cancel.is_set() and result is not None:
            self.journal.finish(result);self.flush()
        return True
