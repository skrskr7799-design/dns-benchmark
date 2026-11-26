"""Outbound-only agent; DNS engine shared byte-for-byte with controller."""
import fcntl
import json
import os
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from .agent_contract import AgentRun, ENGINE, VERSION, PROTOCOL_V2, ENGINE_V2
from .probes.dns import measure, measure_both

def atomic(path,value):
    temp=path.with_suffix(".tmp")
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as f:
        json.dump(value,f,allow_nan=False)
        f.flush()
        os.fsync(f.fileno())
    temp.replace(path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def controller_url(value):
    u=urlsplit(value)
    if not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ("","/"):
        raise ValueError("Controller must be an origin URL")
    if u.scheme!="https" and not (u.scheme=="http" and u.hostname in ("127.0.0.1","::1") and os.getenv("NDC_AGENT_TEST_HTTP")=="1"):
        raise ValueError("Verified HTTPS required")
    return value.rstrip("/")

def execute(task,allowed,cancel=None):
    if task["version"]!=VERSION or task["engine"]!=ENGINE:
        raise ValueError("Unsupported contract")
    cfg=AgentRun.model_validate(task["config"])
    if any(e not in allowed for e in cfg.endpoints):
        raise ValueError("Endpoint not in local allowlist")
    cancel=cancel or threading.Event()
    endpoint=cfg.endpoints[0]
    if cfg.mode=="both":
        rows=list(measure_both(endpoint,cfg.count,cfg.family,cancel))
    else:
        row=measure(endpoint,cfg.count,cfg.mode,cfg.family,cancel)
        rows=[row] if row is not None else []
    if cancel.is_set() or not rows or any(r["count"]!=cfg.count for r in rows):
        raise ValueError("Measurement interrupted")
    return rows

class Agent:
    def __init__(self,root,url,allowed,*,protocol_v2=False):
        self.root=Path(root);self.url=controller_url(url);self.allowed=frozenset(allowed)
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.identity=self.root/"identity.json"
        self.spool=self.root/"spool.json"
        self.client=httpx.Client(timeout=10,trust_env=False,follow_redirects=False,
                                 verify=os.getenv("NDC_AGENT_CA_FILE") or True)
        self.credential=None
        self.protocol_v2=protocol_v2

    def post(self,path,body,auth=True):
        headers={"Authorization":"Bearer "+self.credential} if auth else {}
        return self.client.post(self.url+"/api/v1/agents/machine/"+path,json=body,headers=headers)

    def enroll(self):
        if self.identity.exists():
            saved=json.loads(self.identity.read_text())
            if saved["controller"]!=self.url:
                raise ValueError("Identity belongs to a different controller")
            self.credential=saved["credential"]
            return
        token_file=self.root/"enrollment-token"
        token=token_file.read_text().strip()
        r=self.post("enroll",{"token":token},False)
        r.raise_for_status()
        value=r.json()
        atomic(self.identity,{"controller":self.url,"id":value["id"],"credential":value["credential"]})
        self.credential=value["credential"]
        token_file.unlink()

    def flush(self):
        if not self.spool.exists():
            return True
        value=json.loads(self.spool.read_text())
        if value["state"]=="executing":
            # Crash during measurement: never rerun the lease.
            value={"state":"ready","id":value["id"],"body":{"lease":value["lease"],"status":"failed","results":[],"error":"Agent restarted during measurement"}}
            atomic(self.spool,value)
        r=self.post("results/"+value["id"],value["body"])
        if r.status_code in (200,404,409,422):
            if r.status_code!=200:
                print("Result rejected or expired: "+str(r.status_code),flush=True)
            self.spool.unlink()
            return True
        r.raise_for_status()
        return False

    def step(self):
        if not self.flush():
            return
        if self.protocol_v2:
            r=self.post("v2/poll",{"version":PROTOCOL_V2,"engine":ENGINE_V2,"capabilities":["dns"]})
        else:
            r=self.post("poll",{"version":VERSION,"engine":ENGINE})
        r.raise_for_status()
        reply=r.json()
        if self.protocol_v2 and reply.get("version")!=PROTOCOL_V2:
            raise ValueError("Unsupported controller contract")
        task=reply["task"]
        if not task:
            return
        import re
        if not re.fullmatch(r"[a-f0-9]{32}",task["id"]):
            raise ValueError("Invalid task ID")
        atomic(self.spool,{"state":"executing","id":task["id"],"lease":task["lease"]})
        cancel=threading.Event()
        timer=threading.Timer(min(240,task["lease_seconds"]-15),cancel.set)
        done=threading.Event()
        def heartbeat():
            while not done.wait(10):
                try:
                    response=self.post("heartbeat",{"version":VERSION,"engine":ENGINE,"task_id":task["id"],"lease":task["lease"]})
                    if response.status_code==401 or (response.status_code==200 and not response.json()["active"]):
                        cancel.set()
                        return
                except httpx.HTTPError:
                    pass
        worker=threading.Thread(target=heartbeat,daemon=True)
        timer.start()
        worker.start()
        try:
            rows=execute(task,self.allowed,cancel)
            body={"lease":task["lease"],"status":"completed","results":rows}
        except Exception as exc:
            body={"lease":task["lease"],"status":"failed","results":[],"error":type(exc).__name__+": "+str(exc)[:200]}
        finally:
            timer.cancel()
            done.set()
            worker.join(11)
        atomic(self.spool,{"state":"ready","id":task["id"],"body":body})
        self.flush()

    def run(self):
        with open(self.root/"agent.lock","a") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.enroll()
            delay=5
            while True:
                try:
                    self.step()
                    delay=5
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code==401:
                        print("Agent authorization rejected; rotate and re-enroll",flush=True)
                        return
                    delay=min(60,delay*2)
                except Exception as exc:
                    print("Agent retry: "+type(exc).__name__,flush=True)
                    delay=min(60,delay*2)
                time.sleep(delay)

def main():
    root=Path(os.getenv("NDC_AGENT_DATA","/data"))
    allowed=json.loads((root/"allowed-endpoints.json").read_text())
    if not isinstance(allowed,list) or not 1<=len(allowed)<=100 or any(not isinstance(x,str) for x in allowed):
        raise ValueError("Provide 1–100 explicitly approved resolver endpoints")
    for endpoint in allowed:
        AgentRun(endpoints=[endpoint])
    mode=os.getenv("NDC_AGENT_PROTOCOL","1")
    if mode not in ("1","2"):raise ValueError("Unsupported agent protocol")
    Agent(root,os.environ["NDC_CONTROLLER_URL"],allowed,protocol_v2=mode=="2").run()

if __name__=="__main__":
    main()
