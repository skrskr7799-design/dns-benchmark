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
from .remote_contract import CONFIG,RemoteResult,config_key
from .remote_worker import load_approvals,run_probe,route_capabilities

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
    def __init__(self,root,url,allowed,*,protocol_v2=False,approvals=()):
        self.root=Path(root);self.url=controller_url(url);self.allowed=frozenset(allowed)
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.identity=self.root/"identity.json"
        self.spool=self.root/"spool.json"
        self.client=httpx.Client(timeout=10,trust_env=False,follow_redirects=False,
                                 verify=os.getenv("NDC_AGENT_CA_FILE") or True)
        self.credential=None
        self.protocol_v2=protocol_v2
        self.approvals=tuple(approvals)
        self.peer=None
        self.goodput=None
        self.peer_turn=0

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
        if value.get("version")=="2":
            if value["state"]=="executing":
                value={"state":"ready","version":"2","id":value["id"],
                    "body":value["result_base"]|{"status":"failed","execution_error":"interrupted"}}
                atomic(self.spool,value)
            path="v2/results/"+value["id"]
        else:
            if value["state"]=="executing":
                # Crash during measurement: never rerun the lease.
                value={"state":"ready","id":value["id"],"body":{"lease":value["lease"],"status":"failed","results":[],"error":"Agent restarted during measurement"}}
                atomic(self.spool,value)
            path="results/"+value["id"]
        r=self.post(path,value["body"])
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
        # Rotate peer protocol priority so continuously queued goodput cannot
        # always precede RTT. Controller reservations still serialize DNS.
        runtimes=[r for r in (self.goodput,self.peer) if r is not None]
        if len(runtimes)==2 and self.peer_turn%2:runtimes.reverse()
        self.peer_turn+=1
        for runtime in runtimes:
            if runtime.step():return
        if self.protocol_v2:
            supported={a.config.kind for a in self.approvals if a.config.kind!="route"}
            if any(a.config.kind=="route" for a in self.approvals):
                routes=route_capabilities()
                if any(a.config.kind=="route" and routes[a.config.family] for a in self.approvals):
                    supported.add("route")
            capabilities=["dns"]+sorted(supported)
            r=self.post("v2/poll",{"version":PROTOCOL_V2,"engine":ENGINE_V2,"capabilities":capabilities})
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
        if task.get("version")=="2":
            if not self.protocol_v2:raise ValueError("Unexpected v2 lease")
            self.remote_step(task)
            return
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

    def remote_step(self,task):
        if task.get("engine")!=ENGINE_V2 or task.get("kind") not in ("tcp","tls","http","route") or task.get("lease_seconds")!=300:
            raise ValueError("Unsupported remote lease")
        cfg=CONFIG.validate_python(task["config"])
        if cfg.kind!=task["kind"]:raise ValueError("Remote kind mismatch")
        if config_key(cfg)!=task.get("config_key"):raise ValueError("Remote configuration mismatch")
        result_base={"version":"2","engine":ENGINE_V2,"kind":cfg.kind,"lease":task["lease"],"config_key":task["config_key"]}
        RemoteResult.model_validate(result_base|{"status":"failed","execution_error":"interrupted"})
        atomic(self.spool,{"state":"executing","version":"2","id":task["id"],"result_base":result_base})
        cancel=threading.Event();done=threading.Event()
        def active():
            try:
                response=self.post("v2/heartbeat",{"version":"2","engine":ENGINE_V2,"task_id":task["id"],"lease":task["lease"]})
                return response.status_code==200 and response.json().get("active") is True
            except Exception:
                return False
        def heartbeat():
            while not done.wait(2):
                if not active():
                    cancel.set()
                    return
        worker=None
        try:
            if not active():
                observation,error=None,"cancelled"
            else:
                worker=threading.Thread(target=heartbeat,daemon=True);worker.start()
                observation,error=run_probe(cfg,self.approvals,cancel)
        except Exception:
            observation,error=None,"internal_error"
        finally:
            done.set()
            if worker is not None:worker.join(11)
        if cancel.is_set():observation,error=None,"cancelled"
        body=result_base|({"status":"completed","observation":observation.model_dump(mode="json")} if observation is not None else {"status":"failed","execution_error":error or "internal_error"})
        body=RemoteResult.model_validate(body).model_dump(mode="json")
        atomic(self.spool,{"state":"ready","version":"2","id":task["id"],"body":body})
        self.flush()

    def run(self):
        with open(self.root/"agent.lock","a") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.enroll()
            print('Agent identity ready; protocol '+('2' if self.protocol_v2 else '1')+'; waiting for controller heartbeat',flush=True)
            peer_file=self.root/"peer-directions.json"
            if peer_file.exists() or peer_file.is_symlink():
                if not self.protocol_v2:raise ValueError("Peer runtime requires protocol 2")
                from .peer_runtime import PeerRuntime
                identity=json.loads(self.identity.read_text())
                def peer_post(path,body):
                    return self.client.post(self.url+"/api/v1/agents/machine/peer/"+path,json=body,
                        headers={"Authorization":"Bearer "+self.credential},timeout=2)
                self.peer=PeerRuntime(self.root,identity["id"],peer_post,atomic)
            goodput_file=self.root/"peer-throughput.json"
            if goodput_file.exists() or goodput_file.is_symlink():
                if not self.protocol_v2:raise ValueError("Goodput runtime requires protocol 2")
                from .peer_throughput_runtime import GoodputAgentRuntime
                identity=json.loads(self.identity.read_text())
                def goodput_post(path,body):
                    return self.client.post(self.url+"/api/v1/agents/machine/goodput/"+path,json=body,
                        headers={"Authorization":"Bearer "+self.credential},timeout=2)
                self.goodput=GoodputAgentRuntime(self.root,identity["id"],goodput_post,atomic)
            delay=5
            while True:
                try:
                    self.step()
                    delay=4 if self.peer is not None or self.goodput is not None else 5
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
    approvals=load_approvals(root/"allowed-probes.json") if mode=="2" else ()
    Agent(root,os.environ["NDC_CONTROLLER_URL"],allowed,protocol_v2=mode=="2",approvals=approvals).run()

if __name__=="__main__":
    main()
