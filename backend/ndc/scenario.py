"""Bounded manual and automatic read-only scenario DAG. No shell or outbound actions."""
import json
import sqlite3
import time
import math
import uuid
from pathlib import Path
from contextlib import contextmanager
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator
from .evidence import canonical,digest,Conflict,Capacity
from .network_twin import monitor_observations,analyze

MAX_REVISIONS=128
MAX_RUNS=512
MAX_BYTES=8*1024*1024
MAX_STEPS=16
class Strict(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)

class Step(Strict):
    id:str=Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    action:Literal["monitor_state","twin_state","summarize"]
    target:str|None=Field(default=None,pattern=r"^[a-f0-9]{32}$")
    depends_on:list[str]=Field(default_factory=list,max_length=MAX_STEPS)
    condition:Literal["always","all_healthy","any_failed","any_unknown"]="always"
    @model_validator(mode="after")
    def shape(self):
        if (self.action=="summarize")!=(self.target is None):raise ValueError("Action target mismatch")
        if self.condition!="always" and not self.depends_on:raise ValueError("Condition requires predecessors")
        if len(set(self.depends_on))!=len(self.depends_on):raise ValueError("Duplicate predecessor")
        self.depends_on.sort()
        return self

class Definition(Strict):
    name:str=Field(min_length=1,max_length=80)
    twin_revision:int=Field(ge=0,le=128)
    steps:list[Step]=Field(min_length=1,max_length=MAX_STEPS)
    @model_validator(mode="after")
    def graph(self):
        ids={s.id for s in self.steps}
        if len(ids)!=len(self.steps):raise ValueError("Duplicate step")
        if any(set(s.depends_on)-ids or s.id in s.depends_on for s in self.steps):raise ValueError("Invalid predecessor")
        ordered=[];done=set()
        while len(done)<len(ids):
            ready=sorted((s for s in self.steps if s.id not in done and set(s.depends_on)<=done),key=lambda s:s.id)
            if not ready:raise ValueError("Scenario dependency cycle")
            for s in ready:ordered.append(s);done.add(s.id)
        self.steps=ordered
        return self

class Save(Strict):
    request_id:str=Field(pattern=r"^[a-f0-9]{32}$")
    expected_revision:int=Field(ge=0,le=MAX_REVISIONS)
    definition:Definition

class Run(Strict):
    request_id:str=Field(pattern=r"^[a-f0-9]{32}$")
    revision:int=Field(ge=1,le=MAX_REVISIONS)
    dry_run:bool=True

class Schedule(Strict):
    expected_generation:int=Field(ge=0,le=2147483646)
    revision:int=Field(ge=1,le=MAX_REVISIONS)
    enabled:bool
    mode:Literal["interval","incident"]="interval"
    interval_seconds:int=Field(default=3600,ge=900,le=86400)
    monitor_id:str|None=Field(default=None,pattern=r"^[a-f0-9]{32}$")
    @model_validator(mode="after")
    def binding(self):
        if (self.mode=="incident")!=(self.monitor_id is not None):raise ValueError("Incident monitor required")
        return self

class ScenarioStore:
    def __init__(self,path,clock=time.time):self.path=Path(path);self.clock=clock
    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=5);c.row_factory=sqlite3.Row
        c.execute("PRAGMA synchronous=FULL")
        try:
            with c:yield c
        finally:c.close()
    def initialize(self):
        with self.db() as c:
            v=c.execute("PRAGMA user_version").fetchone()[0]
            if v not in (0,1,2):raise RuntimeError("Unsupported scenario schema")
            if v==0:c.executescript("""BEGIN IMMEDIATE;
                CREATE TABLE definitions(revision INTEGER PRIMARY KEY,request_id TEXT UNIQUE NOT NULL,parent INTEGER NOT NULL,
                    created REAL NOT NULL,payload TEXT NOT NULL,hash TEXT NOT NULL);
                CREATE TABLE runs(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,dry_run INTEGER NOT NULL,
                    created REAL NOT NULL,payload TEXT NOT NULL,hash TEXT NOT NULL);
                CREATE TRIGGER definition_immutable BEFORE UPDATE ON definitions BEGIN SELECT RAISE(ABORT,'Immutable definition'); END;
                CREATE TRIGGER run_immutable BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'Immutable run'); END;
                PRAGMA user_version=1;COMMIT;""")
            if v<2:c.executescript("""BEGIN IMMEDIATE;
                CREATE TABLE schedule(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    generation INTEGER NOT NULL,revision INTEGER,enabled INTEGER NOT NULL,
                    mode TEXT NOT NULL,interval_seconds INTEGER NOT NULL,monitor_id TEXT,
                    next_at REAL,last_clock REAL NOT NULL,last_observed_at REAL,last_state TEXT,
                    last_run_id TEXT,last_run_at REAL,last_error TEXT);
                INSERT INTO schedule VALUES(1,0,NULL,0,'interval',3600,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL);
                PRAGMA user_version=2;COMMIT;""")
            c.execute("PRAGMA journal_mode=WAL")
    def item(self,r,key):
        if r is None:return None
        data=json.loads(r["payload"])
        if digest(data)!=r["hash"]:raise Conflict("Scenario checksum mismatch")
        return {k:r[k] for k in r.keys() if k!="payload"}|{key:data}
    def latest(self):
        with self.db() as c:return self.item(c.execute("SELECT * FROM definitions ORDER BY revision DESC LIMIT 1").fetchone(),"definition")
    def definition(self,rev):
        with self.db() as c:return self.item(c.execute("SELECT * FROM definitions WHERE revision=?",(rev,)).fetchone(),"definition")
    def save(self,body,twin,monitor_ids):
        d=body.definition.model_dump(mode="json");raw=canonical(d)
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            old=c.execute("SELECT * FROM definitions WHERE request_id=?",(body.request_id,)).fetchone()
            if old:
                if old["parent"]!=body.expected_revision or old["payload"]!=raw:raise Conflict("Scenario request conflict")
                return self.item(old,"definition")
            current=c.execute("SELECT coalesce(max(revision),0) FROM definitions").fetchone()[0]
            if current!=body.expected_revision:raise Conflict("Scenario revision changed")
            if current>=MAX_REVISIONS:raise Capacity("Scenario revision limit")
            model=twin.get(body.definition.twin_revision)
            if model is None:raise ValueError("Unknown Twin revision")
            ids={n["id"] for n in model["graph"]["nodes"]}
            for step in body.definition.steps:
                if step.action=="monitor_state" and step.target not in monitor_ids:raise ValueError("Unknown monitor")
                if step.action=="twin_state" and step.target not in ids:raise ValueError("Unknown Twin node")
            c.execute("INSERT INTO definitions VALUES(?,?,?,?,?,?)",(current+1,body.request_id,current,self.clock(),raw,digest(d)))
            return self.item(c.execute("SELECT * FROM definitions WHERE revision=?",(current+1,)).fetchone(),"definition")
    def runs(self):
        with self.db() as c:return [dict(r) for r in c.execute("SELECT id,revision,dry_run,created,hash FROM runs ORDER BY created DESC,id DESC LIMIT 100")]
    def get_run(self,id):
        with self.db() as c:return self.item(c.execute("SELECT * FROM runs WHERE id=?",(id,)).fetchone(),"result")
    def run(self,body,twin,monitors,evidence):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            return self._run(c,body,twin,monitors,evidence)

    def _run(self,c,body,twin,monitors,evidence,*,captured=None,trigger="manual"):
        old=c.execute("SELECT * FROM runs WHERE id=?",(body.request_id,)).fetchone()
        if old:
            if old["revision"]!=body.revision or bool(old["dry_run"])!=body.dry_run:raise Conflict("Run request conflict")
            return self.item(old,"result")
        n,size=c.execute("SELECT count(*),coalesce(sum(length(payload)),0) FROM runs").fetchone()
        if n>=MAX_RUNS:raise Capacity("Scenario run limit")
        row=self.item(c.execute("SELECT * FROM definitions WHERE revision=?",(body.revision,)).fetchone(),"definition")
        if row is None:raise ValueError("Unknown scenario revision")
        definition=Definition.model_validate(row["definition"])
        model=twin.get(definition.twin_revision)
        if model is None:raise Conflict("Pinned topology unavailable")
        if body.dry_run:
            result={"status":"dry_run","observed_at":None,"steps":[{"id":s.id,"action":s.action,"status":"planned","state":None,"evidence_id":None} for s in definition.steps]}
        else:
            at,observations=captured if captured is not None else monitor_observations(monitors,evidence)
            facts={n["id"]:n for n in analyze(model["graph"],observations)}
            result={"status":"completed","observed_at":at,"steps":evaluate(definition,observations,facts)}
        result["twin_revision"]=definition.twin_revision
        result["trigger"]=trigger
        result["limitations"]=["read_only","no_new_network_probe","conditions_use_observed_state","unknown_is_not_healthy","no_notification_or_config_change"]
        raw=canonical(result)
        if size+len(raw)>MAX_BYTES:raise Capacity("Scenario byte limit")
        c.execute("INSERT INTO runs VALUES(?,?,?,?,?,?)",(body.request_id,body.revision,int(body.dry_run),self.clock(),raw,digest(result)))
        return self.item(c.execute("SELECT * FROM runs WHERE id=?",(body.request_id,)).fetchone(),"result")

    def schedule(self):
        with self.db() as c:
            return self._schedule(c)

    def _schedule(self,c):
        r=dict(c.execute("SELECT * FROM schedule WHERE singleton=1").fetchone())
        r.pop("singleton")
        r["enabled"]=bool(r["enabled"])
        return r

    def configure_schedule(self,body,monitor_ids):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            old=self._schedule(c)
            if body.expected_generation!=old["generation"]:raise Conflict("Schedule changed; reload")
            if c.execute("SELECT 1 FROM definitions WHERE revision=?",(body.revision,)).fetchone() is None:
                raise ValueError("Unknown scenario revision")
            if body.enabled and body.monitor_id is not None and body.monitor_id not in monitor_ids:
                raise ValueError("Unknown incident monitor")
            now=self.clock()
            if not math.isfinite(now) or not 0<=now<=253402300799 or now<old["last_clock"]:
                raise Conflict("Schedule clock invalid or rolled back")
            next_at=(now+body.interval_seconds if body.mode=="interval" else now) if body.enabled else None
            c.execute("""UPDATE schedule SET generation=generation+1,revision=?,enabled=?,mode=?,interval_seconds=?,
                monitor_id=?,next_at=?,last_clock=?,last_observed_at=NULL,last_state=NULL,last_run_id=NULL,last_run_at=NULL,last_error=NULL WHERE singleton=1""",
                (body.revision,int(body.enabled),body.mode,body.interval_seconds,body.monitor_id,next_at,now))
            return self._schedule(c)

    def tick(self,twin,monitors,evidence):
        # A read-only due check avoids taking a writer lock every scheduler tick.
        with self.db() as c:
            initial=self._schedule(c)
        now=self.clock()
        if not initial["enabled"] or not math.isfinite(now) or now<initial["last_clock"] or now<initial["next_at"]:return False
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            s=self._schedule(c);now=self.clock()
            if not s["enabled"] or not math.isfinite(now) or now< s["last_clock"] or now<s["next_at"]:return False
            captured=None;due=s["mode"]=="interval"
            next_at=now+(s["interval_seconds"] if due else 60)
            c.execute("UPDATE schedule SET next_at=?,last_clock=? WHERE singleton=1",(next_at,now))
            try:
                if not due:
                    captured=monitor_observations(monitors,evidence)
                    o=captured[1].get(s["monitor_id"])
                    if not o or o["status"]!="fresh" or o["outcome"] not in ("success","partial","failure"):
                        # Unknown/stale/maintenance is not a recovery. Require
                        # a new healthy/degraded baseline before firing again.
                        c.execute("UPDATE schedule SET last_state=NULL WHERE singleton=1")
                        return False
                    at=o["observed_at"];state=o["outcome"]
                    if at is None or not math.isfinite(at) or not 0<=at<=now:return False
                    if s["last_observed_at"] is not None and at<=s["last_observed_at"]:return False
                    due=(s["last_state"] in ("success","partial") and state=="failure"
                         and (s["last_run_at"] is None or now-s["last_run_at"]>=s["interval_seconds"]))
                    c.execute("UPDATE schedule SET last_observed_at=?,last_state=? WHERE singleton=1",(at,state))
                    if not due:return False
                body=Run(request_id=uuid.uuid4().hex,revision=s["revision"],dry_run=False)
                c.execute("SAVEPOINT scheduled_execution")
                try:
                    self._run(c,body,twin,monitors,evidence,captured=captured,trigger=s["mode"])
                except Exception:
                    c.execute("ROLLBACK TO scheduled_execution");c.execute("RELEASE scheduled_execution");raise
                c.execute("RELEASE scheduled_execution")
            except (Capacity,Conflict,ValueError) as exc:
                c.execute("UPDATE schedule SET enabled=0,next_at=NULL,generation=generation+1,last_error=? WHERE singleton=1",(type(exc).__name__,))
                return False
            c.execute("UPDATE schedule SET last_run_id=?,last_run_at=?,last_error=NULL WHERE singleton=1",(body.request_id,now))
            return True

    def delete_run(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            return bool(c.execute("DELETE FROM runs WHERE id=?",(id,)).rowcount)

def evaluate(definition,observations,facts):
    results={}
    for step in definition.steps:
        previous=[results[k]["state"] for k in step.depends_on]
        cond=step.condition
        eligible=(cond=="always" or cond=="all_healthy" and all(s=="healthy" for s in previous)
            or cond=="any_failed" and "failed" in previous
            or cond=="any_unknown" and any(s in (None,"unknown") for s in previous))
        row={"id":step.id,"action":step.action,"status":"skipped","state":None,"evidence_id":None}
        if eligible:
            row["status"]="observed"
            if step.action=="monitor_state":
                o=observations.get(step.target)
                row["state"]={"success":"healthy","failure":"failed","partial":"degraded"}.get(o["outcome"],"unknown") if o and o["status"]=="fresh" else "unknown"
                row["evidence_id"]=o["evidence_id"] if o and o["status"]=="fresh" else None
            elif step.action=="twin_state":
                f=facts.get(step.target,{})
                row["state"]=f.get("direct","unknown");row["evidence_id"]=f.get("evidence_id")
                row["dependency_impact"]=f.get("dependency_impact","unknown")
            else:
                row["state"]="failed" if "failed" in previous else "unknown" if not previous or any(x in (None,"unknown") for x in previous) else "degraded" if "degraded" in previous else "healthy"
        results[step.id]=row
    return list(results.values())
