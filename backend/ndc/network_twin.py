"""Versioned owner topology. Dependencies express hypotheses, never discovered paths."""
import json
import sqlite3
import time
from contextlib import contextmanager
from collections import deque
from pathlib import Path
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator
from .evidence import canonical,digest,Conflict,Capacity
from .time_machine import capture_monitor_inventory

MAX_REVISIONS=128
MAX_NODES=100
MAX_EDGES=300
MAX_BYTES=8*1024*1024

class Strict(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)

class Node(Strict):
    id:str=Field(pattern=r"^[a-f0-9]{32}$")
    name:str=Field(min_length=1,max_length=80)
    kind:Literal["device","service","site","resolver","gateway","agent"]
    monitor_id:str|None=Field(default=None,pattern=r"^[a-f0-9]{32}$")
    @model_validator(mode="after")
    def label(self):
        self.name=self.name.strip()
        if not self.name or any(ord(c)<32 for c in self.name):raise ValueError("Invalid node label")
        return self

class Edge(Strict):
    source:str=Field(pattern=r"^[a-f0-9]{32}$")
    target:str=Field(pattern=r"^[a-f0-9]{32}$")
    kind:Literal["requires","uses","located_at"]

class Graph(Strict):
    nodes:list[Node]=Field(max_length=MAX_NODES)
    edges:list[Edge]=Field(max_length=MAX_EDGES)
    @model_validator(mode="after")
    def topology(self):
        ids={n.id for n in self.nodes}
        if len(ids)!=len(self.nodes):raise ValueError("Duplicate node")
        keys={(e.source,e.target,e.kind) for e in self.edges}
        if len(keys)!=len(self.edges):raise ValueError("Duplicate dependency")
        if any(e.source not in ids or e.target not in ids or e.source==e.target for e in self.edges):
            raise ValueError("Invalid dependency endpoint")
        self.nodes.sort(key=lambda n:n.id);self.edges.sort(key=lambda e:(e.source,e.target,e.kind))
        return self

class Save(Strict):
    request_id:str=Field(pattern=r"^[a-f0-9]{32}$")
    expected_revision:int=Field(ge=0,le=MAX_REVISIONS)
    graph:Graph

class TwinStore:
    def __init__(self,path,clock=time.time):
        self.path=Path(path);self.clock=clock
    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=5);c.row_factory=sqlite3.Row
        c.execute("PRAGMA synchronous=FULL")
        try:
            with c:yield c
        finally:c.close()
    def initialize(self):
        with self.db() as c:
            version=c.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0,1):raise RuntimeError("Unsupported Twin schema")
            if version==0:
                c.executescript("""BEGIN IMMEDIATE;
                    CREATE TABLE revisions(revision INTEGER PRIMARY KEY,request_id TEXT UNIQUE NOT NULL,
                        parent INTEGER NOT NULL,created REAL NOT NULL,graph TEXT NOT NULL,hash TEXT NOT NULL,size INTEGER NOT NULL);
                    CREATE TRIGGER revisions_immutable BEFORE UPDATE ON revisions
                        BEGIN SELECT RAISE(ABORT,'Immutable revision'); END;
                    CREATE TRIGGER revisions_no_delete BEFORE DELETE ON revisions
                        BEGIN SELECT RAISE(ABORT,'Immutable revision'); END;
                    PRAGMA user_version=1;COMMIT;""")
            c.execute("PRAGMA journal_mode=WAL")
    def item(self,r):
        if r is None:return {"revision":0,"parent":None,"created":None,"graph":{"nodes":[],"edges":[]},"hash":None}
        data=json.loads(r["graph"])
        if digest(data)!=r["hash"]:raise Conflict("Twin revision checksum mismatch")
        return {k:r[k] for k in ("revision","parent","created","hash")}|{"graph":data}
    def get(self,revision=None):
        with self.db() as c:
            if revision==0:return self.item(None)
            r=c.execute("SELECT * FROM revisions ORDER BY revision DESC LIMIT 1").fetchone() if revision is None else c.execute("SELECT * FROM revisions WHERE revision=?",(revision,)).fetchone()
            return None if r is None and revision is not None else self.item(r)
    def history(self):
        with self.db() as c:
            return [dict(r) for r in c.execute("SELECT revision,parent,created,hash FROM revisions ORDER BY revision DESC LIMIT 128")]
    def save(self,body,monitor_ids):
        data=body.graph.model_dump(mode="json");raw=canonical(data);size=len(raw.encode("ascii"))
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT * FROM revisions WHERE request_id=?",(body.request_id,)).fetchone()
            if r:
                if r["graph"]!=raw or r["parent"]!=body.expected_revision:raise Conflict("Twin request ID conflict")
                return self.item(r)
            current=c.execute("SELECT coalesce(max(revision),0),coalesce(sum(size),0) FROM revisions").fetchone()
            if current[0]!=body.expected_revision:raise Conflict("Twin revision changed; reload before saving")
            if current[0]>=MAX_REVISIONS or current[1]+size>MAX_BYTES:raise Capacity("Twin revision capacity reached")
            # A deleted existing binding may be removed or preserved, but a
            # new binding cannot point at an unknown monitor.
            previous=self.item(c.execute("SELECT * FROM revisions ORDER BY revision DESC LIMIT 1").fetchone())
            old={(n["id"],n["monitor_id"]) for n in previous["graph"]["nodes"]}
            if any(n.monitor_id is not None and n.monitor_id not in monitor_ids and (n.id,n.monitor_id) not in old for n in body.graph.nodes):
                raise ValueError("Unknown monitor binding")
            rev=current[0]+1
            c.execute("INSERT INTO revisions VALUES(?,?,?,?,?,?,?)",(rev,body.request_id,current[0],self.clock(),raw,digest(data),size))
            return self.item(c.execute("SELECT * FROM revisions WHERE revision=?",(rev,)).fetchone())

def monitor_observations(monitors,evidence):
    inventory=capture_monitor_inventory(monitors)
    result={}
    with evidence.db() as c:
        c.execute("BEGIN")
        for m in inventory["monitors"]:
            o=m["observation"];eid=None
            if o:
                matches=c.execute("""SELECT id,payload FROM observations WHERE source_kind='monitor'
                    AND json_extract(payload,'$.source_id')=? AND json_extract(payload,'$.observed_at')=?
                    AND json_extract(payload,'$.profile_revision')=? AND json_extract(payload,'$.target_id')=? LIMIT 2""",
                    (m["monitor_id"],o["observed_at"],o["profile_revision"],o["target_id"])).fetchall()
                if len(matches)==1:
                    r=json.loads(matches[0]["payload"]);values={v["name"]:v["value"] for v in r["measurements"]}
                    if (r["outcome"],r["protocol"],r["family"],values.get("latency"),values.get("http_status"),values.get("certificate_days_remaining"))==(o["outcome"],o["protocol"],o["family"],o["latency_ms"],o["http_status"],o["certificate_days_remaining"]):
                        eid=matches[0]["id"]
            result[m["monitor_id"]]={"status":m["observation_status"],"observed_at":m["last_check_at"],
                "outcome":o["outcome"] if o else None,"evidence_id":eid}
    return inventory["captured_at"],result

def analyze(graph,observations):
    ids={n["id"] for n in graph["nodes"]}
    dependencies={id:set() for id in ids}
    for e in graph["edges"]:
        if e["kind"]=="requires":dependencies[e["source"]].add(e["target"])
    facts={}
    for n in graph["nodes"]:
        mid=n["monitor_id"];o=observations.get(mid) if mid is not None else None
        direct={"success":"healthy","failure":"failed","partial":"degraded"}.get(o["outcome"],"unknown") if o and o["status"]=="fresh" else "unknown"
        facts[n["id"]]={"direct":direct,"binding_status":o["status"] if o else "missing" if mid else "unbound",
            "observed_at":o["observed_at"] if o else None,"evidence_id":o["evidence_id"] if o else None}
    reach={}
    for id in ids:
        seen=set();q=deque(dependencies[id])
        while q:
            target=q.popleft()
            if target in seen:continue
            seen.add(target);q.extend(dependencies[target]-seen)
        reach[id]=seen
    rows=[]
    for n in graph["nodes"]:
        id=n["id"];deps=reach[id]-{id}
        failed=sorted(x for x in deps if facts[x]["direct"]=="failed")
        degraded=sorted(x for x in deps if facts[x]["direct"]=="degraded")
        unknown=sorted(x for x in deps if facts[x]["direct"]=="unknown")
        # An observed healthy service is not relabelled failed by a hypothesis.
        impact="potential_failure" if failed else "potential_degradation" if degraded else "unknown" if unknown or id in reach[id] else "none_observed"
        rows.append({"id":id,**facts[id],"dependency_impact":impact,"failed_dependencies":failed,
            "degraded_dependencies":degraded,"unknown_dependencies":unknown,"cycle":id in reach[id],
            "potentially_affected":sorted(x for x in ids-{id} if id in reach[x])})
    return rows

def report(store,monitors,evidence,revision=None):
    model=store.get(revision)
    if model is None:return None
    at,observations=monitor_observations(monitors,evidence)
    return {"model":model,"observed_at":at,"nodes":analyze(model["graph"],observations),
        "limitations":["owner_defined_graph_not_discovery","required_dependencies_only","impact_hypothesis_not_root_cause",
            "historical_graph_with_current_observations","source_and_derived_reads_not_atomic","evidence_may_expire"]}
