"""Versioned internal evidence contract and transactional derived store.

No network execution or public write API. Source adapters must provide durable
monotonic sequences; advancing a cursor and inserting its batch are atomic.
"""
import hashlib
import json
import math
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

Key = Annotated[str, Field(min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:-]+$")]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Stamp = Annotated[float,Field(ge=0,le=253402300799,allow_inf_nan=False)]
Revision = Annotated[int,Field(ge=1,le=9223372036854775807)]
Source = Literal["benchmark","monitor","agent","inspector","connectivity","tls","route","scenario","atlas","xray","lab"]
Kind = Literal["dns","tcp","http","tls","icmp","route","throughput","snapshot","routing","scenario"]
Outcome = Literal["success","failure","partial","unknown","skipped"]
Unit = Literal["ms","count","ratio","bytes","bit/s","days","boolean"]

class Record(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True,frozen=True)

class Measurement(Record):
    name: Key
    unit: Unit
    value: float|None=Field(allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_value(self):
        v=self.value
        if v is not None:
            if v<0 or (self.unit=="ratio" and v>1) or (self.unit=="boolean" and v not in (0,1)):
                raise ValueError("Measurement outside unit range")
            if self.unit in ("count","bytes") and not v.is_integer():
                raise ValueError("Discrete measurement must be integral")
        return self

class Observation(Record):
    schema_version: Literal[1]=1
    source_kind: Source
    source_id: Key
    source_revision: Revision
    source_part: Key
    run_id: Key|None=None
    correlation_id: Key|None=None
    vantage_id: Key
    observed_at: Stamp|None=None
    target_id: Digest
    profile_revision: Digest
    probe_kind: Kind
    outcome: Outcome
    provenance: Literal["controller","agent_claim","legacy_summary"]
    measurements: tuple[Measurement,...]=Field(max_length=32)
    protocol: Literal["udp","tcp","dot","h2","h3","doq","http/1.1","icmp"]|None=None
    family: Literal["ipv4","ipv6"]|None=None
    error_code: Key|None=None
    limitations: tuple[Key,...]=Field(default=(),max_length=16)

    @model_validator(mode="after")
    def validate_names(self):
        names=[m.name for m in self.measurements]
        if len(names)!=len(set(names)):
            raise ValueError("Duplicate measurement name")
        return self

    @property
    def identity(self):
        return digest([self.source_kind,self.source_id,self.source_revision,self.source_part])

class Event(Record):
    schema_version: Literal[1]=1
    event_type: Key
    source_kind: Source
    source_id: Key
    source_revision: Revision
    deduplication_key: Key
    rule_version: Key
    observed_at: Stamp|None=None
    severity: Literal["info","warning","critical"]
    confidence: Literal["observed","hypothesis","unknown"]
    evidence_ids: tuple[Digest,...]=Field(min_length=1,max_length=32)

    @model_validator(mode="after")
    def validate_links(self):
        if len(self.evidence_ids)!=len(set(self.evidence_ids)):
            raise ValueError("Duplicate evidence link")
        return self

    @property
    def identity(self):
        return digest([self.source_kind,self.source_id,self.source_revision,self.event_type,self.rule_version,self.deduplication_key])

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def payload(record):
    return canonical(record.model_dump(mode="json"))

class Conflict(Exception):
    pass

class Capacity(Exception):
    pass

class EvidenceStore:
    def __init__(self,path,*,max_rows=50000,max_bytes=32*1024*1024,clock=time.time):
        if not 1<=max_rows<=500000 or not 1024<=max_bytes<=256*1024*1024:
            raise ValueError("Invalid evidence limits")
        self.path=Path(path)
        self.max_rows=max_rows
        self.max_bytes=max_bytes
        self.clock=clock

    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=5)
        c.row_factory=sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA synchronous=FULL")
        try:
            with c:
                yield c
        finally:
            c.close()

    def initialize(self):
        with self.db() as c:
            version=c.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0,1):
                raise RuntimeError("Unsupported intelligence schema")
            if version==0:
                c.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE observations(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE, received_at REAL NOT NULL,
                    payload TEXT NOT NULL, size INTEGER NOT NULL);
                CREATE INDEX observations_received ON observations(received_at);
                CREATE TABLE events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE, recorded_at REAL NOT NULL,
                    payload TEXT NOT NULL, size INTEGER NOT NULL);
                CREATE INDEX events_recorded ON events(recorded_at);
                CREATE TABLE event_evidence(
                    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                    observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE RESTRICT,
                    PRIMARY KEY(event_id,observation_id));
                CREATE INDEX evidence_reverse ON event_evidence(observation_id);
                CREATE TABLE cursors(
                    stream TEXT PRIMARY KEY, position INTEGER NOT NULL, batch_digest TEXT NOT NULL);
                CREATE TABLE usage(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    rows INTEGER NOT NULL CHECK(rows>=0), bytes INTEGER NOT NULL CHECK(bytes>=0));
                INSERT INTO usage VALUES(1,0,0);
                CREATE TRIGGER observation_insert AFTER INSERT ON observations BEGIN
                    UPDATE usage SET rows=rows+1,bytes=bytes+NEW.size WHERE singleton=1; END;
                CREATE TRIGGER observation_delete AFTER DELETE ON observations BEGIN
                    UPDATE usage SET rows=rows-1,bytes=bytes-OLD.size WHERE singleton=1; END;
                CREATE TRIGGER event_insert AFTER INSERT ON events BEGIN
                    UPDATE usage SET rows=rows+1,bytes=bytes+NEW.size WHERE singleton=1; END;
                CREATE TRIGGER event_delete AFTER DELETE ON events BEGIN
                    UPDATE usage SET rows=rows-1,bytes=bytes-OLD.size WHERE singleton=1; END;
                PRAGMA user_version=1;
                COMMIT;
                """)
            c.execute("PRAGMA journal_mode=WAL")

    def ingest(self,stream,position,observations=(),events=()):
        # A stream has exactly one durable producer, position starts at 1.
        if not isinstance(stream,str) or not 1<=len(stream)<=128 or any(not (x.isascii() and (x.isalnum() or x in "_.:-")) for x in stream):
            raise ValueError("Invalid stream")
        if type(position) is not int or not 1<=position<=9223372036854775807:
            raise ValueError("Invalid cursor")
        if len(observations)+len(events)>100:
            raise ValueError("Batch exceeds 100 records")
        obs=[(x.identity,payload(x)) for x in observations]
        ev=[(x.identity,payload(x),x.evidence_ids) for x in events]
        if len({x[0] for x in obs})!=len(obs) or len({x[0] for x in ev})!=len(ev):
            raise Conflict("Duplicate identity within batch")
        if sum(len(x[1]) for x in obs+ev)>256*1024:
            raise ValueError("Batch exceeds 256 KiB")
        batch=digest([obs,ev])
        now=self.clock()
        if not math.isfinite(now) or now<0:
            raise ValueError("Invalid receipt time")
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            row=c.execute("SELECT position,batch_digest FROM cursors WHERE stream=?",(stream,)).fetchone()
            prior=row["position"] if row else 0
            if position==prior and row["batch_digest"]==batch:
                return {"replayed":True,"position":prior,"inserted":0}
            if position!=prior+1:
                raise Conflict("Cursor gap, stale replay or changed batch")
            if row is None and c.execute("SELECT count(*) FROM cursors").fetchone()[0]>=256:
                raise Capacity("Stream capacity reached")
            inserted=0
            for table,items,stamp in (("observations",obs,"received_at"),("events",ev,"recorded_at")):
                for item in items:
                    id,data=item[:2]
                    existing=c.execute(f"SELECT payload FROM {table} WHERE id=?",(id,)).fetchone()
                    if existing:
                        if existing[0]!=data:
                            raise Conflict("Immutable evidence identity conflict")
                        continue
                    size=len(data.encode("ascii"))
                    usage=c.execute("SELECT rows,bytes FROM usage WHERE singleton=1").fetchone()
                    if usage[0]+1>self.max_rows or usage[1]+size>self.max_bytes:
                        raise Capacity("Evidence capacity reached; apply explicit retention")
                    c.execute(f"INSERT INTO {table}(id,{stamp},payload,size) VALUES(?,?,?,?)",(id,now,data,size))
                    if table=="events":
                        for evidence in item[2]:
                            if not c.execute("SELECT 1 FROM observations WHERE id=?",(evidence,)).fetchone():
                                raise Conflict("Event references missing observation")
                            c.execute("INSERT INTO event_evidence VALUES(?,?)",(id,evidence))
                    inserted+=1
            c.execute("INSERT INTO cursors VALUES(?,?,?) ON CONFLICT(stream) DO UPDATE SET position=excluded.position,batch_digest=excluded.batch_digest",(stream,position,batch))
            return {"replayed":False,"position":position,"inserted":inserted}

    def page(self,kind,*,after=0,limit=100):
        if kind not in ("observations","events") or type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=200:
            raise ValueError("Invalid evidence page")
        stamp="received_at" if kind=="observations" else "recorded_at"
        with self.db() as c:
            rows=c.execute(f"SELECT seq,id,{stamp},payload FROM {kind} WHERE seq>? ORDER BY seq LIMIT ?",(after,limit+1)).fetchall()
            items=[{"seq":r["seq"],"id":r["id"],stamp:r[stamp],"record":json.loads(r["payload"])} for r in rows[:limit]]
            return {"items":items,"next_cursor":items[-1]["seq"] if len(rows)>limit else None}

    def status(self):
        with self.db() as c:
            return dict(c.execute("SELECT rows,bytes FROM usage WHERE singleton=1").fetchone())|{"max_rows":self.max_rows,"max_bytes":self.max_bytes}

    def prune(self,*,before,limit=1000):
        # Explicit receipt-time retention; keep evidence referenced by surviving events.
        if not math.isfinite(before) or before<0 or type(limit) is not int or not 1<=limit<=1000:
            raise ValueError("Invalid retention request")
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            events=c.execute("DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE recorded_at<? ORDER BY seq LIMIT ?)",(before,limit)).rowcount
            observations=c.execute("""DELETE FROM observations WHERE seq IN (
                SELECT seq FROM observations o WHERE received_at<? AND NOT EXISTS(
                    SELECT 1 FROM event_evidence e WHERE e.observation_id=o.id)
                ORDER BY seq LIMIT ?)""",(before,limit)).rowcount
            return {"events":events,"observations":observations}
