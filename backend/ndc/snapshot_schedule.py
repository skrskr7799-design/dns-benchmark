"""Bounded fixed-delay snapshot schedules, run in existing monitor scheduler lane."""
import json
import uuid
from typing import Literal
from pydantic import BaseModel,Field,ConfigDict,TypeAdapter
from .evidence import canonical,Capacity,Conflict
from .snapshot_probes import Capture,config_key
from .time_machine import SnapshotStore

MAX_SCHEDULES=8
MIN_INTERVAL=3600
MAX_INTERVAL=7*86400
ADMISSION_GAP=60

class ScheduleConfig(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    label:str=Field(min_length=1,max_length=80)
    interval_seconds:int=Field(ge=MIN_INTERVAL,le=MAX_INTERVAL)
    probe:Capture|None=None

class ScheduleEnable(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    enabled:bool

def install(c):
    c.execute("""CREATE TABLE snapshot_schedules(
        id TEXT PRIMARY KEY,config TEXT NOT NULL,enabled INTEGER NOT NULL,
        created_at REAL NOT NULL,next_at REAL NOT NULL,
        pending_id TEXT UNIQUE,pending_at REAL,last_at REAL,last_status TEXT,
        last_snapshot_id TEXT,last_error TEXT,
        runs INTEGER NOT NULL DEFAULT 0,errors INTEGER NOT NULL DEFAULT 0)""")
    c.execute("""CREATE TABLE snapshot_schedule_gate(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),last_claim_at REAL)""")
    c.execute("INSERT INTO snapshot_schedule_gate VALUES(1,NULL)")

def decode(row):
    if row is None:return None
    r=dict(row);r["config"]=json.loads(r["config"]);r["enabled"]=bool(r["enabled"])
    r["running"]=r["pending_id"] is not None
    return r

class Schedules:
    def __init__(self,evidence,monitors,snapshots=None):
        self.evidence=evidence;self.monitors=monitors
        self.snapshots=snapshots if snapshots is not None else SnapshotStore(evidence)
        self.clock=evidence.clock

    def list(self):
        with self.evidence.db() as c:
            return [decode(r) for r in c.execute("SELECT * FROM snapshot_schedules ORDER BY created_at,id")]

    def create(self,config):
        if not config.label.strip():raise ValueError("Empty label")
        now=self.clock();id=uuid.uuid4().hex
        with self.evidence.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT count(*) FROM snapshot_schedules").fetchone()[0]>=MAX_SCHEDULES:
                raise Capacity("Maximum eight schedules")
            # Explicit creation enables schedule; first execution after interval.
            c.execute("INSERT INTO snapshot_schedules(id,config,enabled,created_at,next_at) VALUES(?,?,1,?,?)",
                (id,canonical(config.model_dump(mode="json")),now,now+config.interval_seconds))
            return decode(c.execute("SELECT * FROM snapshot_schedules WHERE id=?",(id,)).fetchone())

    def enable(self,id,enabled):
        with self.evidence.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=decode(c.execute("SELECT * FROM snapshot_schedules WHERE id=?",(id,)).fetchone())
            if r is None:return None
            if r["running"]:raise Conflict("Snapshot in progress")
            if r["enabled"]!=enabled:
                c.execute("UPDATE snapshot_schedules SET enabled=?,next_at=? WHERE id=?",
                    (int(enabled),self.clock()+r["config"]["interval_seconds"],id))
            return decode(c.execute("SELECT * FROM snapshot_schedules WHERE id=?",(id,)).fetchone())

    def delete(self,id):
        with self.evidence.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT pending_id FROM snapshot_schedules WHERE id=?",(id,)).fetchone()
            if r is None:return False
            if r[0] is not None:raise Conflict("Snapshot in progress")
            c.execute("DELETE FROM snapshot_schedules WHERE id=?",(id,))
            return True

    def claim(self):
        now=self.clock()
        with self.evidence.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT 1 FROM snapshot_schedules WHERE pending_id IS NOT NULL").fetchone():return None
            last=c.execute("SELECT last_claim_at FROM snapshot_schedule_gate WHERE singleton=1").fetchone()[0]
            # Clock rollback cannot lock admission forever.
            if last is not None and 0<=now-last<ADMISSION_GAP:return None
            row=c.execute("SELECT * FROM snapshot_schedules WHERE enabled=1 AND next_at<=? ORDER BY next_at,id LIMIT 1",(now,)).fetchone()
            if row is None:return None
            token=str(uuid.uuid4())
            c.execute("UPDATE snapshot_schedules SET pending_id=?,pending_at=? WHERE id=?",(token,now,row["id"]))
            c.execute("UPDATE snapshot_schedule_gate SET last_claim_at=? WHERE singleton=1",(now,))
            return decode(c.execute("SELECT * FROM snapshot_schedules WHERE id=?",(row["id"],)).fetchone())

    def finish(self,row,status,error=None,snapshot_id=None):
        now=self.clock()
        with self.evidence.db() as c:
            c.execute("BEGIN IMMEDIATE")
            # Match claim token; a second completion cannot advance counters.
            count=c.execute("""UPDATE snapshot_schedules SET pending_id=NULL,pending_at=NULL,last_at=?,
                next_at=?,last_status=?,last_error=?,last_snapshot_id=coalesce(?,last_snapshot_id),
                enabled=CASE WHEN ?='capacity' THEN 0 ELSE enabled END,
                runs=runs+1,errors=errors+? WHERE id=? AND pending_id=?""",
                (now,now+row["config"]["interval_seconds"],status,error,snapshot_id,status,int(status!="captured"),row["id"],row["pending_id"])).rowcount
            return count==1

    def recover(self):
        # Only before scheduler start (single process ownership lock).
        # A committed snapshot survives the commit/ack gap. Never re-run an
        # interrupted network probe; record interrupted and wait a full interval.
        for row in self.list():
            if not row["running"]:continue
            prior=self.snapshots.get(row["pending_id"])
            cfg=ScheduleConfig.model_validate(row["config"])
            expected=(prior is not None and prior["label"]==cfg.label and
                (prior["snapshot"]["scope"]=="configured_monitors" if cfg.probe is None else
                 prior["snapshot"].get("config_key")==config_key(cfg.probe)))
            self.finish(row,"captured" if expected else "interrupted",
                None if expected else "restart_before_commit",prior["id"] if expected else None)

    def tick(self):
        """Caller holds the existing inspection slot; at most one capture."""
        row=self.claim()
        if row is None:return False
        try:
            cfg=ScheduleConfig.model_validate(row["config"])
            if cfg.probe is None:
                result=self.snapshots.create(row["pending_id"],cfg.label,self.monitors)
            else:
                result=self.snapshots.create_probe(row["pending_id"],cfg.label,cfg.probe)
        except Capacity:
            self.finish(row,"capacity","snapshot_capacity")
        except Exception as exc:
            self.finish(row,"error",type(exc).__name__)
        else:
            self.finish(row,"captured",snapshot_id=result["id"])
        return True
