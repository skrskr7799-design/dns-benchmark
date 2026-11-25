"""Single-owner persistent monitoring with transactional incident/outbox updates."""
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
import http.client
import ssl
from .models import MonitorConfig, Inspect
from .monitor_evidence import project,encode
from .probes.connectivity import probe_once
from .probes.inspector import inspect_one

log=logging.getLogger(__name__)

class MonitorBusy(Exception):
    pass

class MonitorStore:
    def __init__(self,path,clock=time.time):
        self.path=Path(path)
        self.clock=clock
        self.max_evidence_pending=10000

    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=10)
        c.row_factory=sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            with c:
                yield c
        finally:
            c.close()

    def initialize(self):
        with self.db() as c:
            version=c.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0,1):
                raise RuntimeError("Unsupported monitoring schema")
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript("""
            CREATE TABLE IF NOT EXISTS monitors(
                id TEXT PRIMARY KEY, config TEXT NOT NULL, enabled INTEGER NOT NULL,
                next_at REAL NOT NULL, running INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'unknown', bad INTEGER NOT NULL DEFAULT 0,
                good INTEGER NOT NULL DEFAULT 0, last_at REAL, last_result TEXT);
            CREATE TABLE IF NOT EXISTS observations(
                id INTEGER PRIMARY KEY, monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
                at REAL NOT NULL, outcome TEXT NOT NULL, latency REAL, payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS obs_monitor_at ON observations(monitor_id,at);
            CREATE TABLE IF NOT EXISTS incidents(
                id INTEGER PRIMARY KEY, monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
                opened REAL NOT NULL, closed REAL, reason TEXT NOT NULL, resolution TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS open_incident ON incidents(monitor_id) WHERE closed IS NULL;
            CREATE TABLE IF NOT EXISTS outbox(
                id INTEGER PRIMARY KEY, monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
                created REAL NOT NULL, message TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, next_at REAL NOT NULL);
            """)
            if version==0:
                c.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE monitor_evidence_outbox(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT NOT NULL);
                CREATE TABLE monitor_evidence_coverage(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    dropped INTEGER NOT NULL DEFAULT 0,
                    dropped_transitions INTEGER NOT NULL DEFAULT 0,
                    first_dropped_at REAL,last_dropped_at REAL);
                INSERT INTO monitor_evidence_coverage(singleton) VALUES(1);
                PRAGMA user_version=1;
                COMMIT;
                """)
            # Missed checks are not synthesized; a claimed check is retried on next tick.
            c.execute("UPDATE monitors SET running=0,next_at=? WHERE running=1",(self.clock(),))
            c.execute("UPDATE outbox SET state='pending' WHERE state='sending'")

    @staticmethod
    def decode(row):
        if not row:
            return None
        r=dict(row)
        r["config"]=json.loads(r["config"])
        r["enabled"]=bool(r["enabled"])
        r["running"]=bool(r["running"])
        r["last_result"]=json.loads(r["last_result"]) if r["last_result"] else None
        return r

    def list(self):
        with self.db() as c:
            return [self.decode(r) for r in c.execute("SELECT * FROM monitors ORDER BY id")]

    def get(self,id):
        with self.db() as c:
            return self.decode(c.execute("SELECT * FROM monitors WHERE id=?",(id,)).fetchone())

    def create(self,config):
        id=uuid.uuid4().hex
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT count(*) FROM monitors").fetchone()[0]>=20:
                raise MonitorBusy("Maximum 20 monitors")
            c.execute("INSERT INTO monitors(id,config,enabled,next_at) VALUES(?,?,?,?)",
                      (id,config.model_dump_json(),int(config.enabled),self.clock()))
        return self.get(id)

    def enable(self,id,value):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT enabled,running FROM monitors WHERE id=?",(id,)).fetchone()
            if not r:
                return None
            if value and not r[0] and r[1]:
                raise MonitorBusy('Previous check still running')
            if bool(r[0])!=value:
                c.execute("UPDATE monitors SET enabled=?,next_at=?,bad=0,good=0 WHERE id=?",(int(value),self.clock(),id))
        return self.get(id)

    def delete(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT running FROM monitors WHERE id=?",(id,)).fetchone()
            if not r:
                return False
            if r[0]:
                raise MonitorBusy("Check in progress; pause and retry")
            c.execute("DELETE FROM monitors WHERE id=?",(id,))
            return True

    def claim(self):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT * FROM monitors WHERE enabled=1 AND running=0 AND next_at<=? ORDER BY next_at,id LIMIT 1",(self.clock(),)).fetchone()
            if not r:
                return None
            c.execute("UPDATE monitors SET running=1 WHERE id=?",(r["id"],))
            return self.decode(r)

    def finish(self,id,result):
        now=self.clock()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT * FROM monitors WHERE id=? AND running=1",(id,)).fetchone()
            if not r:
                return
            cfg=MonitorConfig.model_validate_json(r["config"])
            if not r["enabled"]:
                c.execute("UPDATE monitors SET running=0 WHERE id=?",(id,))
                return
            state=r["state"]
            good,bad=r["good"],r["bad"]
            outcome=result["outcome"]
            c.execute("INSERT INTO observations(monitor_id,at,outcome,latency,payload) VALUES(?,?,?,?,?)",
                      (id,now,outcome,result.get("latency_ms"),json.dumps(result)))
            message=None
            transition=None
            if outcome=="unknown":
                good=bad=0
            elif outcome=="healthy":
                good=min(good+1,cfg.recovery_count);bad=0
                if state=="incident" and good>=cfg.recovery_count:
                    state="healthy"
                    c.execute("UPDATE incidents SET closed=?,resolution='recovered' WHERE monitor_id=? AND closed IS NULL",(now,id))
                    message="RECOVERY: "+cfg.name
                    transition="incident.closed"
                elif state=="unknown":
                    state="healthy"
            else:
                bad=min(bad+1,cfg.failure_count);good=0
                if state!="incident" and bad>=cfg.failure_count:
                    state="incident"
                    c.execute("INSERT INTO incidents(monitor_id,opened,reason) VALUES(?,?,?)",(id,now,result.get("reason") or outcome))
                    transition="incident.opened"
                    message="INCIDENT: "+cfg.name+" — "+(result.get("reason") or outcome)
            # Keep original monitoring and notifications authoritative at capacity.
            # A full analytics queue records an explicit coverage gap without consuming a sequence.
            if c.execute("SELECT count(*) FROM monitor_evidence_outbox").fetchone()[0]>=self.max_evidence_pending:
                c.execute("""UPDATE monitor_evidence_coverage SET dropped=dropped+1,
                    dropped_transitions=dropped_transitions+?,first_dropped_at=coalesce(first_dropped_at,?),last_dropped_at=?
                    WHERE singleton=1""",(int(transition is not None),now,now))
            else:
                seq=c.execute("INSERT INTO monitor_evidence_outbox(payload) VALUES('')").lastrowid
                observation,events=project(id,seq,cfg,result,now,transition)
                c.execute("UPDATE monitor_evidence_outbox SET payload=? WHERE seq=?",(encode(observation,events),seq))
            if message and cfg.notify:
                c.execute("INSERT INTO outbox(monitor_id,created,message,next_at) VALUES(?,?,?,?)",(id,now,message[:500],now))
            c.execute("""UPDATE monitors SET running=0,next_at=?,state=?,good=?,bad=?,last_at=?,last_result=? WHERE id=?""",
                      (now+cfg.interval_seconds,state,good,bad,now,json.dumps(result),id))
            # Per-monitor row cap plus time retention. Open incidents never expire.
            c.execute("DELETE FROM observations WHERE monitor_id=? AND (at<? OR id NOT IN (SELECT id FROM observations WHERE monitor_id=? ORDER BY id DESC LIMIT 10000))",(id,now-30*86400,id))
            c.execute("DELETE FROM incidents WHERE closed IS NOT NULL AND closed<?",(now-180*86400,))
            c.execute("DELETE FROM outbox WHERE state IN ('sent','failed') AND created<?",(now-30*86400,))

    def pending_evidence(self):
        with self.db() as c:
            row=c.execute("SELECT seq,payload FROM monitor_evidence_outbox ORDER BY seq LIMIT 1").fetchone()
            return dict(row) if row else None

    def ack_evidence(self,seq):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            row=c.execute("SELECT seq FROM monitor_evidence_outbox ORDER BY seq LIMIT 1").fetchone()
            if row is None or row[0]!=seq:
                raise MonitorBusy("Evidence acknowledgement out of order")
            c.execute("DELETE FROM monitor_evidence_outbox WHERE seq=?",(seq,))

    def evidence_status(self):
        with self.db() as c:
            c.execute("BEGIN")
            row=dict(c.execute("SELECT dropped,dropped_transitions,first_dropped_at,last_dropped_at FROM monitor_evidence_coverage WHERE singleton=1").fetchone())
            row["pending"]=c.execute("SELECT count(*) FROM monitor_evidence_outbox").fetchone()[0]
            row["max_pending"]=self.max_evidence_pending
            return row

    def prune(self):
        now=self.clock()
        with self.db() as c:
            c.execute("DELETE FROM observations WHERE at<?",(now-30*86400,))
            c.execute("DELETE FROM incidents WHERE closed IS NOT NULL AND closed<?",(now-180*86400,))
            c.execute("UPDATE outbox SET state='failed' WHERE state='pending' AND created<?",(now-7*86400,))
            c.execute("DELETE FROM outbox WHERE state IN ('sent','failed') AND created<?",(now-30*86400,))

    def history(self,id,limit):
        with self.db() as c:
            rows=c.execute("SELECT at,payload FROM observations WHERE monitor_id=? ORDER BY id DESC LIMIT ?",(id,limit))
            return [{"at":r["at"],**json.loads(r["payload"])} for r in rows]

    def incidents(self):
        with self.db() as c:
            return [dict(r) for r in c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 200")]

    def delivery(self):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT * FROM outbox WHERE state='pending' AND next_at<=? ORDER BY id LIMIT 1",(self.clock(),)).fetchone()
            if not r:
                return None
            c.execute("UPDATE outbox SET state='sending',attempts=attempts+1 WHERE id=?",(r["id"],))
            return dict(r)|{"attempts":r["attempts"]+1}

    def delivered(self,row,ok):
        with self.db() as c:
            state="sent" if ok else "failed" if row["attempts"]>=5 else "pending"
            c.execute("UPDATE outbox SET state=?,next_at=? WHERE id=?",(state,self.clock()+min(3600,60*2**row["attempts"]),row["id"]))

    def delivery_counts(self):
        with self.db() as c:
            return {r[0]:r[1] for r in c.execute("SELECT state,count(*) FROM outbox GROUP BY state")}

def check(config):
    if config.kind=="dns":
        r,_=inspect_one(config.endpoint,Inspect(name=config.host,endpoints=[config.endpoint],family=config.family))
        ok=r["outcome"]=="answer"
        latency=r["duration_ms"]
        reason=r["error"] or r["outcome"]
        details={"ip":r["ip"],"rcode":r["rcode"],"protocol":r.get("protocol")}
    else:
        r=probe_once(config.host,config.port,config.family,config.kind,config.path)
        ok=r["ok"] and (config.kind not in ("http","https") or 200<=r["http_status"]<400)
        latency=r["total_ms"] if ok else None
        reason=r["error"] or ("HTTP "+str(r["http_status"]) if not ok else "")
        details={"ip":r["ip"],"http_status":r["http_status"],"stage":r["stage"],
                 "certificate_days":r["certificate"]["days_remaining"] if r["certificate"] else None}
    outcome="healthy" if ok else "failed"
    if ok and config.latency_ms is not None and latency is not None and latency>config.latency_ms:
        outcome="degraded";reason="Latency threshold exceeded"
    days=details.get("certificate_days")
    if ok and config.kind in ("tls","https") and days is not None and days<config.expiry_days:
        outcome="degraded";reason="Certificate expiry threshold"
    return {"outcome":outcome,"latency_ms":latency,"reason":None if outcome=="healthy" else reason,"details":details}

class Telegram:
    def __init__(self,data_dir):
        token_path=Path(data_dir)/"telegram-token"
        self.token=token_path.read_text().strip() if token_path.is_file() else ""
        self.chat=os.getenv("NDC_TELEGRAM_CHAT_ID","")
        import re
        self.enabled=bool(re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+",self.token) and re.fullmatch(r"-?[0-9]+",self.chat))

    def send(self,message):
        # Fixed service endpoint; credentials never returned or logged.
        conn=http.client.HTTPSConnection("api.telegram.org",timeout=5,context=ssl.create_default_context())
        try:
            conn.request("POST","/bot"+self.token+"/sendMessage",body=json.dumps({"chat_id":self.chat,"text":message}),headers={"Content-Type":"application/json"})
            r=conn.getresponse()
            return r.status==200 and json.loads(r.read(32768)).get("ok") is True
        except Exception:
            return False
        finally:
            conn.close()

class MonitorScheduler:
    def __init__(self,store,slot,notifier,probe=check):
        self.store=store;self.slot=slot;self.notifier=notifier;self.probe=probe
        self.stop_event=threading.Event()
        self.next_prune=0
        self.thread=threading.Thread(target=self.loop,daemon=True,name="ndc-monitor")

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(10)

    def tick(self):
        if time.monotonic()>=self.next_prune:
            self.store.prune()
            self.next_prune=time.monotonic()+3600
        if self.slot.acquire(blocking=False):
            try:
                row=self.store.claim()
                if row:
                    try:
                        result=self.probe(MonitorConfig.model_validate(row["config"]))
                    except Exception as exc:
                        result={"outcome":"unknown","latency_ms":None,"reason":type(exc).__name__,"details":{}}
                    self.store.finish(row["id"],result)
            finally:
                self.slot.release()
        if self.notifier.enabled and not self.stop_event.is_set():
            row=self.store.delivery()
            if row:
                self.store.delivered(row,self.notifier.send(row["message"]))

    def loop(self):
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("Monitor scheduler error")
            self.stop_event.wait(1)
