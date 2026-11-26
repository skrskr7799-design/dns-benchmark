"""Explicitly saved controller experiment reports, separate from evidence observations."""
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from .evidence import canonical,digest,Capacity,Conflict

KINDS=("protocol_lab","website_xray")
MAX_ROWS=100
MAX_BYTES=16*1024*1024
MAX_REPORT=512*1024

class ExperimentHistory:
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
            if version not in (0,1):raise RuntimeError("Unsupported experiment history schema")
            if version==0:c.executescript("""BEGIN IMMEDIATE;
                CREATE TABLE reports(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('protocol_lab','website_xray')),created REAL NOT NULL,
                    payload TEXT NOT NULL,hash TEXT NOT NULL,size INTEGER NOT NULL);
                CREATE INDEX reports_kind ON reports(kind,seq);
                PRAGMA user_version=1;COMMIT;""")
            c.execute("PRAGMA journal_mode=WAL")
    def save(self,kind,report):
        if kind not in KINDS:raise ValueError("Unknown experiment kind")
        raw=canonical(report);size=len(raw.encode("utf-8"))
        if size>MAX_REPORT:raise Capacity("Report too large")
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            n,b=c.execute("SELECT count(*),coalesce(sum(size),0) FROM reports").fetchone()
            if n>=MAX_ROWS or b+size>MAX_BYTES:raise Capacity("Experiment history full; export and delete old reports")
            id=uuid.uuid4().hex
            c.execute("INSERT INTO reports(id,kind,created,payload,hash,size) VALUES(?,?,?,?,?,?)",
                (id,kind,self.clock(),raw,digest(report),size))
            return id
    def list(self,kind):
        if kind not in KINDS:raise ValueError("Unknown experiment kind")
        with self.db() as c:
            return [dict(r) for r in c.execute("""SELECT id,kind,created,hash,size,
                json_extract(payload,'$.status') AS status FROM reports WHERE kind=? ORDER BY seq DESC LIMIT 100""",(kind,))]
    def get(self,id):
        with self.db() as c:
            r=c.execute("SELECT * FROM reports WHERE id=?",(id,)).fetchone()
            if r is None:return None
            report=json.loads(r["payload"])
            if digest(report)!=r["hash"]:raise Conflict("Experiment report checksum mismatch")
            return {k:r[k] for k in ("id","kind","created","hash","size")}|{"report":report}
    def delete(self,id):
        with self.db() as c:
            return bool(c.execute("DELETE FROM reports WHERE id=?",(id,)).rowcount)

def optionally_save(store,kind,report,enabled):
    # A failed history write must not hide a completed measurement or cause
    # automatic replay of network traffic.
    if not enabled:return report|{"history_id":None,"history_status":"not_requested"}
    try:id=store.save(kind,report)
    except (Capacity,sqlite3.Error,ValueError):return report|{"history_id":None,"history_status":"not_saved"}
    return report|{"history_id":id,"history_status":"saved"}
