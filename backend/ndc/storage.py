import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from contextlib import contextmanager
from .benchmark_evidence import project
from .evidence import payload

ACTIVE = ("queued", "running", "cancelling")
TERMINAL = ("completed", "failed", "cancelled", "interrupted")

def summary(result):
    return {k:v for k,v in result.items() if k!='samples'}

class Busy(Exception):
    pass

class Store:
    def __init__(self, path: Path):
        self.path = path
        self.max_jobs = int(os.getenv("NDC_MAX_JOBS","500"))
        self.max_evidence_pending=10000
        if not 10<=self.max_jobs<=5000:
            raise ValueError("NDC_MAX_JOBS must be 10–5000")
        path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=10000")
        c.execute("PRAGMA foreign_keys=ON")
        try:
            with c:
                yield c
        finally:
            c.close()

    def initialize(self):
        # Single coordinator owns the database. Backup before first additive migration.
        with self.connect() as c:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            if version > 2:
                raise RuntimeError("Unsupported database schema")
            if version == 0:
                if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='runs'").fetchone():
                    backup = self.path.with_name("history.before-fnd02.sqlite")
                    if not backup.exists():
                        temp = backup.with_suffix(".tmp")
                        with sqlite3.connect(temp) as dst:
                            c.backup(dst)
                        temp.replace(backup)
                c.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, payload TEXT);
                    CREATE TABLE IF NOT EXISTS jobs (
                        id TEXT PRIMARY KEY, created REAL NOT NULL, started REAL, finished REAL,
                        status TEXT NOT NULL, config TEXT NOT NULL, error TEXT,
                        revision INTEGER NOT NULL DEFAULT 1,
                        legacy_id INTEGER REFERENCES runs(id));
                    CREATE TABLE IF NOT EXISTS job_results (
                        job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL, payload TEXT NOT NULL,
                        PRIMARY KEY(job_id, ordinal));
                    CREATE TABLE IF NOT EXISTS profiles (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL, config TEXT NOT NULL,
                        updated REAL NOT NULL);
                    CREATE INDEX IF NOT EXISTS jobs_status_created ON jobs(status, created);
                    PRAGMA user_version=1;
                    COMMIT;
                """)
            if version<2:
                # Existing records are not silently backfilled; new writes only.
                c.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE benchmark_evidence_outbox(
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        payload TEXT NOT NULL);
                    PRAGMA user_version=2;
                    COMMIT;
                """)
            c.execute("PRAGMA journal_mode=WAL")
            # Do not silently resume a previously running job.
            c.execute("UPDATE jobs SET status='interrupted', finished=?, error='Process restarted', revision=revision+1 WHERE status IN ('running','cancelling')", (time.time(),))

    def create(self, config, legacy=False):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            n = c.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running','cancelling')").fetchone()[0]
            if n >= 8 or (legacy and n):
                raise Busy("Queue is full or another run is active")
            if c.execute("SELECT count(*) FROM jobs").fetchone()[0]>=self.max_jobs:
                raise Busy("Run history capacity reached; export and remove old runs")
            # Reserve 80 result slots for each admitted active job (40 x both).
            pending=c.execute("SELECT count(*) FROM benchmark_evidence_outbox").fetchone()[0]
            if pending+80*(n+1)>self.max_evidence_pending:
                raise Busy("Intelligence backlog capacity reached; check evidence status")
            job_id = uuid.uuid4().hex
            c.execute("INSERT INTO jobs(id,created,status,config) VALUES(?,?,'queued',?)",
                      (job_id,time.time(),json.dumps(config)))
        return job_id

    def claim(self):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT 1 FROM jobs WHERE status IN ('running','cancelling') LIMIT 1").fetchone():
                return None
            row = c.execute("SELECT id FROM jobs WHERE status='queued' ORDER BY created,id LIMIT 1").fetchone()
            if not row:
                return None
            c.execute("UPDATE jobs SET status='running',started=?,revision=revision+1 WHERE id=?", (time.time(),row["id"]))
            return row["id"]

    def get(self, job_id, raw=False, since=None):
        with self.connect() as c:
            c.execute("BEGIN")
            r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not r:
                return None
            if since is not None and r["revision"]==since:
                return {"revision":since,"status":r["status"],"unchanged":True}
            job = dict(r)
            job["config"] = json.loads(job["config"])
            job["results"] = [json.loads(x[0]) for x in c.execute("SELECT payload FROM job_results WHERE job_id=? ORDER BY ordinal",(job_id,))]
            job["done"] = sum(x["count"] == x.get("requested_count",x["count"]) for x in job["results"])
            job["total"] = len(job["config"]["endpoints"]) * (2 if job["config"]["mode"]=="both" else 1)
            if not raw:
                job["results"]=[summary(x) for x in job["results"]]
            return job

    def latest_id(self):
        with self.connect() as c:
            row = c.execute("""SELECT id FROM jobs ORDER BY
                CASE status WHEN 'running' THEN 0 WHEN 'cancelling' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END,
                CASE WHEN status IN ('queued','running','cancelling') THEN created ELSE -created END,id LIMIT 1""").fetchone()
            return row[0] if row else None

    def list(self, limit=30, offset=0):
        with self.connect() as c:
            rows = c.execute("SELECT id,status,created,started,finished,error,revision FROM jobs ORDER BY created DESC,id LIMIT ? OFFSET ?",(limit,offset)).fetchall()
            return [dict(r) for r in rows]

    def add_result(self, job_id, ordinal, result):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row=c.execute("SELECT status,config FROM jobs WHERE id=?",(job_id,)).fetchone()
            if row is None or row[0] not in ("running","cancelling"):
                raise Busy("Cannot append to terminal or missing run")
            config=json.loads(row["config"])
            if type(ordinal) is not int or not 0<=ordinal<len(config["endpoints"])*(2 if config["mode"]=="both" else 1):
                raise Busy("Invalid result ordinal")
            record=project(job_id,ordinal,config,result,time.time())
            c.execute("INSERT INTO job_results(job_id,ordinal,payload) VALUES(?,?,?)",(job_id,ordinal,json.dumps(result)))
            c.execute("INSERT INTO benchmark_evidence_outbox(payload) VALUES(?)",(payload(record),))
            c.execute("UPDATE jobs SET revision=revision+1 WHERE id=?",(job_id,))

    def pending_evidence(self):
        with self.connect() as c:
            row=c.execute("SELECT seq,payload FROM benchmark_evidence_outbox ORDER BY seq LIMIT 1").fetchone()
            return dict(row) if row else None

    def ack_evidence(self,seq):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row=c.execute("SELECT seq FROM benchmark_evidence_outbox ORDER BY seq LIMIT 1").fetchone()
            if row is None or row[0]!=seq:
                raise Busy("Evidence acknowledgement out of order")
            c.execute("DELETE FROM benchmark_evidence_outbox WHERE seq=?",(seq,))

    def evidence_pending_count(self):
        with self.connect() as c:
            return c.execute("SELECT count(*) FROM benchmark_evidence_outbox").fetchone()[0]

    def cancel(self, job_id):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute("SELECT status FROM jobs WHERE id=?",(job_id,)).fetchone()
            if not r:
                return None
            if r[0] == "queued":
                c.execute("UPDATE jobs SET status='cancelled',finished=?,revision=revision+1 WHERE id=?",(time.time(),job_id))
            elif r[0] == "running":
                c.execute("UPDATE jobs SET status='cancelling',revision=revision+1 WHERE id=?",(job_id,))
        return self.get(job_id)

    def finish(self, job_id, status, error=None):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute("SELECT status,started FROM jobs WHERE id=?",(job_id,)).fetchone()
            if not r or r["status"] not in ("running","cancelling"):
                return
            if r["status"] == "cancelling":
                status = "cancelled"
            legacy_id = None
            if status == "completed":
                results = [json.loads(x[0]) for x in c.execute("SELECT payload FROM job_results WHERE job_id=? ORDER BY ordinal",(job_id,))]
                legacy_id = c.execute("INSERT INTO runs(payload) VALUES(?)",(json.dumps({"time":time.time(),"run_id":job_id,"results":[summary(x) for x in results]}),)).lastrowid
            c.execute("UPDATE jobs SET status=?,finished=?,error=?,legacy_id=?,revision=revision+1 WHERE id=?",(status,time.time(),error,legacy_id,job_id))

    def delete_run(self,job_id):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT status,legacy_id FROM jobs WHERE id=?",(job_id,)).fetchone()
            if r is None:
                return False
            if r["status"] not in TERMINAL:
                raise Busy("Cannot remove active run")
            c.execute("DELETE FROM jobs WHERE id=?",(job_id,))
            if r["legacy_id"] is not None:
                c.execute("DELETE FROM runs WHERE id=?",(r["legacy_id"],))
            return True

    def history(self):
        with self.connect() as c:
            return [json.loads(x[0]) for x in c.execute("SELECT payload FROM runs ORDER BY id DESC LIMIT 30")]

    def profiles(self):
        with self.connect() as c:
            return [dict(r)|{"config":json.loads(r["config"])} for r in c.execute("SELECT * FROM profiles ORDER BY updated DESC")]

    def put_profile(self, value, profile_id=None):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if profile_id:
                cursor=c.execute("UPDATE profiles SET name=?,config=?,updated=? WHERE id=?",(value["name"],json.dumps(value["config"]),time.time(),profile_id))
                if not cursor.rowcount:
                    return None
            else:
                if c.execute("SELECT count(*) FROM profiles").fetchone()[0]>=100:
                    raise Busy("Profile capacity reached")
                profile_id=uuid.uuid4().hex
                c.execute("INSERT INTO profiles VALUES(?,?,?,?)",(profile_id,value["name"],json.dumps(value["config"]),time.time()))
        return {"id":profile_id,**value}

    def delete_profile(self, profile_id):
        with self.connect() as c:
            return bool(c.execute("DELETE FROM profiles WHERE id=?",(profile_id,)).rowcount)
