import hashlib
import math
import statistics
import ipaddress
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from .agent_contract import ENGINE, VERSION, AgentRun
from .agent_evidence import records,encode

class AgentError(Exception):
    def __init__(self,status,message):
        self.status=status;self.message=message

def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()

def secret():
    return secrets.token_urlsafe(32)

class AgentStore:
    def __init__(self,path,clock=time.time):
        self.path=path;self.clock=clock
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
                raise RuntimeError("Unsupported agent schema")
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript("""
            CREATE TABLE IF NOT EXISTS agents(
                id TEXT PRIMARY KEY,name TEXT NOT NULL,location TEXT NOT NULL,
                credential TEXT UNIQUE,enrollment TEXT UNIQUE,enroll_until REAL,
                revoked INTEGER NOT NULL DEFAULT 0,last_seen REAL,engine TEXT);
            CREATE TABLE IF NOT EXISTS tasks(
                id TEXT PRIMARY KEY,agent_id TEXT NOT NULL REFERENCES agents(id),
                config TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,
                lease TEXT,lease_until REAL,finished REAL,payload TEXT,payload_hash TEXT);
            CREATE INDEX IF NOT EXISTS tasks_agent_state ON tasks(agent_id,state,created);
            CREATE TABLE IF NOT EXISTS batches(id TEXT PRIMARY KEY, created REAL NOT NULL, config TEXT NOT NULL, fingerprint TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS batch_members(batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE, task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE CASCADE, agent_id TEXT NOT NULL REFERENCES agents(id), PRIMARY KEY(batch_id,agent_id));
            CREATE TABLE IF NOT EXISTS agent_audit(
                id INTEGER PRIMARY KEY,at REAL NOT NULL,agent_id TEXT NOT NULL,event TEXT NOT NULL);
            """)

            if version==0:
                c.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE agent_evidence_outbox(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT NOT NULL);
                CREATE TABLE agent_evidence_coverage(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    dropped_tasks INTEGER NOT NULL DEFAULT 0,
                    dropped_observations INTEGER NOT NULL DEFAULT 0,
                    first_dropped_at REAL,last_dropped_at REAL);
                INSERT INTO agent_evidence_coverage(singleton) VALUES(1);
                PRAGMA user_version=1;
                COMMIT;
                """)

    def pending_evidence(self):
        with self.db() as c:
            row=c.execute("SELECT seq,payload FROM agent_evidence_outbox ORDER BY seq LIMIT 1").fetchone()
            return dict(row) if row else None

    def ack_evidence(self,seq):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            row=c.execute("SELECT seq FROM agent_evidence_outbox ORDER BY seq LIMIT 1").fetchone()
            if row is None or row[0]!=seq:
                raise AgentError(409,"Evidence acknowledgement out of order")
            c.execute("DELETE FROM agent_evidence_outbox WHERE seq=?",(seq,))

    def evidence_status(self):
        with self.db() as c:
            c.execute("BEGIN")
            result=dict(c.execute("SELECT dropped_tasks,dropped_observations,first_dropped_at,last_dropped_at FROM agent_evidence_coverage WHERE singleton=1").fetchone())
            result["pending"]=c.execute("SELECT count(*) FROM agent_evidence_outbox").fetchone()[0]
            result["max_pending"]=self.max_evidence_pending
            return result

    def audit(self,c,id,event):
        c.execute("INSERT INTO agent_audit(at,agent_id,event) VALUES(?,?,?)",(self.clock(),id,event))

    def invite(self,name,location):
        token=secret();id=uuid.uuid4().hex
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT count(*) FROM agents").fetchone()[0]>=32:
                raise AgentError(409,"Agent capacity reached")
            c.execute("INSERT INTO agents(id,name,location,enrollment,enroll_until) VALUES(?,?,?,?,?)",(id,name,location,digest(token),self.clock()+600))
            self.audit(c,id,"invite")
        return {"id":id,"token":token,"expires_at":self.clock()+600}

    def enroll(self,token):
        credential=secret()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT id FROM agents WHERE enrollment=? AND enroll_until>? AND revoked=0",(digest(token),self.clock())).fetchone()
            if not r:
                raise AgentError(401,"Invalid enrollment")
            id=r[0]
            c.execute("UPDATE agents SET credential=?,enrollment=NULL,enroll_until=NULL WHERE id=?",(digest(credential),id))
            self.audit(c,id,"enrolled")
        return {"id":id,"credential":credential,"version":VERSION}

    def identity(self,c,credential):
        r=c.execute("SELECT * FROM agents WHERE credential=? AND revoked=0",(digest(credential),)).fetchone()
        if not r:
            raise AgentError(401,"Invalid agent credential")
        return r["id"]

    def expire(self,c):
        now=self.clock()
        c.execute("UPDATE tasks SET state='interrupted',finished=? WHERE state='leased' AND lease_until<=?",(now,now))
        c.execute("UPDATE tasks SET state='interrupted',finished=? WHERE state='queued' AND created<=?",(now,now-86400))
        # Preserve all members until the whole batch is terminal and old.
        c.execute("""DELETE FROM tasks WHERE finished IS NOT NULL AND finished<? AND
            (id NOT IN (SELECT task_id FROM batch_members) OR id IN (
                SELECT m.task_id FROM batch_members m WHERE m.batch_id IN (
                    SELECT m2.batch_id FROM batch_members m2 JOIN tasks t ON t.id=m2.task_id
                    GROUP BY m2.batch_id HAVING count(t.finished)=count(*) AND max(t.finished)<?)))""",
            (now-30*86400,now-30*86400))
        c.execute("DELETE FROM batches WHERE NOT EXISTS (SELECT 1 FROM batch_members WHERE batch_id=batches.id)")
        c.execute("DELETE FROM agent_audit WHERE at<?",(now-180*86400,))

    def list(self):
        with self.db() as c:
            return [dict(r)|{"online":not r["revoked"] and r["last_seen"] is not None and self.clock()-r["last_seen"]<45}
                    for r in c.execute("SELECT id,name,location,revoked,last_seen,engine,enroll_until,credential IS NOT NULL AS enrolled FROM agents ORDER BY name,id")]

    def revoke(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if not c.execute("UPDATE agents SET revoked=1,credential=NULL,enrollment=NULL,enroll_until=NULL WHERE id=? AND revoked=0",(id,)).rowcount:
                raise AgentError(404,"Active agent not found")
            c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE agent_id=? AND state IN ('queued','leased')",(self.clock(),id))
            self.audit(c,id,"revoked")

    def rotate(self,id):
        token=secret()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if not c.execute("UPDATE agents SET credential=NULL,enrollment=?,enroll_until=?,last_seen=NULL,engine=NULL WHERE id=? AND revoked=0",(digest(token),self.clock()+600,id)).rowcount:
                raise AgentError(404,"Active agent not found")
            c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE agent_id=? AND state IN ('queued','leased')",(self.clock(),id))
            self.audit(c,id,"rotated")
        return {"id":id,"token":token,"expires_at":self.clock()+600}

    def enqueue(self,id,config):
        task=uuid.uuid4().hex
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            if not c.execute("SELECT 1 FROM agents WHERE id=? AND revoked=0 AND credential IS NOT NULL",(id,)).fetchone():
                raise AgentError(404,"Enrolled agent not found")
            if c.execute("SELECT count(*) FROM tasks WHERE agent_id=? AND state IN ('queued','leased')",(id,)).fetchone()[0]>=4:
                raise AgentError(409,"Agent queue full")
            if c.execute("SELECT count(*) FROM tasks").fetchone()[0]>=10000:
                raise AgentError(409,"Task history capacity reached")
            c.execute("INSERT INTO tasks(id,agent_id,config,state,created) VALUES(?,?,?,'queued',?)",(task,id,config.model_dump_json(),self.clock()))
            self.audit(c,id,"task queued "+task)
        return {"id":task}

    def batch(self,body):
        config=body.config.model_dump_json()
        ids=sorted(body.agent_ids)
        fingerprint=digest(json.dumps([ids,config]))
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            existing=c.execute("SELECT fingerprint FROM batches WHERE id=?",(body.request_id,)).fetchone()
            if existing:
                if existing[0]!=fingerprint:
                    raise AgentError(409,"Batch request ID already used")
                return {"id":body.request_id,"duplicate":True}
            if c.execute("SELECT count(*) FROM tasks").fetchone()[0]+len(ids)>10000:
                raise AgentError(409,"Task history capacity reached")
            for id in ids:
                if not c.execute("SELECT 1 FROM agents WHERE id=? AND revoked=0 AND credential IS NOT NULL",(id,)).fetchone():
                    raise AgentError(404,"Selected agent is not enrolled")
                if c.execute("SELECT count(*) FROM tasks WHERE agent_id=? AND state IN ('queued','leased')",(id,)).fetchone()[0]>=4:
                    raise AgentError(409,"Selected agent queue full")
            now=self.clock()
            c.execute("INSERT INTO batches VALUES(?,?,?,?)",(body.request_id,now,config,fingerprint))
            for id in ids:
                task=uuid.uuid4().hex
                c.execute("INSERT INTO tasks(id,agent_id,config,state,created) VALUES(?,?,?,'queued',?)",(task,id,config,now))
                c.execute("INSERT INTO batch_members VALUES(?,?,?)",(body.request_id,task,id))
                self.audit(c,id,"batch task "+task)
        return {"id":body.request_id,"duplicate":False}

    def batches(self):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            return [dict(r)|{"config":json.loads(r["config"])} for r in c.execute("""SELECT b.id,b.created,b.config,count(t.id) AS total,
                sum(CASE WHEN t.state IN ('queued','leased') THEN 0 ELSE 1 END) AS finished
                FROM batches b JOIN batch_members m ON m.batch_id=b.id JOIN tasks t ON t.id=m.task_id
                GROUP BY b.id ORDER BY b.created DESC LIMIT 50""")]

    def batch_detail(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            b=c.execute("SELECT id,created,config FROM batches WHERE id=?",(id,)).fetchone()
            if not b:
                raise AgentError(404,"Batch not found")
            rows=[]
            for r in c.execute("""SELECT t.id,t.agent_id,t.state,t.created,t.finished,t.payload,a.name,a.location,a.last_seen,a.revoked
                FROM batch_members m JOIN tasks t ON t.id=m.task_id JOIN agents a ON a.id=t.agent_id WHERE m.batch_id=? ORDER BY a.name,a.id""",(id,)):
                row=dict(r)
                payload=json.loads(row.pop("payload")) if row["payload"] else None
                row.pop("payload",None)
                row["online"]=not row["revoked"] and row["last_seen"] is not None and self.clock()-row["last_seen"]<45
                row["error"]=payload.get("error") if payload else None
                row["results"]=[comparison_row(x) for x in payload.get("results",[])] if payload else []
                rows.append(row)
            return dict(b)|{"config":json.loads(b["config"]),"members":rows}

    def cancel_batch(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if not c.execute("SELECT 1 FROM batches WHERE id=?",(id,)).fetchone():
                raise AgentError(404,"Batch not found")
            n=c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE id IN (SELECT task_id FROM batch_members WHERE batch_id=?) AND state IN ('queued','leased')",(self.clock(),id)).rowcount
            return {"cancelled":n}

    def poll(self,credential,heartbeat):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            id=self.identity(c,credential)
            self.expire(c)
            c.execute("UPDATE agents SET last_seen=?,engine=? WHERE id=?",(self.clock(),heartbeat.engine,id))
            if c.execute("SELECT 1 FROM tasks WHERE agent_id=? AND state='leased'",(id,)).fetchone():
                return {"task":None}
            r=c.execute("SELECT * FROM tasks WHERE agent_id=? AND state='queued' ORDER BY created,id LIMIT 1",(id,)).fetchone()
            if not r:
                return {"task":None}
            lease=secret();until=self.clock()+300
            c.execute("UPDATE tasks SET state='leased',lease=?,lease_until=? WHERE id=?",(digest(lease),until,r["id"]))
            return {"task":{"id":r["id"],"lease":lease,"lease_seconds":300,"config":json.loads(r["config"]),"version":VERSION,"engine":ENGINE}}

    def heartbeat(self,credential,body):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            id=self.identity(c,credential)
            c.execute("UPDATE agents SET last_seen=?,engine=? WHERE id=?",(self.clock(),body.engine,id))
            row=c.execute("SELECT 1 FROM tasks WHERE id=? AND agent_id=? AND lease=? AND state='leased' AND lease_until>?",(body.task_id,id,digest(body.lease),self.clock())).fetchone()
            return {"active":bool(row)}

    def complete(self,credential,id,body):
        payload=body.model_dump(exclude={"lease"})
        encoded=json.dumps(payload,sort_keys=True,separators=(",",":"),allow_nan=False)
        ph=digest(encoded)
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            agent=self.identity(c,credential)
            r=c.execute("SELECT * FROM tasks WHERE id=? AND agent_id=? AND lease=?",(id,agent,digest(body.lease))).fetchone()
            if not r:
                raise AgentError(404,"Task not found")
            if r["state"] in ("completed","failed") and r["payload_hash"]==ph:
                return {"accepted":True,"duplicate":True}
            if r["state"]!="leased" or r["lease_until"]<=self.clock():
                raise AgentError(409,"Lease expired or task already finalized")
            cfg=AgentRun.model_validate_json(r["config"])
            validate_result(cfg,body)
            now=self.clock()
            c.execute("UPDATE tasks SET state=?,finished=?,payload=?,payload_hash=? WHERE id=?",(body.status,now,encoded,ph,id))
            # Preserve accepted remote results under analytics backpressure.
            # Both modes are one batch: never store only half of a task.
            if c.execute("SELECT count(*) FROM agent_evidence_outbox").fetchone()[0]>=self.max_evidence_pending:
                c.execute("""UPDATE agent_evidence_coverage SET dropped_tasks=dropped_tasks+1,
                    dropped_observations=dropped_observations+?,first_dropped_at=coalesce(first_dropped_at,?),last_dropped_at=?
                    WHERE singleton=1""",(len(body.results) if body.status=="completed" else 1,now,now))
            else:
                member=c.execute("SELECT batch_id FROM batch_members WHERE task_id=?",(id,)).fetchone()
                observations=records(id,agent,member[0] if member else None,cfg,body)
                c.execute("INSERT INTO agent_evidence_outbox(payload) VALUES(?)",(encode(observations),))
            c.execute("UPDATE agents SET last_seen=? WHERE id=?",(self.clock(),agent))
            return {"accepted":True,"duplicate":False}

    def cancel(self,id):
        with self.db() as c:
            if not c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE id=? AND state IN ('queued','leased')",(self.clock(),id)).rowcount:
                raise AgentError(409,"Task not active")

    def tasks(self):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            return [dict(r)|{"config":json.loads(r["config"])} for r in c.execute("SELECT id,agent_id,config,state,created,finished FROM tasks ORDER BY created DESC LIMIT 200")]

    def detail(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            r=c.execute("SELECT id,agent_id,config,state,created,finished,payload FROM tasks WHERE id=?",(id,)).fetchone()
            if not r:
                raise AgentError(404,"Task not found")
            return dict(r)|{"config":json.loads(r["config"]),"payload":json.loads(r["payload"]) if r["payload"] else None}

def validate_result(cfg,body):
    from .probes.dns import domains
    if body.status=="failed":
        if body.results or not body.error:
            raise AgentError(422,"Invalid failure result")
        return
    modes=["cold","warm"] if cfg.mode=="both" else [cfg.mode]
    if len(body.results)!=len(modes):
        raise AgentError(422,"Wrong result series count")
    for row,mode in zip(body.results,modes):
        if row.get("endpoint")!=cfg.endpoints[0] or row.get("mode")!=mode or row.get("family")!=cfg.family or row.get("engine")!=ENGINE or row.get("count")!=cfg.count:
            raise AgentError(422,"Result does not match task")
        samples=row.get("samples")
        if not isinstance(samples,list) or len(samples)!=cfg.count:
            raise AgentError(422,"Invalid sample count")
        for i,s in enumerate(samples):
            if not isinstance(s,dict) or type(s.get("index")) is not int or s.get("index")!=i or s.get("domain")!=domains[i%len(domains)] or s.get("qtype")!="A" or type(s.get("ok")) is not bool:
                raise AgentError(422,"Invalid sample")
            latency=s.get("duration_ms")
            if latency is not None and (type(latency) not in (int,float) or not 0<=latency<=300000):
                raise AgentError(422,"Invalid latency")
            if s["ok"] and latency is None:
                raise AgentError(422,"Missing successful latency")
        if row.get("ok")!=sum(s["ok"] for s in samples):
            raise AgentError(422,"Invalid success count")
    if len(modes)==2 and body.results[0].get("ip")!=body.results[1].get("ip"):
        raise AgentError(422,"Both must use same IP")

def comparison_row(row):
    # Derive latency aggregates from validated samples, never trust claimed summary.
    samples=row["samples"]
    values=sorted(s["duration_ms"] for s in samples if s["ok"])
    def pct(p):
        return round(values[max(0,math.ceil(len(values)*p)-1)],2) if values else None
    def ip(value):
        try:
            return str(ipaddress.ip_address(value))
        except (ValueError,TypeError):
            return None
    peer=ip(row.get("ip"))
    protocols=sorted({s["protocol"] for s in samples if s["ok"] and isinstance(s.get("protocol"),str) and s["protocol"] in ("udp","tcp","dot","h2","h3","doq")})
    return {"mode":row["mode"],"ip":peer,"protocols":protocols,"count":len(samples),"ok":len(values),
            "mean":round(statistics.mean(values),2) if values else None,"p95":pct(.95),"p50":pct(.5),
            "jitter":round(statistics.pstdev(values),2) if values else None,
            "warmup_ok":row.get("warmup",{}).get("ok") is True if isinstance(row.get("warmup"),dict) else False,
            "reused":sum(s.get("reused") is True for s in samples if s["ok"]),
            "unknown_reuse":sum(s.get("reused") is None for s in samples if s["ok"])}
