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
from .agent_contract import ENGINE, VERSION, AgentRun, PROTOCOL_V2, CAPABILITY_TTL, DISPATCHABLE_V2
from .agent_evidence import records,encode
from .remote_contract import CONFIG,config_key,validate_remote,project_remote
from .evidence import canonical
from .distributed import DISPATCH_WINDOW,compare as compare_remote_batch
from .agent_control_pki import peer_fingerprint

class AgentError(Exception):
    def __init__(self,status,message):
        self.status=status;self.message=message

def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()

def secret():
    return secrets.token_urlsafe(32)

from .peer_coordination import PeerCoordination,SCHEMA as PEER_SCHEMA
from .goodput_coordination import GoodputCoordination,SCHEMA as GOODPUT_SCHEMA,SESSION_SCHEMA

class AgentStore(PeerCoordination,GoodputCoordination):
    # Only implemented types; each agent must explicitly claim local support.
    remote_kinds=("tcp","tls","http","route")

    def supported_kinds(self):
        return (*DISPATCHABLE_V2,*self.remote_kinds)

    def __init__(self,path,clock=time.time):
        self.path=path;self.clock=clock
        self.max_evidence_pending=10000
        # Volatile grant relay; all accesses in serialized write transactions.
        self.peer_handoffs={}
        self.goodput_handoffs={}

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
            if version not in (0,1,2,3,4,5,6,7):
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

            if version<2:
                c.executescript("""
                BEGIN IMMEDIATE;
                ALTER TABLE tasks ADD COLUMN contract_version TEXT NOT NULL DEFAULT '1'
                    CHECK(contract_version IN ('1','2'));
                ALTER TABLE tasks ADD COLUMN probe_kind TEXT NOT NULL DEFAULT 'dns'
                    CHECK(probe_kind IN ('dns','tcp','tls','http','route'));
                CREATE TABLE agent_capabilities(
                    agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
                    version TEXT NOT NULL CHECK(version='2'),
                    engine TEXT NOT NULL CHECK(engine='python-network-v2'),
                    capabilities TEXT NOT NULL,reported_at REAL NOT NULL);
                PRAGMA user_version=2;
                COMMIT;
                """)

            if version<3:
                c.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE remote_batch_policy(
                    batch_id TEXT PRIMARY KEY REFERENCES batches(id) ON DELETE CASCADE,
                    dispatch_until REAL NOT NULL);
                PRAGMA user_version=3;
                COMMIT;
                """)

            if version<4:
                c.executescript("BEGIN IMMEDIATE;"+PEER_SCHEMA+"PRAGMA user_version=4;COMMIT;")

            if version<5:
                c.executescript("BEGIN IMMEDIATE;"+GOODPUT_SCHEMA+"PRAGMA user_version=5;COMMIT;")

            if version<6:
                c.executescript("BEGIN IMMEDIATE;"+SESSION_SCHEMA+"PRAGMA user_version=6;COMMIT;")

            if version<7:
                c.executescript("""BEGIN IMMEDIATE;
                    ALTER TABLE agents ADD COLUMN control_fingerprint TEXT;
                    ALTER TABLE agents ADD COLUMN control_expires REAL;
                    PRAGMA user_version=7;COMMIT;""")

    def capability_list(self):
        with self.db() as c:
            now=self.clock()
            output=[]
            for row in c.execute("""SELECT a.id,a.name,a.location,a.revoked,a.credential IS NOT NULL AS enrolled,
                a.last_seen,c.version,c.engine,c.capabilities,c.reported_at
                FROM agents a LEFT JOIN agent_capabilities c ON c.agent_id=a.id ORDER BY a.name,a.id"""):
                r=dict(row)
                fresh=bool(r["enrolled"] and not r["revoked"] and r["reported_at"] is not None
                    and 0<=now-r["reported_at"]<CAPABILITY_TTL)
                claims=json.loads(r["capabilities"]) if r["capabilities"] is not None else []
                r["capabilities"]=claims
                r["fresh"]=fresh
                r["dispatchable"]=[k for k in self.supported_kinds() if fresh and k in claims]
                r["provenance"]="agent_claim" if r["version"] is not None else "unreported"
                output.append(r)
            return {"server_version":PROTOCOL_V2,"dispatchable":list(self.supported_kinds()),
                "capability_ttl_seconds":CAPABILITY_TTL,"agents":output}

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

    def enroll(self,token,csr=None,authority=None):
        if (csr is None)!=(authority is None):raise AgentError(422,"CSR and authority required together")
        credential=secret()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r=c.execute("SELECT id FROM agents WHERE enrollment=? AND enroll_until>? AND revoked=0",(digest(token),self.clock())).fetchone()
            if not r:
                raise AgentError(401,"Invalid enrollment")
            id=r[0]
            certificate=pin=expires=None
            if authority is not None:
                certificate,pin,expires=authority.sign_client(id,csr)
            c.execute("UPDATE agents SET credential=?,enrollment=NULL,enroll_until=NULL,control_fingerprint=?,control_expires=? WHERE id=?",(digest(credential),pin,expires,id))
            self.audit(c,id,"enrolled mtls" if pin else "enrolled")
        result={"id":id,"credential":credential,"version":VERSION}
        if certificate:result.update(certificate=certificate,certificate_expires=expires)
        return result

    def rate_identity(self,credential):
        # Read-only preflight. Every route still authenticates in its own
        # transaction, so credential rotation/revocation cannot authorize a
        # later mutation using the preflight result.
        with self.db() as c:
            return self.identity(c,credential)

    def identity(self,c,credential):
        r=c.execute("SELECT * FROM agents WHERE credential=? AND revoked=0",(digest(credential),)).fetchone()
        if not r:
            raise AgentError(401,"Invalid agent credential")
        pin=peer_fingerprint.get()
        if r["control_fingerprint"]!=pin or (pin is not None and (r["control_expires"] is None or self.clock()>=r["control_expires"])):
            raise AgentError(401,"Invalid agent certificate binding")
        return r["id"]

    def expire(self,c):
        now=self.clock()
        self.peer_expire(c,now)
        c.execute("UPDATE tasks SET state='interrupted',finished=? WHERE state='leased' AND lease_until<=?",(now,now))
        c.execute("UPDATE tasks SET state='interrupted',finished=? WHERE state='queued' AND created<=?",(now,now-86400))
        c.execute("""UPDATE tasks SET state='interrupted',finished=? WHERE state='queued' AND id IN (
            SELECT m.task_id FROM batch_members m JOIN remote_batch_policy p ON p.batch_id=m.batch_id
            WHERE p.dispatch_until<=?)""",(now,now))
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
                    for r in c.execute("SELECT id,name,location,revoked,last_seen,engine,enroll_until,control_fingerprint IS NOT NULL AS mtls,control_expires,credential IS NOT NULL AS enrolled FROM agents ORDER BY name,id")]

    def revoke(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if not c.execute("UPDATE agents SET revoked=1,credential=NULL,enrollment=NULL,enroll_until=NULL,control_fingerprint=NULL,control_expires=NULL WHERE id=? AND revoked=0",(id,)).rowcount:
                raise AgentError(404,"Active agent not found")
            c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE agent_id=? AND state IN ('queued','leased')",(self.clock(),id))
            c.execute("DELETE FROM agent_capabilities WHERE agent_id=?",(id,))
            self.peer_invalidate(c,id)
            self.audit(c,id,"revoked")

    def rotate(self,id):
        token=secret()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if not c.execute("UPDATE agents SET credential=NULL,enrollment=?,enroll_until=?,last_seen=NULL,engine=NULL,control_fingerprint=NULL,control_expires=NULL WHERE id=? AND revoked=0",(digest(token),self.clock()+600,id)).rowcount:
                raise AgentError(404,"Active agent not found")
            c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE agent_id=? AND state IN ('queued','leased')",(self.clock(),id))
            c.execute("DELETE FROM agent_capabilities WHERE agent_id=?",(id,))
            self.peer_invalidate(c,id)
            self.audit(c,id,"rotated")
        return {"id":id,"token":token,"expires_at":self.clock()+600}

    def enqueue(self,id,config):
        task=uuid.uuid4().hex
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            if not c.execute("SELECT 1 FROM agents WHERE id=? AND revoked=0 AND credential IS NOT NULL",(id,)).fetchone():
                raise AgentError(404,"Enrolled agent not found")
            if c.execute("SELECT count(*) FROM tasks WHERE agent_id=? AND state IN ('queued','leased')",(id,)).fetchone()[0]+int(self.peer_reserved(c,id))>=4:
                raise AgentError(409,"Agent queue full")
            if c.execute("SELECT count(*) FROM tasks").fetchone()[0]>=10000:
                raise AgentError(409,"Task history capacity reached")
            c.execute("INSERT INTO tasks(id,agent_id,config,state,created) VALUES(?,?,?,'queued',?)",(task,id,config.model_dump_json(),self.clock()))
            self.audit(c,id,"task queued "+task)
        return {"id":task}

    def enqueue_remote(self,id,body):
        cfg=body.config;task=body.request_id
        encoded=canonical(cfg.model_dump(mode="json"))
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            agent=c.execute("SELECT 1 FROM agents WHERE id=? AND revoked=0 AND credential IS NOT NULL",(id,)).fetchone()
            if not agent:raise AgentError(404,"Enrolled agent not found")
            prior=c.execute("SELECT agent_id,contract_version,probe_kind,config FROM tasks WHERE id=?",(task,)).fetchone()
            if prior:
                if c.execute("SELECT 1 FROM batch_members WHERE task_id=?",(task,)).fetchone():
                    raise AgentError(409,"Task request ID already used by batch")
                if tuple(prior)!=(id,"2",cfg.kind,encoded):raise AgentError(409,"Task request ID already used")
                return {"id":task,"duplicate":True}
            if cfg.kind not in self.remote_kinds:raise AgentError(409,"Remote probe kind not enabled")
            cap=c.execute("SELECT capabilities,reported_at FROM agent_capabilities WHERE agent_id=?",(id,)).fetchone()
            if not cap or not 0<=self.clock()-cap["reported_at"]<CAPABILITY_TTL or cfg.kind not in json.loads(cap["capabilities"]):
                raise AgentError(409,"Fresh matching agent capability required")
            if c.execute("SELECT count(*) FROM tasks WHERE agent_id=? AND state IN ('queued','leased')",(id,)).fetchone()[0]+int(self.peer_reserved(c,id))>=4:
                raise AgentError(409,"Agent queue full")
            if c.execute("SELECT count(*) FROM tasks").fetchone()[0]>=10000:
                raise AgentError(409,"Task history capacity reached")
            c.execute("""INSERT INTO tasks(id,agent_id,config,state,created,contract_version,probe_kind)
                VALUES(?,?,?,'queued',?,'2',?)""",(task,id,encoded,self.clock(),cfg.kind))
            self.audit(c,id,"remote task queued "+task)
            return {"id":task,"duplicate":False}

    def remote_tasks(self):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            return [dict(r)|{"config":json.loads(r["config"])} for r in c.execute("""SELECT id,agent_id,config,state,created,finished,contract_version,probe_kind
                FROM tasks WHERE contract_version='2' ORDER BY created DESC,id DESC LIMIT 200""")]

    def remote_detail(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            r=c.execute("""SELECT id,agent_id,config,state,created,finished,payload,contract_version,probe_kind
                FROM tasks WHERE id=? AND contract_version='2'""",(id,)).fetchone()
            if not r:raise AgentError(404,"Remote task not found")
            return dict(r)|{"config":json.loads(r["config"]),"payload":json.loads(r["payload"]) if r["payload"] else None}

    def remote_cancel(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if not c.execute("""UPDATE tasks SET state='cancelled',finished=?
                WHERE id=? AND contract_version='2' AND state IN ('queued','leased')""",(self.clock(),id)).rowcount:
                raise AgentError(409,"Remote task not active")
            return {"cancelled":True}

    def remote_batch(self,body):
        cfg=body.config;ids=body.agent_ids;encoded=canonical(cfg.model_dump(mode="json"))
        fingerprint=digest(canonical(["remote-v2",ids,encoded,DISPATCH_WINDOW]))
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            existing=c.execute("SELECT fingerprint FROM batches WHERE id=?",(body.request_id,)).fetchone()
            if existing:
                if existing[0]!=fingerprint or not c.execute("SELECT 1 FROM remote_batch_policy WHERE batch_id=?",(body.request_id,)).fetchone():
                    raise AgentError(409,"Batch request ID already used")
                return {"id":body.request_id,"duplicate":True}
            if cfg.kind not in self.remote_kinds:raise AgentError(409,"Remote probe kind not enabled")
            now=self.clock()
            if c.execute("SELECT count(*) FROM tasks").fetchone()[0]+len(ids)>10000:
                raise AgentError(409,"Task history capacity reached")
            for id in ids:
                if not c.execute("SELECT 1 FROM agents WHERE id=? AND revoked=0 AND credential IS NOT NULL",(id,)).fetchone():
                    raise AgentError(404,"Selected agent not enrolled")
                cap=c.execute("SELECT capabilities,reported_at FROM agent_capabilities WHERE agent_id=?",(id,)).fetchone()
                if not cap or not 0<=now-cap["reported_at"]<CAPABILITY_TTL or cfg.kind not in json.loads(cap["capabilities"]):
                    raise AgentError(409,"Fresh matching capability required for every agent")
                if c.execute("SELECT count(*) FROM tasks WHERE agent_id=? AND state IN ('queued','leased')",(id,)).fetchone()[0]+int(self.peer_reserved(c,id))>=4:
                    raise AgentError(409,"Selected agent queue full")
            c.execute("INSERT INTO batches VALUES(?,?,?,?)",(body.request_id,now,encoded,fingerprint))
            c.execute("INSERT INTO remote_batch_policy VALUES(?,?)",(body.request_id,now+DISPATCH_WINDOW))
            for id in ids:
                task=uuid.uuid4().hex
                c.execute("""INSERT INTO tasks(id,agent_id,config,state,created,contract_version,probe_kind)
                    VALUES(?,?,?,'queued',?,'2',?)""",(task,id,encoded,now,cfg.kind))
                c.execute("INSERT INTO batch_members VALUES(?,?,?)",(body.request_id,task,id))
                self.audit(c,id,"remote batch task "+task)
            return {"id":body.request_id,"duplicate":False}

    def remote_batches(self):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            return [dict(r)|{"config":json.loads(r["config"])} for r in c.execute("""SELECT b.id,b.created,b.config,p.dispatch_until,count(t.id) AS total,
                sum(CASE WHEN t.state IN ('queued','leased') THEN 0 ELSE 1 END) AS finished
                FROM batches b JOIN remote_batch_policy p ON p.batch_id=b.id JOIN batch_members m ON m.batch_id=b.id
                JOIN tasks t ON t.id=m.task_id GROUP BY b.id ORDER BY b.created DESC,b.id DESC LIMIT 50""")]

    def remote_batch_detail(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            b=c.execute("""SELECT b.id,b.created,b.config,p.dispatch_until FROM batches b
                JOIN remote_batch_policy p ON p.batch_id=b.id WHERE b.id=?""",(id,)).fetchone()
            if not b:raise AgentError(404,"Remote batch not found")
            rows=[]
            for r in c.execute("""SELECT t.id,t.agent_id,t.state,t.created,t.finished,t.lease_until,t.payload,
                a.name,a.location,a.last_seen,a.revoked FROM batch_members m JOIN tasks t ON t.id=m.task_id
                JOIN agents a ON a.id=t.agent_id WHERE m.batch_id=? ORDER BY a.name,a.id""",(id,)):
                row=dict(r);row["payload"]=json.loads(row["payload"]) if row["payload"] else None
                row["online"]=bool(not row["revoked"] and row["last_seen"] is not None and 0<=self.clock()-row["last_seen"]<45)
                rows.append(row)
            cfg=CONFIG.validate_json(b["config"])
            return dict(b)|{"config":cfg.model_dump(mode="json")}|compare_remote_batch(cfg,b["created"],b["dispatch_until"],rows)

    def remote_batch_cancel(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            if not c.execute("SELECT 1 FROM remote_batch_policy WHERE batch_id=?",(id,)).fetchone():
                raise AgentError(404,"Remote batch not found")
            n=c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE id IN (SELECT task_id FROM batch_members WHERE batch_id=?) AND state IN ('queued','leased')",(self.clock(),id)).rowcount
            return {"cancelled":n}

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
                if c.execute("SELECT count(*) FROM tasks WHERE agent_id=? AND state IN ('queued','leased')",(id,)).fetchone()[0]+int(self.peer_reserved(c,id))>=4:
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
                WHERE NOT EXISTS (SELECT 1 FROM remote_batch_policy p WHERE p.batch_id=b.id)
                GROUP BY b.id ORDER BY b.created DESC LIMIT 50""")]

    def batch_detail(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            b=c.execute("SELECT id,created,config FROM batches WHERE id=? AND NOT EXISTS (SELECT 1 FROM remote_batch_policy p WHERE p.batch_id=batches.id)",(id,)).fetchone()
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
            if not c.execute("SELECT 1 FROM batches WHERE id=? AND NOT EXISTS (SELECT 1 FROM remote_batch_policy p WHERE p.batch_id=batches.id)",(id,)).fetchone():
                raise AgentError(404,"Batch not found")
            n=c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE id IN (SELECT task_id FROM batch_members WHERE batch_id=?) AND state IN ('queued','leased')",(self.clock(),id)).rowcount
            return {"cancelled":n}

    def lease_dns(self,c,id):
        if self.peer_reserved(c,id):return None
        if c.execute("SELECT 1 FROM tasks WHERE agent_id=? AND state='leased'",(id,)).fetchone():
            return None
        r=c.execute("""SELECT * FROM tasks WHERE agent_id=? AND state='queued'
            AND contract_version='1' AND probe_kind='dns' ORDER BY created,id LIMIT 1""",(id,)).fetchone()
        if not r:return None
        lease=secret();until=self.clock()+300
        c.execute("UPDATE tasks SET state='leased',lease=?,lease_until=? WHERE id=?",(digest(lease),until,r["id"]))
        return {"id":r["id"],"lease":lease,"lease_seconds":300,"config":json.loads(r["config"]),"version":VERSION,"engine":ENGINE}

    def poll(self,credential,heartbeat):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            id=self.identity(c,credential)
            self.expire(c)
            c.execute("UPDATE agents SET last_seen=?,engine=? WHERE id=?",(self.clock(),heartbeat.engine,id))
            c.execute("DELETE FROM agent_capabilities WHERE agent_id=?",(id,))
            self.peer_invalidate(c,id)
            return {"task":self.lease_dns(c,id)}

    def poll_v2(self,credential,body):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            id=self.identity(c,credential)
            self.expire(c)
            now=self.clock()
            c.execute("UPDATE agents SET last_seen=?,engine=? WHERE id=?",(now,ENGINE,id))
            c.execute("""INSERT INTO agent_capabilities(agent_id,version,engine,capabilities,reported_at)
                VALUES(?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
                version=excluded.version,engine=excluded.engine,capabilities=excluded.capabilities,
                reported_at=excluded.reported_at""",(id,body.version,body.engine,json.dumps(body.capabilities),now))
            task=self.lease_v2(c,id,body.capabilities)
            return {"version":PROTOCOL_V2,"dispatchable":list(self.supported_kinds()),"task":task}

    def lease_v2(self,c,id,claims):
        if self.peer_reserved(c,id):return None
        if c.execute("SELECT 1 FROM tasks WHERE agent_id=? AND state='leased'",(id,)).fetchone():return None
        for r in c.execute("SELECT * FROM tasks WHERE agent_id=? AND state='queued' ORDER BY created,id",(id,)).fetchall():
            if r["probe_kind"] not in claims:continue
            if r["contract_version"]=="1" and r["probe_kind"]=="dns":
                return self.lease_dns(c,id)
            if r["contract_version"]!="2" or r["probe_kind"] not in self.remote_kinds:continue
            cfg=CONFIG.validate_json(r["config"])
            if cfg.kind!=r["probe_kind"]:raise AgentError(409,"Invalid stored task contract")
            lease=secret()
            c.execute("UPDATE tasks SET state='leased',lease=?,lease_until=? WHERE id=?",(digest(lease),self.clock()+300,r["id"]))
            return {"id":r["id"],"lease":lease,"lease_seconds":300,"config":cfg.model_dump(mode="json"),
                "config_key":config_key(cfg),"kind":cfg.kind,"version":PROTOCOL_V2,"engine":"python-network-v2"}
        return None

    def remote_heartbeat(self,credential,body):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            id=self.identity(c,credential)
            r=c.execute("""SELECT probe_kind FROM tasks WHERE id=? AND agent_id=? AND lease=? AND
                contract_version='2' AND state='leased' AND lease_until>?""",
                (body.task_id,id,digest(body.lease),self.clock())).fetchone()
            c.execute("UPDATE agents SET last_seen=? WHERE id=?",(self.clock(),id))
            return {"active":bool(r and r["probe_kind"] in self.remote_kinds)}

    def complete_remote(self,credential,id,body):
        encoded=canonical(body.model_dump(mode="json",exclude={"lease"}))
        ph=digest(encoded)
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            agent=self.identity(c,credential)
            r=c.execute("SELECT * FROM tasks WHERE id=? AND agent_id=? AND lease=?",(id,agent,digest(body.lease))).fetchone()
            if not r or r["contract_version"]!="2" or r["probe_kind"]!=body.kind:
                raise AgentError(404,"Remote task not found")
            if r["state"] in ("completed","failed") and r["payload_hash"]==ph:
                return {"accepted":True,"duplicate":True}
            if r["state"]!="leased" or r["lease_until"]<=self.clock():
                raise AgentError(409,"Lease expired or task already finalized")
            cfg=CONFIG.validate_json(r["config"])
            validate_remote(cfg,body)
            now=self.clock()
            record=project_remote(id,agent,cfg,body)
            member=c.execute("SELECT batch_id FROM batch_members WHERE task_id=?",(id,)).fetchone()
            if member:record=record.model_copy(update={"correlation_id":member[0]})
            c.execute("UPDATE tasks SET state=?,finished=?,payload=?,payload_hash=? WHERE id=?",(body.status,now,encoded,ph,id))
            if c.execute("SELECT count(*) FROM agent_evidence_outbox").fetchone()[0]>=self.max_evidence_pending:
                c.execute("""UPDATE agent_evidence_coverage SET dropped_tasks=dropped_tasks+1,
                    dropped_observations=dropped_observations+1,first_dropped_at=coalesce(first_dropped_at,?),last_dropped_at=?
                    WHERE singleton=1""",(now,now))
            else:
                c.execute("INSERT INTO agent_evidence_outbox(payload) VALUES(?)",(encode((record,)),))
            c.execute("UPDATE agents SET last_seen=? WHERE id=?",(now,agent))
            return {"accepted":True,"duplicate":False}

    def heartbeat(self,credential,body):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            id=self.identity(c,credential)
            c.execute("UPDATE agents SET last_seen=?,engine=? WHERE id=?",(self.clock(),body.engine,id))
            row=c.execute("SELECT 1 FROM tasks WHERE id=? AND agent_id=? AND lease=? AND state='leased' AND contract_version='1' AND probe_kind='dns' AND lease_until>?",(body.task_id,id,digest(body.lease),self.clock())).fetchone()
            return {"active":bool(row)}

    def complete(self,credential,id,body):
        payload=body.model_dump(exclude={"lease"})
        encoded=json.dumps(payload,sort_keys=True,separators=(",",":"),allow_nan=False)
        ph=digest(encoded)
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            agent=self.identity(c,credential)
            r=c.execute("SELECT * FROM tasks WHERE id=? AND agent_id=? AND lease=?",(id,agent,digest(body.lease))).fetchone()
            if not r or r["contract_version"]!="1" or r["probe_kind"]!="dns":
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
            if not c.execute("UPDATE tasks SET state='cancelled',finished=? WHERE id=? AND contract_version='1' AND probe_kind='dns' AND state IN ('queued','leased')",(self.clock(),id)).rowcount:
                raise AgentError(409,"Task not active")

    def tasks(self):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            return [dict(r)|{"config":json.loads(r["config"])} for r in c.execute("SELECT id,agent_id,config,state,created,finished FROM tasks WHERE contract_version='1' AND probe_kind='dns' ORDER BY created DESC LIMIT 200")]

    def detail(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            self.expire(c)
            r=c.execute("SELECT id,agent_id,config,state,created,finished,payload FROM tasks WHERE id=? AND contract_version='1' AND probe_kind='dns'",(id,)).fetchone()
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
