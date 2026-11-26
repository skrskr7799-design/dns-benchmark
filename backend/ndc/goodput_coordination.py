"""Internal admission only: no listener, offer, transport or public API.

Every operation shares AgentStore's SQLite transaction and agent reservation.
The budget counts planned payload, not wire traffic or execution time.
"""
import math
from .evidence import canonical,digest
from .peer_throughput import ThroughputPolicy,ThroughputPlan

CLAIM_TTL=45
WINDOW=60
QUEUE_SECONDS=120
RETENTION=30*86400
MAX_GLOBAL_PENDING=4
MAX_GLOBAL_ADMISSIONS=8
MAX_GLOBAL_BYTES=32*1024*1024
MAX_AGENT_ADMISSIONS=4
MAX_AGENT_BYTES=16*1024*1024
MAX_HISTORY=2048

SCHEMA="""
CREATE TABLE goodput_claims(
 agent_id TEXT NOT NULL REFERENCES agents(id),policy_key TEXT NOT NULL,
 reported_at REAL NOT NULL,PRIMARY KEY(agent_id,policy_key));
CREATE TABLE goodput_requests(
 id TEXT PRIMARY KEY,source_id TEXT NOT NULL REFERENCES agents(id),
 destination_id TEXT NOT NULL REFERENCES agents(id),plan TEXT NOT NULL,
 policy_key TEXT NOT NULL,byte_count INTEGER NOT NULL,
 created REAL NOT NULL,deadline REAL NOT NULL,finished REAL,state TEXT NOT NULL,
 CHECK(source_id<>destination_id),CHECK(byte_count BETWEEN 65536 AND 4194304));
CREATE INDEX goodput_source ON goodput_requests(source_id,finished);
CREATE INDEX goodput_destination ON goodput_requests(destination_id,finished);
CREATE INDEX goodput_window ON goodput_requests(created);
CREATE TABLE goodput_clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),last REAL NOT NULL);
INSERT INTO goodput_clock VALUES(1,0);
"""

def key(policy):
    return digest(policy.model_dump(mode="json"))

class GoodputCoordination:
    goodput_enabled=False

    def goodput_gate(self):
        from .peer_coordination import PeerConflict
        if not self.peer_enabled or not self.goodput_enabled:
            raise PeerConflict("Goodput coordination disabled")

    def goodput_now(self,c):
        from .peer_coordination import PeerConflict
        now=self.clock()
        last=c.execute("SELECT last FROM goodput_clock WHERE singleton=1").fetchone()[0]
        if not math.isfinite(now) or now<last:
            raise PeerConflict("Goodput clock rollback")
        c.execute("UPDATE goodput_clock SET last=? WHERE singleton=1",(now,))
        return now

    def goodput_reserved(self,c,id):
        return bool(c.execute("""SELECT 1 FROM goodput_requests WHERE finished IS NULL
            AND (source_id=? OR destination_id=?) LIMIT 1""",(id,id)).fetchone())

    def goodput_expire(self,c,now):
        # Do not delete history or reset admission budget on clock rollback.
        last=c.execute("SELECT last FROM goodput_clock WHERE singleton=1").fetchone()[0]
        if not math.isfinite(now) or now<last:return
        # Expiry can prune budget/history outside goodput calls; persist its
        # clock too so a later rollback cannot reopen an already aged window.
        c.execute("UPDATE goodput_clock SET last=? WHERE singleton=1",(now,))
        c.execute("""UPDATE goodput_requests SET state='interrupted',finished=?
            WHERE finished IS NULL AND deadline<=?""",(now,now))
        c.execute("DELETE FROM goodput_requests WHERE finished IS NOT NULL AND finished<?",(now-RETENTION,))
        c.execute("DELETE FROM goodput_claims WHERE reported_at<=? OR reported_at>?",(now-CLAIM_TTL,now))

    def goodput_invalidate(self,c,id):
        c.execute("DELETE FROM goodput_claims WHERE agent_id=?",(id,))
        c.execute("""UPDATE goodput_requests SET state='cancelled',finished=max(created,?)
            WHERE finished IS NULL AND (source_id=? OR destination_id=?)""",(self.clock(),id,id))

    def goodput_report_claims(self,credential,policies):
        from .peer_coordination import PeerConflict
        self.goodput_gate()
        if len(policies)>64:raise ValueError("Too many goodput policies")
        ps=[ThroughputPolicy.model_validate(p.model_dump(mode="json")) for p in policies]
        keys={key(p) for p in ps}
        if len(keys)!=len(ps):raise ValueError("Duplicate goodput policy")
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");id=self.identity(c,credential)
            now=self.goodput_now(c);self.expire(c)
            if any(id not in (p.direction.source_agent_id,p.direction.destination_agent_id) for p in ps):
                raise PeerConflict("Unrelated goodput policy")
            for r in c.execute("""SELECT id,policy_key FROM goodput_requests WHERE finished IS NULL
                AND (source_id=? OR destination_id=?)""",(id,id)).fetchall():
                if r["policy_key"] not in keys:
                    c.execute("UPDATE goodput_requests SET state='cancelled',finished=? WHERE id=?",(now,r["id"]))
            c.execute("DELETE FROM goodput_claims WHERE agent_id=?",(id,))
            c.executemany("INSERT INTO goodput_claims VALUES(?,?,?)",[(id,k,now) for k in keys])

    def goodput_fresh(self,c,policy,now):
        d=policy.direction
        for id in (d.source_agent_id,d.destination_agent_id):
            r=c.execute("""SELECT p.reported_at FROM goodput_claims p JOIN agents a ON a.id=p.agent_id
                WHERE p.agent_id=? AND p.policy_key=? AND a.revoked=0 AND a.credential IS NOT NULL""",(id,key(policy))).fetchone()
            if not r or not 0<=now-r[0]<CLAIM_TTL:return False
        return True

    def goodput_admit(self,plan):
        from .peer_coordination import PeerConflict
        self.goodput_gate()
        p=ThroughputPlan.model_validate(plan.model_dump(mode="json"));d=p.direction
        encoded=canonical(p.model_dump(mode="json"));count=p.policy.byte_count
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");now=self.goodput_now(c);self.expire(c)
            if c.execute("SELECT 1 FROM peer_requests WHERE id=?",(p.request_id,)).fetchone():
                raise PeerConflict("Cross-kind request ID conflict")
            existing=c.execute("SELECT plan FROM goodput_requests WHERE id=?",(p.request_id,)).fetchone()
            if existing:
                if existing[0]!=encoded:raise PeerConflict("Request ID conflict")
                return {"id":p.request_id,"duplicate":True}
            if not self.goodput_fresh(c,p.policy,now):raise PeerConflict("Fresh matching goodput claims required")
            if c.execute("SELECT count(*) FROM goodput_requests").fetchone()[0]>=MAX_HISTORY:
                raise PeerConflict("Goodput history capacity")
            if c.execute("SELECT count(*) FROM goodput_requests WHERE finished IS NULL").fetchone()[0]>=MAX_GLOBAL_PENDING:
                raise PeerConflict("Global goodput pending capacity")
            n,b=c.execute("SELECT count(*),coalesce(sum(byte_count),0) FROM goodput_requests WHERE created>?",(now-WINDOW,)).fetchone()
            if n>=MAX_GLOBAL_ADMISSIONS or b+count>MAX_GLOBAL_BYTES:raise PeerConflict("Global goodput budget")
            for id in (d.source_agent_id,d.destination_agent_id):
                if self.peer_reserved(c,id) or c.execute("SELECT 1 FROM tasks WHERE agent_id=? AND state IN ('queued','leased')",(id,)).fetchone():
                    raise PeerConflict("Agent busy")
                n,b=c.execute("""SELECT count(*),coalesce(sum(byte_count),0) FROM goodput_requests
                    WHERE created>? AND (source_id=? OR destination_id=?)""",(now-WINDOW,id,id)).fetchone()
                if n>=MAX_AGENT_ADMISSIONS or b+count>MAX_AGENT_BYTES:raise PeerConflict("Agent goodput budget")
            c.execute("""INSERT INTO goodput_requests(id,source_id,destination_id,plan,policy_key,byte_count,created,deadline,state)
                VALUES(?,?,?,?,?,?,?,?,'queued')""",(p.request_id,d.source_agent_id,d.destination_agent_id,encoded,key(p.policy),count,now,now+QUEUE_SECONDS))
            return {"id":p.request_id,"duplicate":False}

    def goodput_cancel(self,id):
        self.goodput_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");now=self.goodput_now(c);self.expire(c)
            return bool(c.execute("UPDATE goodput_requests SET state='cancelled',finished=? WHERE id=? AND finished IS NULL",(now,id)).rowcount)
