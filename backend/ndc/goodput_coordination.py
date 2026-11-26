"""Internal admission and session coordination; no listener or public API.

Every operation shares AgentStore's SQLite transaction and agent reservation.
The budget counts planned payload, not wire traffic or execution time.
"""
import math
import hashlib
import ipaddress
import secrets
import json
from .evidence import canonical,digest,Observation,Measurement
from .agent_evidence import encode
from .peer_throughput import ThroughputPolicy,ThroughputPlan,ThroughputReport

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

SESSION_SCHEMA="""
ALTER TABLE goodput_requests ADD COLUMN receiver_lease TEXT;
ALTER TABLE goodput_requests ADD COLUMN source_lease TEXT;
ALTER TABLE goodput_requests ADD COLUMN receiver_report TEXT;
ALTER TABLE goodput_requests ADD COLUMN source_report TEXT;
ALTER TABLE goodput_requests ADD COLUMN quarantine_until REAL NOT NULL DEFAULT 0;
"""
PREPARE_SECONDS=20
READY_SECONDS=15
QUARANTINE_SECONDS=10

def valid_token(value):
    return isinstance(value,str) and len(value)==43 and all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value)

def lease_hash(value):
    from .peer_coordination import PeerConflict
    if not valid_token(value):raise PeerConflict("Invalid lease")
    return hashlib.sha256(value.encode("ascii")).hexdigest()

def key(policy):
    return digest(policy.model_dump(mode="json"))

class GoodputCoordination:
    goodput_enabled=False
    goodput_session_enabled=False

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
        return bool(c.execute("""SELECT 1 FROM goodput_requests WHERE (finished IS NULL OR quarantine_until>?)
            AND (source_id=? OR destination_id=?) LIMIT 1""",(self.clock(),id,id)).fetchone())

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
        self.goodput_prune_handoffs(c,now)

    def goodput_invalidate(self,c,id):
        c.execute("DELETE FROM goodput_claims WHERE agent_id=?",(id,))
        c.execute("""UPDATE goodput_requests SET state='cancelled',finished=max(created,?)
            WHERE finished IS NULL AND (source_id=? OR destination_id=?)""",(self.clock(),id,id))
        self.goodput_prune_handoffs(c,self.clock())

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
            self.goodput_prune_handoffs(c,now)

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
            if c.execute("SELECT count(*) FROM goodput_requests WHERE finished IS NULL OR quarantine_until>?",(now,)).fetchone()[0]>=MAX_GLOBAL_PENDING:
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
            changed=bool(c.execute("UPDATE goodput_requests SET state='cancelled',finished=? WHERE id=? AND finished IS NULL",(now,id)).rowcount)
            self.goodput_handoffs.pop(id,None)
            return changed


    def goodput_prune_handoffs(self,c,now):
        for id in tuple(self.goodput_handoffs):
            if not c.execute("SELECT 1 FROM goodput_requests WHERE id=? AND state='ready' AND finished IS NULL AND deadline>?",(id,now)).fetchone():
                self.goodput_handoffs.pop(id,None)

    def goodput_session_gate(self):
        from .peer_coordination import PeerConflict
        self.goodput_gate()
        if not self.goodput_session_enabled:raise PeerConflict("Goodput sessions disabled")

    def goodput_row(self,c,id):
        from .peer_coordination import PeerConflict
        r=c.execute("SELECT * FROM goodput_requests WHERE id=?",(id,)).fetchone()
        if r is None:raise PeerConflict("Goodput request not found")
        return r

    def goodput_active(self,c,r,state,now):
        from .peer_coordination import PeerConflict
        if r["state"]!=state or r["finished"] is not None or not r["created"]<=now<r["deadline"]:
            raise PeerConflict("Goodput request not active")
        p=ThroughputPlan.model_validate_json(r["plan"])
        if not self.goodput_fresh(c,p.policy,now):raise PeerConflict("Goodput claim stale")
        return p

    def goodput_offer(self,credential):
        self.goodput_session_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential)
            now=self.goodput_now(c);self.expire(c)
            r=c.execute("""SELECT * FROM goodput_requests WHERE finished IS NULL AND
                ((destination_id=? AND state='queued') OR (source_id=? AND state='ready'))""",(agent,agent)).fetchone()
            if r is None:return {"offer":None}
            p=ThroughputPlan.model_validate_json(r["plan"])
            if not self.goodput_fresh(c,p.policy,now):return {"offer":None}
            return {"offer":{"id":r["id"],"role":"receiver" if r["destination_id"]==agent else "source"}}

    def goodput_prepare(self,credential,id):
        from .peer_coordination import PeerConflict
        self.goodput_session_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential)
            now=self.goodput_now(c);self.expire(c);r=self.goodput_row(c,id)
            if r["destination_id"]!=agent:raise PeerConflict("Wrong receiver")
            p=self.goodput_active(c,r,"queued",now)
            lease=secrets.token_urlsafe(32);until=min(r["deadline"],now+PREPARE_SECONDS)
            c.execute("""UPDATE goodput_requests SET state='preparing',receiver_lease=?,deadline=?,quarantine_until=?
                WHERE id=?""",(lease_hash(lease),until,until+QUARANTINE_SECONDS,id))
            return {"plan":p.model_dump(mode="json"),"lease":lease,"deadline":until}

    def goodput_ready(self,credential,id,lease,grant):
        from .peer_coordination import PeerConflict
        self.goodput_session_gate()
        if not valid_token(grant):raise PeerConflict("Invalid grant")
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential)
            now=self.goodput_now(c);self.expire(c);r=self.goodput_row(c,id)
            if r["destination_id"]!=agent or r["receiver_lease"]!=lease_hash(lease):
                raise PeerConflict("Wrong receiver lease")
            self.goodput_active(c,r,"preparing",now)
            until=min(r["deadline"],now+READY_SECONDS)
            c.execute("UPDATE goodput_requests SET state='ready',deadline=? WHERE id=?",(until,id))
            self.goodput_handoffs[id]=grant
            return {"deadline":until}

    def goodput_start(self,credential,id):
        from .peer_coordination import PeerConflict
        self.goodput_session_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential)
            now=self.goodput_now(c);self.expire(c);r=self.goodput_row(c,id)
            if r["source_id"]!=agent:raise PeerConflict("Wrong source")
            p=self.goodput_active(c,r,"ready",now)
            grant=self.goodput_handoffs.pop(id,None)
            if grant is None:
                c.execute("UPDATE goodput_requests SET state='interrupted',finished=? WHERE id=?",(now,id))
                return {"state":"interrupted"}
            lease=secrets.token_urlsafe(32)
            c.execute("UPDATE goodput_requests SET state='running',source_lease=? WHERE id=?",(lease_hash(lease),id))
            return {"plan":p.model_dump(mode="json"),"lease":lease,"grant":grant,"deadline":r["deadline"]}

    def goodput_role(self,r,agent,lease):
        from .peer_coordination import PeerConflict
        role="receiver" if r["destination_id"]==agent else "source" if r["source_id"]==agent else None
        if role is None or r[role+"_lease"]!=lease_hash(lease):raise PeerConflict("Wrong goodput lease")
        return role

    def goodput_status(self,credential,id,lease):
        self.goodput_session_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential)
            now=self.goodput_now(c);self.expire(c);r=self.goodput_row(c,id)
            self.goodput_role(r,agent,lease)
            p=ThroughputPlan.model_validate_json(r["plan"])
            active=(r["finished"] is None and r["state"] in ("preparing","ready","running")
                and r["created"]<=now<r["deadline"] and self.goodput_fresh(c,p.policy,now))
            return {"active":active,"state":r["state"]}

    def goodput_finish(self,credential,id,lease,report):
        from .peer_coordination import PeerConflict
        self.goodput_session_gate()
        report=ThroughputReport.model_validate(report.model_dump(mode="json"))
        value=canonical(report.model_dump(mode="json"))
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential)
            now=self.goodput_now(c);self.expire(c);r=self.goodput_row(c,id)
            role=self.goodput_role(r,agent,lease);column=role+"_report"
            if r[column] is not None:
                if r[column]!=value:raise PeerConflict("Conflicting goodput result replay")
                return {"duplicate":True,"state":r["state"]}
            p=self.goodput_active(c,r,"running",now)
            if report.plan!=p:raise PeerConflict("Goodput plan mismatch")
            c.execute("UPDATE goodput_requests SET "+column+"=? WHERE id=?",(value,id))
            r=self.goodput_row(c,id)
            if r["source_report"] is None or r["receiver_report"] is None:
                return {"duplicate":False,"state":"running"}
            matched=r["source_report"]==r["receiver_report"]
            d=p.direction;summary=report.summary()
            metrics=(Measurement(name="offered_rate",unit="bit/s",value=float(p.policy.rate_bps)),
                Measurement(name="received_bytes",unit="bytes",value=float(report.received_bytes) if matched else None),
                Measurement(name="receiver_elapsed",unit="ms",value=report.receiver_elapsed_us/1000 if matched else None),
                Measurement(name="application_goodput",unit="bit/s",value=summary["application_goodput_bps"] if matched else None))
            record=Observation(source_kind="agent",source_id=id,source_revision=1,source_part="peer-goodput-v1",
                run_id=id,vantage_id="agent:"+d.source_agent_id,observed_at=None,
                target_id=digest(d.model_dump(mode="json")),profile_revision=key(p.policy),
                probe_kind="throughput",outcome="success" if matched else "unknown",provenance="agent_claim",
                measurements=metrics,protocol="tcp",family="ipv4" if ipaddress.ip_address(d.destination_ip).version==4 else "ipv6",
                error_code=None if matched else "peer_result_inconsistent",
                limitations=("agent_claim_not_attested","remote_observation_time_unavailable","paced_application_goodput",
                    "no_link_capacity_inference","wire_overhead_not_measured"))
            if c.execute("SELECT count(*) FROM agent_evidence_outbox").fetchone()[0]>=self.max_evidence_pending:
                c.execute("""UPDATE agent_evidence_coverage SET dropped_tasks=dropped_tasks+1,
                    dropped_observations=dropped_observations+1,first_dropped_at=coalesce(first_dropped_at,?),last_dropped_at=?
                    WHERE singleton=1""",(now,now))
            else:c.execute("INSERT INTO agent_evidence_outbox(payload) VALUES(?)",(encode((record,)),))
            state="completed" if matched else "inconsistent"
            # Both authenticated roles have reported, but cancellation/expiry
            # retains quarantine; mismatched claims also keep the reservation.
            c.execute("UPDATE goodput_requests SET state=?,finished=?,quarantine_until=? WHERE id=?",
                (state,now,r["quarantine_until"],id))
            return {"duplicate":False,"state":state}

    def goodput_detail(self,id):
        self.goodput_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");self.expire(c);r=dict(self.goodput_row(c,id))
            for k in ("receiver_lease","source_lease"):r.pop(k)
            for k in ("plan","receiver_report","source_report"):
                r[k]=json.loads(r[k]) if r[k] is not None else None
            return r
