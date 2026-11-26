"""Durable directional coordination and volatile grant relay.
The controller records claims, not proof of local policy or transport execution.
"""
import hashlib
import ipaddress
import json
import secrets
from .peer_contract import RTTPlan,RTTReport,PeerDirection
from .peer_throughput import ThroughputPlan,ThroughputReport,ThroughputPolicy
from pydantic import TypeAdapter
from .evidence import canonical,digest,Observation,Measurement
from .agent_evidence import encode

ACTIVE=("queued","preparing","ready","running")
MAX_HISTORY=2048
CLAIM_TTL=45
PREPARE_SECONDS=20
READY_SECONDS=15
QUEUE_SECONDS=120
RETENTION=30*86400
TRANSFER_WINDOW=60
TRANSFER_AGENT_BYTES=16*1024*1024
TRANSFER_GLOBAL_BYTES=32*1024*1024
PLAN=TypeAdapter(RTTPlan|ThroughputPlan)
TRANSFER_SCHEMA="""
CREATE TABLE peer_transfers(
    id TEXT PRIMARY KEY REFERENCES peer_requests(id) ON DELETE CASCADE,
    byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 65536 AND 4194304),
    receiver_report TEXT);
"""

SCHEMA="""
CREATE TABLE peer_claims(
    agent_id TEXT NOT NULL REFERENCES agents(id),
    direction_key TEXT NOT NULL,reported_at REAL NOT NULL,
    PRIMARY KEY(agent_id,direction_key));
CREATE TABLE peer_requests(
    id TEXT PRIMARY KEY,source_id TEXT NOT NULL REFERENCES agents(id),
    destination_id TEXT NOT NULL REFERENCES agents(id),
    plan TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,
    deadline REAL NOT NULL,finished REAL,receiver_lease TEXT,source_lease TEXT,
    source_report TEXT,receiver_echoes INTEGER,outcome TEXT,
    CHECK(source_id<>destination_id));
CREATE INDEX peer_source ON peer_requests(source_id,state);
CREATE INDEX peer_destination ON peer_requests(destination_id,state);
"""

class PeerConflict(RuntimeError):pass

def hash_lease(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()

def direction_key(d):
    return digest(d.model_dump(mode="json"))

def claim_key(plan):
    if isinstance(plan,ThroughputPlan):
        return digest({"method":plan.method,"policy":plan.policy.model_dump(mode="json")})
    return direction_key(plan.direction)

class PeerCoordination:
    # Disabled by default; explicit controller opt-in required.
    peer_enabled=False
    # Independent feature gate; runtime integration is a later increment.
    throughput_enabled=False

    def peer_reserved(self,c,id):
        return bool(c.execute("""SELECT 1 FROM peer_requests WHERE
            (source_id=? OR destination_id=?) AND finished IS NULL LIMIT 1""",(id,id)).fetchone())

    def peer_expire(self,c,now):
        c.execute("""UPDATE peer_requests SET state='interrupted',outcome='unknown',finished=?
            WHERE finished IS NULL AND (deadline<=? OR created>?)""",(now,now,now))
        c.execute("DELETE FROM peer_requests WHERE finished IS NOT NULL AND finished<?",(now-RETENTION,))
        c.execute("DELETE FROM peer_claims WHERE reported_at<=? OR reported_at>?",(now-CLAIM_TTL,now))
        for id in tuple(self.peer_handoffs):
            if not c.execute("SELECT 1 FROM peer_requests WHERE id=? AND state='ready' AND deadline>?",(id,now)).fetchone():
                self.peer_handoffs.pop(id,None)

    def peer_invalidate(self,c,id):
        for r in c.execute("SELECT id FROM peer_requests WHERE finished IS NULL AND (source_id=? OR destination_id=?)",(id,id)):
            self.peer_handoffs.pop(r[0],None)
        c.execute("DELETE FROM peer_claims WHERE agent_id=?",(id,))
        c.execute("""UPDATE peer_requests SET state='cancelled',outcome='unknown',finished=?
            WHERE finished IS NULL AND (source_id=? OR destination_id=?)""",(self.clock(),id,id))

    def peer_gate(self):
        if not self.peer_enabled:raise PeerConflict("Peer coordination disabled")

    def peer_report_claims(self,credential,directions,policies=()):
        self.peer_gate()
        if len(directions)+len(policies)>64:raise ValueError("Too many peer policies")
        if policies and not self.throughput_enabled:raise PeerConflict("Throughput disabled")
        ds=[PeerDirection.model_validate(d.model_dump(mode="json")) for d in directions]
        ps=[ThroughputPolicy.model_validate(p.model_dump(mode="json")) for p in policies]
        keys={direction_key(d) for d in ds}
        keys.update(digest({"method":"tls-paced-goodput-v1","policy":p.model_dump(mode="json")}) for p in ps)
        if len(keys)!=len(ds)+len(ps):raise ValueError("Duplicate policy")
        ds.extend(p.direction for p in ps)
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            id=self.identity(c,credential);self.expire(c)
            if any(id not in (d.source_agent_id,d.destination_agent_id) for d in ds):
                raise PeerConflict("Unrelated direction")
            # A withdrawn approval invalidates pending/active work. Refreshing
            # unchanged claims does not extend a request deadline.
            for r in c.execute("SELECT id,plan FROM peer_requests WHERE finished IS NULL AND (source_id=? OR destination_id=?)",(id,id)).fetchall():
                if claim_key(PLAN.validate_json(r["plan"])) not in keys:
                    c.execute("UPDATE peer_requests SET state='cancelled',outcome='unknown',finished=? WHERE id=?",(self.clock(),r["id"]))
                    self.peer_handoffs.pop(r["id"],None)
            c.execute("DELETE FROM peer_claims WHERE agent_id=?",(id,))
            c.executemany("INSERT INTO peer_claims VALUES(?,?,?)",[(id,k,self.clock()) for k in keys])

    def peer_fresh(self,c,plan):
        d=plan.direction
        if isinstance(plan,ThroughputPlan) and not self.throughput_enabled:return False
        now=self.clock()
        for id in (d.source_agent_id,d.destination_agent_id):
            r=c.execute("""SELECT p.reported_at FROM peer_claims p JOIN agents a ON a.id=p.agent_id
                WHERE p.agent_id=? AND p.direction_key=? AND a.revoked=0 AND a.credential IS NOT NULL""",(id,claim_key(plan))).fetchone()
            if not r or not 0<=now-r[0]<CLAIM_TTL:return False
        return True

    def peer_admit(self,plan):
        self.peer_gate()
        plan=PLAN.validate_python(plan.model_dump(mode="json"))
        if isinstance(plan,ThroughputPlan) and not self.throughput_enabled:raise PeerConflict("Throughput disabled")
        encoded=canonical(plan.model_dump(mode="json"));d=plan.direction
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");self.expire(c)
            existing=c.execute("SELECT plan FROM peer_requests WHERE id=?",(plan.request_id,)).fetchone()
            if existing:
                if existing[0]!=encoded:raise PeerConflict("Request ID conflict")
                return {"id":plan.request_id,"duplicate":True}
            if not self.peer_fresh(c,plan):raise PeerConflict("Fresh matching directional claims required")
            if c.execute("SELECT count(*) FROM peer_requests").fetchone()[0]>=MAX_HISTORY:
                raise PeerConflict("Peer history capacity")
            for id in (d.source_agent_id,d.destination_agent_id):
                if self.peer_reserved(c,id) or c.execute("SELECT 1 FROM tasks WHERE agent_id=? AND state IN ('queued','leased')",(id,)).fetchone():
                    raise PeerConflict("Agent busy")
            now=self.clock()
            if isinstance(plan,ThroughputPlan):
                self.transfer_budget(c,plan,now)
            c.execute("""INSERT INTO peer_requests(id,source_id,destination_id,plan,state,created,deadline)
                VALUES(?,?,?,?,'queued',?,?)""",(plan.request_id,d.source_agent_id,d.destination_agent_id,encoded,now,now+QUEUE_SECONDS))
            if isinstance(plan,ThroughputPlan):
                c.execute("INSERT INTO peer_transfers(id,byte_count) VALUES(?,?)",(plan.request_id,plan.policy.byte_count))
            return {"id":plan.request_id,"duplicate":False}

    def transfer_budget(self,c,plan,now):
        # Count the full reserved volume even for cancellations, failures and
        # lost receipts. Retain it for 60s after the original deadline or finish,
        # whichever is later. Queued transfers count until terminal.
        rows=c.execute("""SELECT p.source_id,p.destination_id,p.finished,t.byte_count
            FROM peer_transfers t JOIN peer_requests p ON p.id=t.id
            WHERE p.finished IS NULL OR max(p.deadline,p.finished)>?""",(now-TRANSFER_WINDOW,)).fetchall()
        if any(r["finished"] is None for r in rows):raise PeerConflict("Another transfer is active")
        n=plan.policy.byte_count
        if sum(r["byte_count"] for r in rows)+n>TRANSFER_GLOBAL_BYTES:raise PeerConflict("Global transfer budget")
        for id in (plan.direction.source_agent_id,plan.direction.destination_agent_id):
            if sum(r["byte_count"] for r in rows if id in (r["source_id"],r["destination_id"]))+n>TRANSFER_AGENT_BYTES:
                raise PeerConflict("Agent transfer budget")

    def peer_row(self,c,id):
        r=c.execute("SELECT * FROM peer_requests WHERE id=?",(id,)).fetchone()
        if not r:raise PeerConflict("Peer request not found")
        return r

    def peer_active(self,c,r,state):
        if r["state"]!=state or r["finished"] is not None or not r["created"]<=self.clock()<r["deadline"]:
            raise PeerConflict("Peer request not active")
        p=PLAN.validate_json(r["plan"])
        if not self.peer_fresh(c,p):raise PeerConflict("Directional claim stale")
        return p

    def peer_prepare(self,credential,id):
        self.peer_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential);self.expire(c)
            r=self.peer_row(c,id)
            if r["destination_id"]!=agent:raise PeerConflict("Wrong receiver")
            plan=self.peer_active(c,r,"queued")
            lease=secrets.token_urlsafe(32);until=min(r["deadline"],self.clock()+PREPARE_SECONDS)
            c.execute("UPDATE peer_requests SET state='preparing',receiver_lease=?,deadline=? WHERE id=?",(hash_lease(lease),until,id))
            return {"plan":plan.model_dump(mode="json"),"lease":lease,"deadline":until}

    def peer_ready(self,credential,id,lease,grant=None):
        self.peer_gate()
        if grant is not None and (not isinstance(grant,str) or len(grant)!=43 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in grant)):
            raise ValueError("Invalid grant")
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential);self.expire(c)
            r=self.peer_row(c,id)
            if r["destination_id"]!=agent or r["receiver_lease"]!=hash_lease(lease):raise PeerConflict("Wrong receiver lease")
            self.peer_active(c,r,"preparing")
            until=min(r["deadline"],self.clock()+READY_SECONDS)
            c.execute("UPDATE peer_requests SET state='ready',deadline=? WHERE id=?",(until,id))
            if grant is not None:self.peer_handoffs[id]=grant
            return {"deadline":until}

    def peer_start(self,credential,id,require_grant=False):
        self.peer_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential);self.expire(c)
            r=self.peer_row(c,id)
            if r["source_id"]!=agent:raise PeerConflict("Wrong source")
            plan=self.peer_active(c,r,"ready")
            grant=self.peer_handoffs.pop(id,None)
            if require_grant and grant is None:
                c.execute("UPDATE peer_requests SET state='interrupted',outcome='unknown',finished=? WHERE id=?",(self.clock(),id))
                return {"state":"interrupted"}
            lease=secrets.token_urlsafe(32)
            # A lost response is ambiguous; never reissue a source lease.
            c.execute("UPDATE peer_requests SET state='running',source_lease=? WHERE id=?",(hash_lease(lease),id))
            reply={"plan":plan.model_dump(mode="json"),"lease":lease,"deadline":r["deadline"]}
            if require_grant:reply["grant"]=grant
            return reply

    def peer_offer(self,credential):
        self.peer_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential);self.expire(c)
            r=c.execute("""SELECT * FROM peer_requests WHERE finished IS NULL AND
                ((destination_id=? AND state='queued') OR (source_id=? AND state='ready'))""",(agent,agent)).fetchone()
            if not r:return {"offer":None}
            plan=PLAN.validate_json(r["plan"])
            if not self.peer_fresh(c,plan):return {"offer":None}
            return {"offer":{"id":r["id"],"role":"receiver" if r["destination_id"]==agent else "source"}}

    def peer_status(self,credential,id,lease):
        self.peer_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential);self.expire(c)
            r=self.peer_row(c,id)
            key="receiver_lease" if r["destination_id"]==agent else "source_lease" if r["source_id"]==agent else None
            if key is None or r[key]!=hash_lease(lease):raise PeerConflict("Wrong status lease")
            p=PLAN.validate_json(r["plan"])
            active=r["finished"] is None and r["created"]<=self.clock()<r["deadline"] and self.peer_fresh(c,p)
            return {"active":active,"state":r["state"]}

    def peer_finish(self,credential,id,lease,*,report=None,echoes=None):
        self.peer_gate()
        if (report is None)==(echoes is None):raise ValueError("Exactly one role result required")
        if report is not None:
            report=RTTReport.model_validate(report.model_dump(mode="json"))
            value=canonical(report.model_dump(mode="json"));column="source_report";role="source"
        else:
            if type(echoes) is not int or not 0<=echoes<=5:raise ValueError("Invalid receiver count")
            value=echoes;column="receiver_echoes";role="destination"
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential);self.expire(c)
            r=self.peer_row(c,id)
            lease_col="source_lease" if role=="source" else "receiver_lease"
            if r[role+"_id"]!=agent or r[lease_col]!=hash_lease(lease):raise PeerConflict("Wrong result lease")
            if r[column] is not None:
                if r[column]!=value:raise PeerConflict("Conflicting result replay")
                return {"duplicate":True,"state":r["state"]}
            p=self.peer_active(c,r,"running")
            if not isinstance(p,RTTPlan):raise PeerConflict("Wrong result method")
            if report is not None and report.plan!=p:raise PeerConflict("Report plan mismatch")
            if echoes is not None and echoes>p.samples:raise PeerConflict("Receiver count outside plan")
            # Column names come from fixed role branches, never caller input.
            c.execute("UPDATE peer_requests SET "+column+"=? WHERE id=?",(value,id))
            r=self.peer_row(c,id)
            if r["source_report"] is None or r["receiver_echoes"] is None:
                return {"duplicate":False,"state":"running"}
            src=RTTReport.model_validate_json(r["source_report"])
            summary=src.summary();n=summary["echoes"]
            matched=n==r["receiver_echoes"]
            outcome=("success" if n==p.samples else "partial" if n else "unknown") if matched else "unknown"
            state="completed" if matched else "inconsistent"
            now=self.clock();d=p.direction
            metrics=tuple(Measurement(name="peer_echo_"+str(s.index)+"_rtt",unit="ms",value=s.rtt_ms)
                for s in src.samples if matched and s.status=="echo")
            metrics+=(Measurement(name="requested_echoes",unit="count",value=float(p.samples)),
                Measurement(name="matched_echoes",unit="count",value=float(n) if matched else None))
            record=Observation(source_kind="agent",source_id=id,source_revision=1,source_part="peer-rtt-v1",
                run_id=id,vantage_id="agent:"+d.source_agent_id,observed_at=None,target_id=direction_key(d),
                profile_revision=digest({"method":p.method,"samples":p.samples}),probe_kind="tcp",
                outcome=outcome,provenance="agent_claim",measurements=metrics,protocol="tcp",
                family="ipv4" if ipaddress.ip_address(d.destination_ip).version==4 else "ipv6",
                error_code=None if matched and n else "peer_result_inconsistent" if not matched else "peer_echo_unknown",
                limitations=("agent_claim_not_attested","remote_observation_time_unavailable","tls_application_echo_rtt",
                "no_one_way_latency","no_packet_loss_inference"))
            if c.execute("SELECT count(*) FROM agent_evidence_outbox").fetchone()[0]>=self.max_evidence_pending:
                c.execute("""UPDATE agent_evidence_coverage SET dropped_tasks=dropped_tasks+1,
                    dropped_observations=dropped_observations+1,first_dropped_at=coalesce(first_dropped_at,?),last_dropped_at=?
                    WHERE singleton=1""",(now,now))
            else:c.execute("INSERT INTO agent_evidence_outbox(payload) VALUES(?)",(encode((record,)),))
            c.execute("UPDATE peer_requests SET state=?,outcome=?,finished=? WHERE id=?",(state,outcome,now,id))
            return {"duplicate":False,"state":state}

    def peer_finish_transfer(self,credential,id,lease,report,*,receiver=False):
        self.peer_gate()
        if not self.throughput_enabled:raise PeerConflict("Throughput disabled")
        report=ThroughputReport.model_validate(report.model_dump(mode="json"))
        value=canonical(report.model_dump(mode="json"))
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");agent=self.identity(c,credential);self.expire(c)
            r=self.peer_row(c,id)
            role="destination" if receiver else "source"
            key="receiver_lease" if receiver else "source_lease"
            if r[role+"_id"]!=agent or r[key]!=hash_lease(lease):raise PeerConflict("Wrong result lease")
            t=c.execute("SELECT * FROM peer_transfers WHERE id=?",(id,)).fetchone()
            if not t:raise PeerConflict("Wrong result method")
            previous=t["receiver_report"] if receiver else r["source_report"]
            if previous is not None:
                if previous!=value:raise PeerConflict("Conflicting result replay")
                return {"duplicate":True,"state":r["state"]}
            p=self.peer_active(c,r,"running")
            if not isinstance(p,ThroughputPlan) or report.plan!=p:raise PeerConflict("Report plan mismatch")
            if receiver:c.execute("UPDATE peer_transfers SET receiver_report=? WHERE id=?",(value,id))
            else:c.execute("UPDATE peer_requests SET source_report=? WHERE id=?",(value,id))
            source=c.execute("SELECT source_report FROM peer_requests WHERE id=?",(id,)).fetchone()[0]
            dest=c.execute("SELECT receiver_report FROM peer_transfers WHERE id=?",(id,)).fetchone()[0]
            if source is None or dest is None:return {"duplicate":False,"state":"running"}
            matched=source==dest
            now=self.clock();d=p.direction
            metrics=(Measurement(name="offered_rate",unit="bit/s",value=float(p.policy.rate_bps)),
                Measurement(name="planned_bytes",unit="bytes",value=float(p.policy.byte_count)))
            if matched:
                metrics+=(Measurement(name="received_bytes",unit="bytes",value=float(report.received_bytes)),
                    Measurement(name="receiver_elapsed",unit="ms",value=report.receiver_elapsed_us/1000),
                    Measurement(name="application_goodput",unit="bit/s",value=report.summary()["application_goodput_bps"]))
            record=Observation(source_kind="agent",source_id=id,source_revision=1,source_part="peer-goodput-v1",
                run_id=id,vantage_id="agent:"+d.source_agent_id,observed_at=None,target_id=direction_key(d),
                profile_revision=claim_key(p),probe_kind="throughput",outcome="success" if matched else "unknown",
                provenance="agent_claim",measurements=metrics,protocol="tcp",
                family="ipv4" if ipaddress.ip_address(d.destination_ip).version==4 else "ipv6",
                error_code=None if matched else "peer_result_inconsistent",
                limitations=("agent_claim_not_attested","remote_observation_time_unavailable",
                    "paced_application_goodput","not_link_capacity","payload_bytes_only"))
            if c.execute("SELECT count(*) FROM agent_evidence_outbox").fetchone()[0]>=self.max_evidence_pending:
                c.execute("""UPDATE agent_evidence_coverage SET dropped_tasks=dropped_tasks+1,
                    dropped_observations=dropped_observations+1,first_dropped_at=coalesce(first_dropped_at,?),last_dropped_at=?
                    WHERE singleton=1""",(now,now))
            else:c.execute("INSERT INTO agent_evidence_outbox(payload) VALUES(?)",(encode((record,)),))
            state="completed" if matched else "inconsistent"
            c.execute("UPDATE peer_requests SET state=?,outcome=?,finished=? WHERE id=?",
                (state,"success" if matched else "unknown",now,id))
            return {"duplicate":False,"state":state}

    def peer_detail(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");self.expire(c);r=dict(self.peer_row(c,id))
            for key in ("receiver_lease","source_lease"):r.pop(key)
            r["plan"]=json.loads(r["plan"])
            r["source_report"]=json.loads(r["source_report"]) if r["source_report"] else None
            t=c.execute("SELECT receiver_report FROM peer_transfers WHERE id=?",(id,)).fetchone()
            if t:r["receiver_report"]=json.loads(t[0]) if t[0] else None
            return r

    def peer_list(self):
        self.peer_gate()
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");self.expire(c)
            return [dict(r) for r in c.execute("SELECT id,source_id,destination_id,state,created,deadline,finished,outcome FROM peer_requests ORDER BY created DESC,id DESC LIMIT 200")]

    def peer_cancel(self,id):
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE");self.expire(c);r=self.peer_row(c,id)
            if r["finished"] is not None:return False
            self.peer_handoffs.pop(id,None)
            c.execute("UPDATE peer_requests SET state='cancelled',outcome='unknown',finished=? WHERE id=?",(self.clock(),id))
            return True
