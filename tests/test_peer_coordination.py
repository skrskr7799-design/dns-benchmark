import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from backend.ndc.agent_store import AgentStore,AgentError
from backend.ndc.agent_contract import AgentRun,PollV2
from backend.ndc.peer_contract import PeerDirection,RTTPlan,RTTReport,RTTSample
from backend.ndc.peer_coordination import PeerConflict
from backend.ndc.agent_evidence import decode

class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.path=Path(t.name)/"agents.sqlite";self.now=100000.
        self.s=AgentStore(self.path,lambda:self.now);self.s.initialize()
        self.a=self.s.enroll(self.s.invite("source","site")["token"])
        self.b=self.s.enroll(self.s.invite("receiver","site")["token"])
        self.d=PeerDirection(source_agent_id=self.a["id"],destination_agent_id=self.b["id"],
            source_ip="127.0.0.1",destination_ip="127.0.0.2",port=8443,source_certificate="1"*64,destination_certificate="2"*64)
        self.p=RTTPlan(request_id="a"*32,direction=self.d,samples=3)
    def claims(self):
        self.s.peer_enabled=True
        for n in (self.a,self.b):self.s.peer_report_claims(n["credential"],[self.d])
    def admit(self):
        self.claims();return self.s.peer_admit(self.p)
    def prepare(self):
        return self.s.peer_prepare(self.b["credential"],self.p.request_id)["lease"]
    def ready(self,lease):
        return self.s.peer_ready(self.b["credential"],self.p.request_id,lease)
    def start(self):
        return self.s.peer_start(self.a["credential"],self.p.request_id)["lease"]
    def running(self):
        self.admit();r=self.prepare();self.ready(r);return r,self.start()
    def report(self,n=3):
        return RTTReport(plan=self.p,samples=[RTTSample(index=i+1,status="echo",rtt_ms=float(i+1)) for i in range(n)])
    def test_default_gate_and_atomic_reservation(self):
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.p)
        self.s.peer_enabled=True
        self.s.peer_report_claims(self.a["credential"],[self.d])
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.p)
        self.claims()
        with ThreadPoolExecutor(max_workers=2) as pool:
            result=list(pool.map(lambda _:self.s.peer_admit(self.p),range(2)))
        self.assertEqual(sum(not x["duplicate"] for x in result),1)
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.p.model_copy(update={"request_id":"b"*32}))
        cfg=AgentRun(endpoints=["udp://127.0.0.1"])
        for _ in range(3):self.s.enqueue(self.a["id"],cfg)
        with self.assertRaises(AgentError):self.s.enqueue(self.a["id"],cfg)
        self.assertIsNone(self.s.poll_v2(self.a["credential"],PollV2(version="2",engine="python-network-v2",capabilities=["dns"]))["task"])
        self.s.peer_cancel(self.p.request_id)
        self.assertIsNotNone(self.s.poll_v2(self.a["credential"],PollV2(version="2",engine="python-network-v2",capabilities=["dns"]))["task"])
    def test_roles_and_no_lease_reissue(self):
        self.admit()
        with self.assertRaises(PeerConflict):self.start()
        with self.assertRaises(PeerConflict):self.s.peer_prepare(self.a["credential"],self.p.request_id)
        r=self.prepare()
        with self.assertRaises(PeerConflict):self.prepare()
        with self.assertRaises(PeerConflict):self.ready("x"*43)
        self.ready(r);s=self.start()
        with self.assertRaises(PeerConflict):self.start()
        self.s=AgentStore(self.path,lambda:self.now);self.s.initialize();self.s.peer_enabled=True
        with self.assertRaises(PeerConflict):self.start()
        self.assertNotIn(s,str(self.s.peer_detail(self.p.request_id)))
        self.assertNotIn(r,str(self.s.peer_detail(self.p.request_id)))
    def test_reconciled_evidence_and_replay(self):
        r,s=self.running()
        self.assertEqual(self.s.peer_finish(self.a["credential"],self.p.request_id,s,report=self.report())["state"],"running")
        self.assertEqual(self.s.evidence_status()["pending"],0)
        self.assertEqual(self.s.peer_finish(self.b["credential"],self.p.request_id,r,echoes=3)["state"],"completed")
        self.assertTrue(self.s.peer_finish(self.a["credential"],self.p.request_id,s,report=self.report())["duplicate"])
        with self.assertRaises(PeerConflict):self.s.peer_finish(self.b["credential"],self.p.request_id,r,echoes=2)
        obs,_=decode(self.s.pending_evidence()["payload"])
        self.assertEqual((obs[0].outcome,obs[0].provenance),("success","agent_claim"))
        self.assertEqual(self.s.evidence_status()["pending"],1)
    def test_mismatch_is_unknown(self):
        r,s=self.running()
        self.s.peer_finish(self.b["credential"],self.p.request_id,r,echoes=2)
        self.s.peer_finish(self.a["credential"],self.p.request_id,s,report=self.report())
        self.assertEqual(self.s.peer_detail(self.p.request_id)["state"],"inconsistent")
        obs,_=decode(self.s.pending_evidence()["payload"])
        self.assertEqual(obs[0].outcome,"unknown")
        self.assertFalse(any(m.unit=="ms" for m in obs[0].measurements))
    def test_expiry_rotation_withdrawal(self):
        self.admit();r=self.prepare();self.now+=20
        with self.assertRaises(PeerConflict):self.ready(r)
        self.assertEqual(self.s.peer_detail(self.p.request_id)["state"],"interrupted")
        self.p=self.p.model_copy(update={"request_id":"b"*32});self.admit()
        self.s.peer_report_claims(self.a["credential"],[])
        self.assertEqual(self.s.peer_detail(self.p.request_id)["state"],"cancelled")
        self.p=self.p.model_copy(update={"request_id":"c"*32});self.admit()
        self.s.rotate(self.b["id"])
        self.assertEqual(self.s.peer_detail(self.p.request_id)["state"],"cancelled")
    def test_migration(self):
        with self.s.db() as c:
            c.execute("DROP TABLE goodput_requests");c.execute("DROP TABLE goodput_claims");c.execute("DROP TABLE goodput_clock")
            c.execute("DROP TABLE peer_requests");c.execute("DROP TABLE peer_claims");c.execute("PRAGMA user_version=3")
        self.s.initialize();self.admit()
        self.assertEqual(self.s.peer_detail(self.p.request_id)["state"],"queued")

    def goodput(self,n=1):
        from backend.ndc.peer_throughput import ThroughputPolicy,ThroughputPlan
        return ThroughputPlan(request_id=format(n,"032x"),policy=ThroughputPolicy(direction=self.d,byte_count=4194304,rate_bps=8000000))
    def goodput_claims(self):
        self.claims();self.s.goodput_enabled=True
        for n in (self.a,self.b):self.s.goodput_report_claims(n["credential"],[self.goodput().policy])
    def test_goodput_gates_reservation_and_budget(self):
        p=self.goodput()
        with self.assertRaises(PeerConflict):self.s.goodput_admit(p)
        self.claims();self.s.goodput_enabled=True
        with self.assertRaises(PeerConflict):self.s.goodput_admit(p)
        self.goodput_claims()
        with ThreadPoolExecutor(max_workers=2) as pool:
            result=list(pool.map(lambda _:self.s.goodput_admit(p),range(2)))
        self.assertEqual(sum(not x["duplicate"] for x in result),1)
        self.assertIsNone(self.s.peer_offer(self.a["credential"])["offer"])
        self.assertIsNone(self.s.peer_offer(self.b["credential"])["offer"])
        self.assertIsNone(self.s.poll_v2(self.a["credential"],PollV2(version="2",engine="python-network-v2",capabilities=["dns"]))["task"])
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.p)
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.p.model_copy(update={"request_id":p.request_id}))
        self.assertTrue(self.s.goodput_cancel(p.request_id))
        for i in range(2,5):
            q=self.goodput(i);self.s.goodput_admit(q);self.s.goodput_cancel(q.request_id)
        with self.assertRaises(PeerConflict):self.s.goodput_admit(self.goodput(5))
        self.s=AgentStore(self.path,lambda:self.now);self.s.initialize();self.goodput_claims()
        with self.assertRaises(PeerConflict):self.s.goodput_admit(self.goodput(5))
        self.now-=1
        with self.assertRaises(PeerConflict):self.s.goodput_admit(self.goodput(5))
        self.now+=61;self.goodput_claims();self.s.goodput_admit(self.goodput(5))
        self.s.goodput_report_claims(self.b["credential"],[])
        with self.s.db() as c:
            self.assertEqual(c.execute("SELECT state FROM goodput_requests WHERE id=?",(self.goodput(5).request_id,)).fetchone()[0],"cancelled")
        self.assertEqual(self.s.evidence_status()["pending"],0)

    def test_goodput_reservation_blocks_real_queued_task_and_rtt(self):
        self.goodput_claims();p=self.goodput()
        self.s.peer_admit(self.p)
        with self.assertRaises(PeerConflict):self.s.goodput_admit(p)
        self.s.peer_cancel(self.p.request_id)
        self.s.goodput_admit(p)
        cfg=AgentRun(endpoints=["udp://127.0.0.1"])
        self.s.enqueue(self.a["id"],cfg)
        heartbeat=PollV2(version="2",engine="python-network-v2",capabilities=["dns"])
        self.assertIsNone(self.s.poll_v2(self.a["credential"],heartbeat)["task"])
        self.s.goodput_cancel(p.request_id)
        self.assertIsNotNone(self.s.poll_v2(self.a["credential"],heartbeat)["task"])

    def test_goodput_clock_highwater_in_other_expiry_paths(self):
        self.goodput_claims();p=self.goodput()
        self.s.goodput_admit(p);self.s.goodput_cancel(p.request_id)
        self.now+=120
        self.s.poll_v2(self.a["credential"],PollV2(version="2",engine="python-network-v2",capabilities=["dns"]))
        self.now-=60
        with self.assertRaises(PeerConflict):self.s.goodput_report_claims(self.a["credential"],[p.policy])

    def test_goodput_global_budget_and_migration(self):
        from backend.ndc.peer_throughput import ThroughputPolicy,ThroughputPlan
        with self.s.db() as c:
            c.execute("DROP TABLE goodput_requests");c.execute("DROP TABLE goodput_claims");c.execute("DROP TABLE goodput_clock");c.execute("PRAGMA user_version=4")
        self.s.initialize();self.goodput_claims()
        pairs=[]
        for i in range(5):
            nodes=[self.s.enroll(self.s.invite("node"+str(i)+str(j),"site")["token"]) for j in range(2)]
            d=self.d.model_copy(update={"source_agent_id":nodes[0]["id"],"destination_agent_id":nodes[1]["id"]})
            policy=ThroughputPolicy(direction=d,byte_count=4194304,rate_bps=8000000)
            for n in nodes:self.s.goodput_report_claims(n["credential"],[policy])
            pairs.append((policy,nodes))
        def plan(i,j):return ThroughputPlan(request_id=format(100+i*10+j,"032x"),policy=pairs[i][0])
        for i in range(4):self.s.goodput_admit(plan(i,0))
        with self.assertRaises(PeerConflict):self.s.goodput_admit(plan(4,0))
        for i in range(4):self.s.goodput_cancel(plan(i,0).request_id)
        for i in range(4):self.s.goodput_admit(plan(i,1));self.s.goodput_cancel(plan(i,1).request_id)
        with self.assertRaises(PeerConflict):self.s.goodput_admit(plan(4,1))
        self.now+=60
        for policy,nodes in pairs:
            for n in nodes:self.s.goodput_report_claims(n["credential"],[policy])
        self.s.goodput_admit(plan(4,1))
        self.s.rotate(pairs[4][1][0]["id"])
        with self.s.db() as c:
            self.assertEqual(c.execute("SELECT state FROM goodput_requests WHERE id=?",(plan(4,1).request_id,)).fetchone()[0],"cancelled")

    def goodput_running(self):
        self.goodput_claims();self.s.goodput_session_enabled=True;p=self.goodput()
        self.s.goodput_admit(p)
        self.assertEqual(self.s.goodput_offer(self.b["credential"])["offer"]["role"],"receiver")
        r=self.s.goodput_prepare(self.b["credential"],p.request_id)["lease"]
        with self.assertRaises(PeerConflict):self.s.goodput_prepare(self.b["credential"],p.request_id)
        self.s.goodput_ready(self.b["credential"],p.request_id,r,"G"*43)
        with self.assertRaises(PeerConflict):self.s.goodput_start(self.b["credential"],p.request_id)
        reply=self.s.goodput_start(self.a["credential"],p.request_id)
        self.assertEqual(reply["grant"],"G"*43)
        with self.assertRaises(PeerConflict):self.s.goodput_start(self.a["credential"],p.request_id)
        return p,r,reply["lease"]

    def goodput_report(self,p,digest="f"*64):
        from backend.ndc.peer_throughput import ThroughputReport
        return ThroughputReport(plan=p,received_bytes=p.policy.byte_count,receiver_elapsed_us=5000000,payload_sha256=digest)

    def test_goodput_session_dual_receipt_and_idempotence(self):
        p,r,s=self.goodput_running();report=self.goodput_report(p)
        self.assertTrue(self.s.goodput_status(self.a["credential"],p.request_id,s)["active"])
        with self.assertRaises(PeerConflict):self.s.goodput_finish(self.b["credential"],p.request_id,s,report)
        self.assertEqual(self.s.goodput_finish(self.a["credential"],p.request_id,s,report)["state"],"running")
        self.assertEqual(self.s.evidence_status()["pending"],0)
        self.assertEqual(self.s.goodput_finish(self.b["credential"],p.request_id,r,report)["state"],"completed")
        self.assertTrue(self.s.goodput_finish(self.a["credential"],p.request_id,s,report)["duplicate"])
        with self.assertRaises(PeerConflict):self.s.goodput_finish(self.a["credential"],p.request_id,s,self.goodput_report(p,"e"*64))
        obs,_=decode(self.s.pending_evidence()["payload"])
        self.assertEqual((obs[0].probe_kind,obs[0].outcome,obs[0].provenance),("throughput","success","agent_claim"))
        self.assertEqual(self.s.evidence_status()["pending"],1)
        detail=str(self.s.goodput_detail(p.request_id))
        for secret in (r,s,"G"*43):self.assertNotIn(secret,detail)

    def test_goodput_mismatch_and_cancel_quarantine(self):
        p,r,s=self.goodput_running()
        self.s.goodput_finish(self.a["credential"],p.request_id,s,self.goodput_report(p))
        self.s.goodput_finish(self.b["credential"],p.request_id,r,self.goodput_report(p,"e"*64))
        self.assertEqual(self.s.goodput_detail(p.request_id)["state"],"inconsistent")
        obs,_=decode(self.s.pending_evidence()["payload"])
        self.assertEqual(obs[0].outcome,"unknown")
        self.assertIsNone(next(m.value for m in obs[0].measurements if m.name=="application_goodput"))
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.p)
        self.now+=30;self.claims();self.s.peer_admit(self.p)
        self.s.peer_cancel(self.p.request_id)
        self.goodput_claims();q=self.goodput(2);self.s.goodput_admit(q)
        lease=self.s.goodput_prepare(self.b["credential"],q.request_id)["lease"]
        self.s.goodput_cancel(q.request_id)
        self.assertFalse(self.s.goodput_status(self.b["credential"],q.request_id,lease)["active"])
        with self.assertRaises(PeerConflict):self.s.goodput_admit(self.goodput(3))

    def test_goodput_lost_grant_after_restart(self):
        self.goodput_claims();p=self.goodput();self.s.goodput_admit(p)
        with self.assertRaises(PeerConflict):self.s.goodput_prepare(self.b["credential"],p.request_id)
        self.s.goodput_session_enabled=True
        r=self.s.goodput_prepare(self.b["credential"],p.request_id)["lease"]
        self.s.goodput_ready(self.b["credential"],p.request_id,r,"G"*43)
        self.s=AgentStore(self.path,lambda:self.now);self.s.initialize()
        self.s.peer_enabled=self.s.goodput_enabled=self.s.goodput_session_enabled=True
        self.assertEqual(self.s.goodput_start(self.a["credential"],p.request_id),{"state":"interrupted"})
        with self.assertRaises(PeerConflict):self.s.goodput_start(self.a["credential"],p.request_id)
        self.assertEqual(self.s.evidence_status()["pending"],0)
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.p)

if __name__=="__main__":unittest.main()
