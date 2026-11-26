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
            c.execute("DROP TABLE peer_transfers")
            c.execute("DROP TABLE peer_requests");c.execute("DROP TABLE peer_claims");c.execute("PRAGMA user_version=3")
        self.s.initialize();self.admit()
        self.assertEqual(self.s.peer_detail(self.p.request_id)["state"],"queued")

if __name__=="__main__":unittest.main()
