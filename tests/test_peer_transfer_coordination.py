import tempfile
import unittest
from pathlib import Path
from backend.ndc.agent_store import AgentStore
from backend.ndc.peer_contract import PeerDirection,RTTPlan,RTTReport
from backend.ndc.peer_throughput import ThroughputPlan,ThroughputPolicy,ThroughputReport
from backend.ndc.peer_coordination import PeerConflict
from backend.ndc.agent_evidence import decode
from backend.ndc.peer_api import Finish

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)/"agents.sqlite";self.now=100000.
        self.s=AgentStore(self.path,lambda:self.now);self.s.initialize();self.s.peer_enabled=True
        self.a=self.s.enroll(self.s.invite("source","fixture")["token"])
        self.b=self.s.enroll(self.s.invite("receiver","fixture")["token"])
        self.d=PeerDirection(source_agent_id=self.a["id"],destination_agent_id=self.b["id"],
            source_ip="127.0.0.1",destination_ip="127.0.0.2",port=8443,source_certificate="1"*64,destination_certificate="2"*64)
        self.policy=ThroughputPolicy(direction=self.d,byte_count=4194304,rate_bps=8000000)
        self.plan=ThroughputPlan(request_id="a"*32,policy=self.policy)
    def claims(self):
        self.s.throughput_enabled=True
        for n in (self.a,self.b):self.s.peer_report_claims(n["credential"],[],[self.policy])
    def run_plan(self):
        self.claims();self.s.peer_admit(self.plan)
        id=self.plan.request_id;r=self.s.peer_prepare(self.b["credential"],id)["lease"]
        self.s.peer_ready(self.b["credential"],id,r,"g"*43)
        a=self.s.peer_start(self.a["credential"],id,True)["lease"]
        return r,a
    def report(self,sha="f"*64):
        return ThroughputReport(plan=self.plan,received_bytes=self.policy.byte_count,receiver_elapsed_us=4500000,payload_sha256=sha)
    def test_separate_policy_gate(self):
        for n in (self.a,self.b):self.s.peer_report_claims(n["credential"],[self.d])
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.plan)
        self.s.throughput_enabled=True
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.plan)
        self.claims()
        with self.assertRaises(PeerConflict):self.s.peer_admit(RTTPlan(request_id="b"*32,direction=self.d))
        changed=self.plan.model_copy(update={"policy":self.policy.model_copy(update={"byte_count":65536})})
        with self.assertRaises(PeerConflict):self.s.peer_admit(changed)
        self.assertFalse(self.s.peer_admit(self.plan)["duplicate"])
        self.assertTrue(self.s.peer_admit(self.plan)["duplicate"])
    def test_matching_reports_and_role_binding(self):
        r,a=self.run_plan();id=self.plan.request_id
        with self.assertRaises(PeerConflict):self.s.peer_finish_transfer(self.a["credential"],id,a,self.report(),receiver=True)
        with self.assertRaises(PeerConflict):self.s.peer_finish(self.b["credential"],id,r,echoes=1)
        self.assertEqual(self.s.peer_finish_transfer(self.a["credential"],id,a,self.report())["state"],"running")
        self.assertEqual(self.s.evidence_status()["pending"],0)
        self.assertEqual(self.s.peer_finish_transfer(self.b["credential"],id,r,self.report(),receiver=True)["state"],"completed")
        self.assertTrue(self.s.peer_finish_transfer(self.b["credential"],id,r,self.report(),receiver=True)["duplicate"])
        obs,_=decode(self.s.pending_evidence()["payload"])
        self.assertEqual((obs[0].probe_kind,obs[0].outcome),("throughput","success"))
        self.assertIsNotNone(next(m.value for m in obs[0].measurements if m.name=="application_goodput"))
        self.assertEqual(self.s.evidence_status()["pending"],1)
        self.assertEqual(self.s.peer_detail(id)["receiver_report"]["payload_sha256"],"f"*64)
        Finish(id=id,lease=a,transfer_report=self.report())
    def test_mismatch_is_unknown(self):
        r,a=self.run_plan();id=self.plan.request_id
        self.s.peer_finish_transfer(self.a["credential"],id,a,self.report())
        self.s.peer_finish_transfer(self.b["credential"],id,r,self.report("e"*64),receiver=True)
        obs,_=decode(self.s.pending_evidence()["payload"])
        self.assertEqual(obs[0].outcome,"unknown")
        self.assertFalse(any(m.name=="application_goodput" for m in obs[0].measurements))
    def test_budget_persists_even_after_cancel(self):
        self.claims()
        for i in range(4):
            p=self.plan.model_copy(update={"request_id":format(i,"032x")})
            self.s.peer_admit(p)
            self.s.peer_cancel(p.request_id)
        self.s=AgentStore(self.path,lambda:self.now);self.s.initialize();self.s.peer_enabled=True;self.claims()
        with self.assertRaises(PeerConflict):self.s.peer_admit(self.plan)
        self.now+=181;self.claims()
        self.assertFalse(self.s.peer_admit(self.plan)["duplicate"])
    def test_only_one_active_transfer(self):
        self.claims();self.s.peer_admit(self.plan)
        c=self.s.enroll(self.s.invite("c","fixture")["token"])
        d=self.s.enroll(self.s.invite("d","fixture")["token"])
        direction=self.d.model_copy(update={"source_agent_id":c["id"],"destination_agent_id":d["id"]})
        policy=self.policy.model_copy(update={"direction":direction})
        for n in (c,d):self.s.peer_report_claims(n["credential"],[],[policy])
        with self.assertRaises(PeerConflict):self.s.peer_admit(ThroughputPlan(request_id="b"*32,policy=policy))

if __name__=="__main__":unittest.main()
