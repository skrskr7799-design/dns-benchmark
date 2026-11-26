import tempfile
import unittest
import sqlite3
from pathlib import Path
from backend.ndc.agent_store import AgentStore,AgentError
from backend.ndc.agent_contract import PollV2,Heartbeat,AgentRun,Result
from backend.ndc.remote_contract import RemoteRequest,RemoteTCP,RemoteResult,RemoteHeartbeat,TCPObservation,config_key
from backend.ndc.agent_evidence import decode

class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.now=100000.;self.s=AgentStore(Path(t.name)/"agents.sqlite",lambda:self.now);self.s.initialize()
        self.a=self.s.enroll(self.s.invite("one","site")["token"])
        self.b=self.s.enroll(self.s.invite("two","site")["token"])
        self.cfg=RemoteTCP(host="127.0.0.1",port=443)
        self.req=RemoteRequest(request_id="a"*32,config=self.cfg)
    def poll(self,kinds=("tcp",),node=None):
        return self.s.poll_v2((node or self.a)["credential"],PollV2(version="2",engine="python-network-v2",capabilities=list(kinds)))["task"]
    def enqueue(self,req=None):
        return self.s.enqueue_remote(self.a["id"],req or self.req)
    def lease(self):
        self.s.remote_kinds=("tcp",)
        self.poll()
        self.enqueue()
        return self.poll()
    def result(self,task,**kw):
        args={"version":"2","engine":"python-network-v2","kind":"tcp","lease":task["lease"],
            "config_key":config_key(self.cfg),"status":"completed",
            "observation":{"outcome":"success","stage":"complete","address":"127.0.0.1","peer_ip":"127.0.0.1","dns_ms":1.0,"connect_ms":2.0,"total_ms":4.0}}
        return RemoteResult(**(args|kw))
    def complete(self,task,body=None,node=None):
        return self.s.complete_remote((node or self.a)["credential"],task["id"],body or self.result(task))
    def heartbeat(self,task,node=None):
        return self.s.remote_heartbeat((node or self.a)["credential"],RemoteHeartbeat(version="2",engine="python-network-v2",task_id=task["id"],lease=task["lease"]))["active"]
    def test_gate_and_freshness(self):
        self.poll()
        with self.assertRaises(AgentError):self.enqueue()
        self.s.remote_kinds=("tcp",)
        self.now+=45
        with self.assertRaises(AgentError):self.enqueue()
        self.poll(("dns",))
        with self.assertRaises(AgentError):self.enqueue()
        self.poll()
        self.assertFalse(self.enqueue()["duplicate"])
        self.assertTrue(self.enqueue()["duplicate"])
        with self.assertRaises(AgentError):self.enqueue(RemoteRequest(request_id=self.req.request_id,config=RemoteTCP(host="localhost",port=443)))
        self.assertIsNone(self.s.poll(self.a["credential"],Heartbeat())["task"])
        self.assertIsNone(self.poll(("dns",)))
        self.assertEqual(self.poll()["kind"],"tcp")
    def test_shared_queue_and_legacy_isolation(self):
        task=self.lease()
        self.assertTrue(self.heartbeat(task))
        self.assertFalse(self.heartbeat(task,self.b))
        self.assertIsNone(self.poll(("tcp","dns")))
        self.assertIsNone(self.s.poll(self.a["credential"],Heartbeat())["task"])
        self.assertEqual(self.s.tasks(),[])
        with self.assertRaises(AgentError):self.s.detail(task["id"])
        with self.assertRaises(AgentError):self.s.complete(self.a["credential"],task["id"],Result(lease=task["lease"],status="failed",error="legacy"))
        for _ in range(3):self.s.enqueue(self.a["id"],AgentRun(endpoints=["udp://127.0.0.1"]))
        with self.assertRaises(AgentError):self.s.enqueue(self.a["id"],AgentRun(endpoints=["udp://127.0.0.1"]))
        self.s.remote_cancel(task["id"])
        self.assertFalse(self.heartbeat(task))
        with self.assertRaises(AgentError):self.complete(task)
        self.assertEqual(self.s.evidence_status()["pending"],0)
        self.assertEqual(self.poll(("dns","tcp"))["version"],"1")
    def test_complete_replay_and_provenance(self):
        task=self.lease()
        with self.assertRaises(AgentError):self.complete(task,node=self.b)
        with self.assertRaises(ValueError):self.complete(task,self.result(task,config_key="0"*64))
        bad=self.result(task,observation={"outcome":"success","stage":"complete","address":"127.0.0.2","peer_ip":"127.0.0.2","connect_ms":2.0,"total_ms":4.0})
        with self.assertRaises(ValueError):self.complete(task,bad)
        self.assertFalse(self.complete(task)["duplicate"])
        self.s.initialize()
        self.assertTrue(self.complete(task)["duplicate"])
        self.assertEqual(self.s.evidence_status()["pending"],1)
        obs,_=decode(self.s.pending_evidence()["payload"])
        r=obs[0]
        self.assertEqual((r.probe_kind,r.provenance,r.outcome,r.observed_at),("tcp","agent_claim","success",None))
        self.assertEqual(r.vantage_id,"agent:"+self.a["id"])
        self.assertNotIn(task["lease"],r.model_dump_json())
        self.assertEqual(self.s.remote_detail(task["id"])["state"],"completed")
    def test_failure_is_unknown_and_atomic_rollback(self):
        task=self.lease()
        body=self.result(task,status="failed",observation=None,execution_error="deadline")
        with self.s.db() as c:
            c.execute("CREATE TRIGGER reject_outbox BEFORE INSERT ON agent_evidence_outbox BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.complete(task,body)
        self.assertEqual(self.s.remote_detail(task["id"])["state"],"leased")
        with self.s.db() as c:c.execute("DROP TRIGGER reject_outbox")
        self.complete(task,body)
        obs,_=decode(self.s.pending_evidence()["payload"])
        self.assertEqual(obs[0].outcome,"unknown");self.assertEqual(obs[0].measurements,())
        self.assertEqual(obs[0].error_code,"deadline")
    def test_expiry_and_capacity(self):
        task=self.lease();self.now+=301
        with self.assertRaises(AgentError):self.complete(task)
        self.assertEqual(self.s.remote_detail(task["id"])["state"],"interrupted")
        self.assertEqual(self.s.evidence_status()["pending"],0)
        self.poll()
        self.enqueue(RemoteRequest(request_id="b"*32,config=self.cfg))
        task=self.poll()
        self.s.max_evidence_pending=0
        self.complete(task)
        self.assertEqual(self.s.evidence_status()["dropped_observations"],1)
        self.assertTrue(self.complete(task)["duplicate"])
        self.assertEqual(self.s.evidence_status()["dropped_observations"],1)
    def test_strict_target_and_result(self):
        for kw in ({"port":True},{"host":"https://example.com"},{"family":"both"},{"command":"id"},{"port":0},{"kind":"route"}):
            with self.assertRaises(ValueError):RemoteTCP(**({"host":"localhost","port":443}|kw))
        for kw in ({"connect_ms":float("nan")},{"peer_ip":"127.0.0.2"},{"stage":"resolve"},{"outcome":"failure"},{"total_ms":1.0},{"payload":"private"}):
            with self.assertRaises(ValueError):
                TCPObservation(**({"outcome":"success","stage":"complete","address":"127.0.0.1","peer_ip":"127.0.0.1","connect_ms":2.0,"total_ms":4.0}|kw))

if __name__=="__main__":unittest.main()
