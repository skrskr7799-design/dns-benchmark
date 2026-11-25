import tempfile
import unittest
from pathlib import Path
from backend.ndc.agent_store import AgentStore,AgentError
from backend.ndc.agent_contract import AgentRun,Batch,Heartbeat,Result
from backend.ndc.probes.dns import domains

class BatchTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.now=100000
        self.store=AgentStore(Path(tmp.name)/"agents.sqlite",lambda:self.now)
        self.store.initialize()
        self.nodes=[self.store.enroll(self.store.invite(n,n)["token"]) for n in ("first","second")]
        self.cfg=AgentRun(endpoints=["udp://127.0.0.1"],count=1)
        self.body=Batch(request_id="a"*32,agent_ids=[a["id"] for a in self.nodes],config=self.cfg)

    def test_atomic_and_idempotent(self):
        second=self.nodes[1]["id"]
        for _ in range(4):
            self.store.enqueue(second,self.cfg)
        with self.assertRaises(AgentError):
            self.store.batch(self.body)
        self.assertEqual(len(self.store.tasks()),4)
        self.assertEqual(self.store.batches(),[])
        for task in self.store.tasks():
            self.store.cancel(task["id"])
        self.assertFalse(self.store.batch(self.body)["duplicate"])
        self.assertTrue(self.store.batch(self.body)["duplicate"])
        self.assertEqual(len(self.store.tasks()),6)
        other=self.body.model_copy(update={"config":self.cfg.model_copy(update={"count":2})})
        with self.assertRaises(AgentError):
            self.store.batch(other)
        self.assertEqual(self.store.cancel_batch(self.body.request_id)["cancelled"],2)

    def test_offline_resume_and_recompute(self):
        self.store.batch(self.body)
        self.assertFalse(any(m["online"] for m in self.store.batch_detail(self.body.request_id)["members"]))
        first,second=self.nodes
        task=self.store.poll(first["credential"],Heartbeat())["task"]
        row={"endpoint":self.cfg.endpoints[0],"mode":"cold","family":"ipv4","engine":"python-dns02","count":1,"ok":1,"ip":"127.0.0.1","p95":9999,"samples":[{"index":0,"domain":domains[0],"qtype":"A","ok":True,"duration_ms":12,"protocol":"udp"}]}
        result=Result(lease=task["lease"],status="completed",results=[row])
        self.store.complete(first["credential"],task["id"],result)
        self.store.initialize()
        self.assertTrue(self.store.complete(first["credential"],task["id"],result)["duplicate"])
        self.now+=46
        members=self.store.batch_detail(self.body.request_id)["members"]
        self.assertEqual(members[0]["results"][0]["p95"],12)
        self.assertFalse(members[0]["online"])
        self.assertEqual(members[1]["state"],"queued")
        task=self.store.poll(second["credential"],Heartbeat())["task"]
        self.store.complete(second["credential"],task["id"],Result(lease=task["lease"],status="failed",error="fixture"))
        self.assertEqual(self.store.batches()[0]["finished"],2)
        self.assertEqual(self.store.batch_detail(self.body.request_id)["members"][1]["results"],[])

    def test_batch_retention_and_limits(self):
        self.store.batch(self.body)
        self.store.cancel_batch(self.body.request_id)
        self.now+=31*86400
        self.assertEqual(self.store.batches(),[])
        with self.assertRaises(ValueError):
            Batch(request_id="b"*32,agent_ids=[self.nodes[0]["id"]]*2,config=self.cfg)

if __name__=="__main__":
    unittest.main()
