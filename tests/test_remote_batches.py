import tempfile
import unittest
from pathlib import Path
from backend.ndc.agent_store import AgentStore,AgentError
from backend.ndc.agent_contract import PollV2,Heartbeat,AgentRun,Batch
from backend.ndc.remote_contract import RemoteBatch,RemoteTCP,RemoteResult,config_key
from backend.ndc.agent_evidence import decode

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.now=100000.;self.s=AgentStore(Path(tmp.name)/"agents.sqlite",lambda:self.now);self.s.initialize()
        self.nodes=[self.s.enroll(self.s.invite("site"+str(i),"label")["token"]) for i in range(3)]
        self.cfg=RemoteTCP(host="example.com",port=443)
        self.body=RemoteBatch(request_id="a"*32,agent_ids=[n["id"] for n in self.nodes],config=self.cfg)
    def poll(self,n,claims=("tcp",)):
        return self.s.poll_v2(n["credential"],PollV2(version="2",engine="python-network-v2",capabilities=list(claims)))["task"]
    def create(self):
        for n in self.nodes:self.poll(n)
        return self.s.remote_batch(self.body)
    def complete(self,n,t,ip):
        body=RemoteResult(version="2",engine="python-network-v2",kind="tcp",lease=t["lease"],config_key=config_key(self.cfg),
            status="completed",observation={"outcome":"success","stage":"complete","address":ip,"peer_ip":ip,"connect_ms":2.0,"total_ms":3.0})
        return self.s.complete_remote(n["credential"],t["id"],body)
    def test_atomic_admission_and_replay(self):
        self.poll(self.nodes[0]);self.poll(self.nodes[1])
        with self.assertRaises(AgentError):self.s.remote_batch(self.body)
        self.assertEqual(self.s.remote_tasks(),[])
        self.poll(self.nodes[2])
        self.assertFalse(self.s.remote_batch(self.body)["duplicate"])
        self.assertTrue(self.s.remote_batch(self.body)["duplicate"])
        self.assertEqual(len(self.s.remote_tasks()),3)
        self.assertEqual(self.s.batches(),[])
        with self.assertRaises(AgentError):self.s.batch_detail(self.body.request_id)
        with self.assertRaises(AgentError):self.s.cancel_batch(self.body.request_id)
        with self.assertRaises(AgentError):self.s.batch(Batch(request_id=self.body.request_id,agent_ids=self.body.agent_ids,config=AgentRun(endpoints=["udp://127.0.0.1"])))
        with self.assertRaises(AgentError):self.s.remote_batch(self.body.model_copy(update={"config":RemoteTCP(host="example.net",port=443)}))
    def test_matched_cohorts_and_provenance(self):
        self.create()
        for n,ip in zip(self.nodes,["192.0.2.1","192.0.2.1","192.0.2.2"]):
            self.now+=1;t=self.poll(n);self.now+=1
            self.assertFalse(self.complete(n,t,ip)["duplicate"])
            self.assertTrue(self.complete(n,t,ip)["duplicate"])
        r=self.s.remote_batch_detail(self.body.request_id)
        self.assertEqual(r["counts"],{"success":3,"failure":0,"partial":0,"unknown":0})
        self.assertEqual([g["comparable"] for g in r["cohorts"]],[True,False])
        self.assertFalse(r["window"]["simultaneous_verified"])
        self.assertTrue(all(x["controller_window_verified"] for x in r["members"]))
        obs,_=decode(self.s.pending_evidence()["payload"])
        self.assertEqual(obs[0].correlation_id,self.body.request_id)
        self.assertEqual(self.s.evidence_status()["pending"],3)
        self.s.initialize();self.assertEqual(self.s.remote_batch_detail(self.body.request_id)["counts"],r["counts"])
    def test_dispatch_deadline_and_cancel(self):
        self.create()
        t=self.poll(self.nodes[0])
        self.now+=120
        self.assertIsNone(self.poll(self.nodes[1]))
        self.assertIsNone(self.s.poll(self.nodes[2]["credential"],Heartbeat())["task"])
        r=self.s.remote_batch_detail(self.body.request_id)
        self.assertEqual(sorted(x["state"] for x in r["members"]),["interrupted","interrupted","leased"])
        self.assertEqual(r["counts"]["unknown"],3)
        self.assertEqual(self.s.remote_batch_cancel(self.body.request_id)["cancelled"],1)
        with self.assertRaises(AgentError):self.complete(self.nodes[0],t,"192.0.2.1")
        self.assertEqual(self.s.remote_batches()[0]["finished"],3)
    def test_migration_and_retention(self):
        legacy=self.s.batch(Batch(request_id="b"*32,agent_ids=self.body.agent_ids,config=AgentRun(endpoints=["udp://127.0.0.1"])))
        with self.s.db() as c:
            c.execute("DROP TABLE peer_requests")
            c.execute("DROP TABLE peer_claims")
            c.execute("DROP TABLE remote_batch_policy")
            c.execute("PRAGMA user_version=2")
        self.s.initialize();self.assertEqual(self.s.batches()[0]["id"],legacy["id"])
        self.s.cancel_batch(legacy["id"])
        self.create();self.s.remote_batch_cancel(self.body.request_id)
        self.now+=31*86400
        self.assertEqual(self.s.remote_batches(),[])
        with self.s.db() as c:self.assertEqual(c.execute("SELECT count(*) FROM remote_batch_policy").fetchone()[0],0)
    def test_strict_batch(self):
        for ids in (self.body.agent_ids[:1],[self.nodes[0]["id"]]*2,["bad",self.nodes[0]["id"]]):
            with self.assertRaises(ValueError):RemoteBatch(request_id="c"*32,agent_ids=ids,config=self.cfg)

if __name__=="__main__":unittest.main()
