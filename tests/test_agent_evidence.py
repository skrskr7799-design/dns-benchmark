import tempfile
import unittest
import sqlite3
from pathlib import Path
from backend.ndc.agent_store import AgentStore,AgentError
from backend.ndc.agent_contract import AgentRun,Heartbeat,Result,Batch
from backend.ndc.probes.dns import domains
from backend.ndc.storage import Store
from backend.ndc.monitoring import MonitorStore
from backend.ndc.evidence import EvidenceStore,Capacity
from backend.ndc.evidence_drain import EvidenceDrain
from backend.ndc.agent_evidence import STREAM

class Tests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.now=100000.0
        self.a=AgentStore(self.root/"agents.sqlite",lambda:self.now);self.a.initialize()
        self.b=Store(self.root/"history.sqlite");self.b.initialize()
        self.m=MonitorStore(self.root/"monitoring.sqlite",lambda:self.now);self.m.initialize()
        self.e=EvidenceStore(self.root/"intelligence.sqlite",clock=lambda:self.now);self.e.initialize()
        self.d=EvidenceDrain(self.b,self.m,self.e,lambda:self.now,agent=self.a)
        self.nodes=[self.a.enroll(self.a.invite(n,n)["token"]) for n in ("one","two")]
        self.cfg=AgentRun(endpoints=["udp://127.0.0.1"],count=2,mode="both")

    def lease(self,node=None):
        node=node or self.nodes[0]
        self.a.enqueue(node["id"],self.cfg)
        return self.a.poll(node["credential"],Heartbeat())["task"]

    def result(self,task):
        rows=[]
        for mode in ("cold","warm"):
            rows.append({"endpoint":self.cfg.endpoints[0],"mode":mode,"family":self.cfg.family,
                "engine":"python-dns02","count":2,"ok":2,"ip":"127.0.0.1",
                "p95":99999,"mean":99999,"bootstrap_ms":99999,"protocols":["h3"],
                "warmup":{"ok":True},"samples":[{"index":i,"domain":domains[i],"qtype":"A","ok":True,
                    "duration_ms":v,"protocol":"udp","reused":None,"peer_ip":None}
                    for i,v in enumerate((10,20))]})
        return Result(lease=task["lease"],status="completed",results=rows)

    def complete(self,task,body=None,node=None):
        return self.a.complete((node or self.nodes[0])["credential"],task["id"],body or self.result(task))

    def test_batch_provenance_recomputed_and_replay(self):
        batch="a"*32
        self.a.batch(Batch(request_id=batch,agent_ids=[n["id"] for n in self.nodes],config=self.cfg))
        task=self.a.poll(self.nodes[0]["credential"],Heartbeat())["task"]
        self.complete(task)
        self.assertTrue(self.complete(task)["duplicate"])
        self.assertEqual(self.a.evidence_status()["pending"],1)
        def crash(): raise RuntimeError("after commit before ack")
        with self.assertRaises(RuntimeError): self.d.once(STREAM,crash)
        self.assertEqual(self.e.status()["rows"],2)
        self.a.initialize();self.e.initialize()
        d=EvidenceDrain(self.b,self.m,self.e,lambda:self.now,agent=self.a)
        self.assertTrue(d.once(STREAM))
        self.assertEqual(self.a.evidence_status()["pending"],0)
        self.assertEqual(self.e.status()["rows"],2)
        for item in self.e.page("observations")["items"]:
            r=item["record"];metrics={m["name"]:m["value"] for m in r["measurements"]}
            self.assertEqual(r["source_kind"],"agent")
            self.assertEqual(r["vantage_id"],"agent:"+self.nodes[0]["id"])
            self.assertEqual(r["correlation_id"],batch)
            self.assertEqual(r["provenance"],"agent_claim")
            self.assertIsNone(r["observed_at"])
            self.assertEqual(r["protocol"],"udp")
            self.assertEqual(metrics["p95"],20)
            self.assertEqual(metrics["p99"],20)
            self.assertEqual(metrics["mean"],15)
            self.assertIsNone(metrics["bootstrap_ms"])
            self.assertIn("agent_claim_not_attested",r["limitations"])
            self.assertNotIn(task["lease"],str(r))
            self.assertNotIn(self.nodes[0]["credential"],str(r))

    def test_validation_and_atomic_source_rollback(self):
        task=self.lease()
        with self.assertRaises(AgentError):
            self.complete(task,node=self.nodes[1])
        bad=self.result(task)
        bad.results[0]["samples"][0]["domain"]="wrong.example"
        with self.assertRaises(AgentError): self.complete(task,bad)
        self.assertEqual(self.a.evidence_status()["pending"],0)
        with self.a.db() as c:
            c.execute("CREATE TRIGGER fail_queue BEFORE INSERT ON agent_evidence_outbox BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.complete(task)
        self.assertEqual(self.a.detail(task["id"])["state"],"leased")
        self.assertEqual(self.a.evidence_status()["pending"],0)
        with self.a.db() as c: c.execute("DROP TRIGGER fail_queue")
        self.complete(task)
        self.assertEqual(self.a.pending_evidence()["seq"],1)

    def test_capacity_whole_task_and_failed_unknown(self):
        task=self.lease();self.complete(task)
        small=EvidenceStore(self.root/"intelligence.sqlite",max_rows=1)
        d=EvidenceDrain(self.b,self.m,small,lambda:self.now,agent=self.a)
        with self.assertRaises(Capacity): d.once(STREAM)
        self.assertEqual(small.status()["rows"],0)
        self.assertEqual(self.a.evidence_status()["pending"],1)
        self.a.max_evidence_pending=1
        second=self.lease();self.complete(second)
        status=self.a.evidence_status()
        self.assertEqual((status["pending"],status["dropped_tasks"],status["dropped_observations"]),(1,1,2))
        self.assertTrue(self.complete(second)["duplicate"])
        self.assertEqual(self.a.evidence_status()["dropped_tasks"],1)
        self.d.once(STREAM)
        third=self.lease()
        self.complete(third,Result(lease=third["lease"],status="failed",error="private-error"))
        self.assertEqual(self.a.pending_evidence()["seq"],2)
        self.d.once(STREAM)
        r=self.e.page("observations")["items"][-1]["record"]
        self.assertEqual(r["outcome"],"unknown")
        self.assertEqual(r["measurements"],[])
        self.assertNotIn("private-error",str(r))

    def test_migration_and_expired_task_no_fake_result(self):
        task=self.lease();self.complete(task)
        with self.a.db() as c:
            c.execute("DROP TABLE remote_batch_policy")
            c.execute("DROP TABLE agent_capabilities")
            c.execute("ALTER TABLE tasks DROP COLUMN contract_version")
            c.execute("ALTER TABLE tasks DROP COLUMN probe_kind")
            c.execute("DROP TABLE agent_evidence_outbox")
            c.execute("DROP TABLE agent_evidence_coverage")
            c.execute("PRAGMA user_version=0")
        self.a.initialize()
        self.assertEqual(self.a.detail(task["id"])["state"],"completed")
        self.assertEqual(self.a.evidence_status()["pending"],0)
        expired=self.lease();self.now+=301
        with self.assertRaises(AgentError): self.complete(expired)
        self.assertEqual(self.a.evidence_status()["pending"],0)
        task=self.lease();self.complete(task)
        self.assertEqual(self.a.pending_evidence()["seq"],1)

    def test_untrusted_metadata_not_used(self):
        task=self.lease();body=self.result(task)
        body.results[0]["ip"]={"invalid":"ip"}
        body.results[0]["samples"][0]["protocol"]=["udp"]
        body.results[0]["samples"][0]["reused"]="false"
        # Both-mode IP check still requires exact matching claimed value.
        body.results[1]["ip"]={"invalid":"ip"}
        self.complete(task,body)
        self.d.once(STREAM)
        r=self.e.page("observations")["items"][0]["record"]
        self.assertIsNone(r["protocol"])
        self.assertIsNone(r["family"])
        self.assertIn("bootstrap_ip_unavailable",r["limitations"])

if __name__=="__main__":
    unittest.main()
