import sqlite3
import tempfile
import unittest
from pathlib import Path
from backend.ndc.storage import Store,Busy
from backend.ndc.evidence import EvidenceStore,Capacity
from backend.ndc.benchmark_evidence import BenchmarkDrain,project

CFG={"endpoints":["udp://127.0.0.1"],"mode":"cold","family":"ipv4","parallel":1,"count":2}
ROW={"endpoint":CFG["endpoints"][0],"mode":"cold","family":"ipv4","engine":"python-dns02","ip":"127.0.0.1",
    "count":2,"ok":2,"requested_count":2,"protocols":["udp"],"peer_ips":[],"p95":12.0,
    "samples":[{"index":i,"domain":"example.com","qtype":"A","ok":True} for i in range(2)]}

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.store=Store(self.root/"history.sqlite");self.store.initialize()
        self.evidence=EvidenceStore(self.root/"intelligence.sqlite");self.evidence.initialize()
        self.drain=BenchmarkDrain(self.store,self.evidence)

    def result(self):
        id=self.store.create(CFG);self.store.claim()
        self.store.add_result(id,0,ROW)
        self.store.finish(id,"completed")
        return id

    def test_atomic_source_and_replay_after_crash(self):
        id=self.result()
        self.assertEqual(self.store.evidence_pending_count(),1)
        self.assertEqual(self.evidence.status()["rows"],0)
        def crash(): raise RuntimeError("injected after derived commit")
        with self.assertRaises(RuntimeError): self.drain.once(crash)
        self.assertEqual(self.store.evidence_pending_count(),1)
        self.assertEqual(self.evidence.status()["rows"],1)
        restarted=Store(self.root/"history.sqlite");restarted.initialize()
        dest=EvidenceStore(self.root/"intelligence.sqlite");dest.initialize()
        self.assertTrue(BenchmarkDrain(restarted,dest).once())
        self.assertEqual(restarted.evidence_pending_count(),0)
        row=dest.page("observations")["items"][0]["record"]
        self.assertEqual(row["run_id"],id)
        self.assertEqual(row["outcome"],"success")
        self.assertEqual(row["protocol"],"udp")
        self.assertIn("peer_ip_unverified",row["limitations"])
        self.assertEqual(dest.status()["rows"],1)
        self.assertFalse(BenchmarkDrain(restarted,dest).once())
        self.result()
        self.assertTrue(self.drain.once())
        self.assertEqual(dest.status()["rows"],2)

    def test_atomic_rollback(self):
        id=self.store.create(CFG);self.store.claim()
        with self.store.connect() as c:
            c.execute("CREATE TRIGGER fail_outbox BEFORE INSERT ON benchmark_evidence_outbox BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.store.add_result(id,0,ROW)
        self.assertEqual(self.store.get(id)["results"],[])
        self.assertEqual(self.store.evidence_pending_count(),0)
        with self.store.connect() as c: c.execute("DROP TRIGGER fail_outbox")
        self.store.add_result(id,0,ROW)
        with self.assertRaises(sqlite3.IntegrityError): self.store.add_result(id,0,ROW)
        self.assertEqual(self.store.evidence_pending_count(),1)

    def test_delete_and_saturation(self):
        id=self.result()
        self.assertTrue(self.store.delete_run(id))
        self.assertIsNone(self.store.get(id))
        self.assertEqual(self.store.evidence_pending_count(),1)
        self.store.max_evidence_pending=80
        with self.assertRaises(Busy): self.store.create(CFG)
        small=EvidenceStore(self.root/"intelligence.sqlite",max_rows=1)
        BenchmarkDrain(self.store,small).once()
        self.assertEqual(self.store.evidence_pending_count(),0)
        self.result()
        with self.assertRaises(Capacity): BenchmarkDrain(self.store,small).once()
        self.assertEqual(self.store.evidence_pending_count(),1)

    def test_upgrade_no_backfill(self):
        id=self.result()
        with self.store.connect() as c:
            c.execute("DROP TABLE benchmark_evidence_outbox")
            c.execute("PRAGMA user_version=1")
        self.store.initialize()
        self.assertEqual(len(self.store.get(id)["results"]),1)
        self.assertEqual(self.store.evidence_pending_count(),0)
        self.result()
        self.assertTrue(self.drain.once())

    def test_incomplete_and_partial(self):
        missing=project("a",0,CFG,{"count":2,"ok":2},100.0)
        self.assertEqual(missing.outcome,"unknown")
        self.assertEqual(missing.measurements,())
        partial=project("a",0,CFG,ROW|{"count":1,"ok":1,"samples":ROW["samples"][:1]},100.0)
        self.assertEqual(partial.outcome,"partial")
        self.assertNotEqual(partial.profile_revision,project("a",0,CFG,ROW,100.0).profile_revision)

if __name__=="__main__":
    unittest.main()
