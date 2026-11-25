import tempfile
import sqlite3
import unittest
from pathlib import Path
from backend.ndc.models import MonitorConfig
from backend.ndc.monitoring import MonitorStore
from backend.ndc.storage import Store
from backend.ndc.evidence import EvidenceStore
from backend.ndc.evidence_drain import EvidenceDrain

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.now=100000.0
        self.m=MonitorStore(self.root/"monitoring.sqlite",lambda:self.now);self.m.initialize()
        self.b=Store(self.root/"history.sqlite");self.b.initialize()
        self.e=EvidenceStore(self.root/"intelligence.sqlite",clock=lambda:self.now);self.e.initialize()
        self.d=EvidenceDrain(self.b,self.m,self.e,lambda:self.now)
        self.id=self.m.create(MonitorConfig(name="fixture",host="localhost",kind="tcp",interval_seconds=60,notify=True))["id"]
    def check(self,latency=10,outcome="healthy"):
        self.assertEqual(self.m.claim()["id"],self.id)
        self.m.finish(self.id,{"outcome":outcome,"latency_ms":latency,"details":{"ip":"127.0.0.1"}})
        self.now+=60
    def snapshot(self):
        return self.m.observatory_snapshot(self.id,0,self.now+1)
    def events(self):
        return [x["record"]["event_type"] for x in self.e.page("events")["items"]]
    def drain(self):
        while self.d.once("monitor-v1"): pass
    def learn(self):
        for _ in range(12): self.check()
    def test_restart_and_derived_replay(self):
        self.learn();self.check(60)
        self.m.initialize();self.check(60)
        self.assertTrue(self.snapshot()["active_at_read"])
        self.assertEqual([x["type"] for x in self.snapshot()["journal"]],["tracking.started","anomaly.detected"])
        self.check(60);self.check();self.m.initialize();self.check()
        self.assertFalse(self.snapshot()["active_at_read"])
        self.assertEqual(self.m.delivery_counts(),{})
        for _ in range(13): self.d.once("monitor-v1")
        def crash(): raise RuntimeError("after commit")
        with self.assertRaises(RuntimeError): self.d.once("monitor-v1",crash)
        self.e.initialize();self.m.initialize();self.drain()
        self.assertEqual(self.events(),["anomaly.detected","anomaly.recovered"])
        self.assertEqual(len(self.snapshot()["journal"]),3)
        self.assertTrue(all(x["evidence_id"] for x in self.snapshot()["journal"][1:]))
    def test_pause_resets_even_short_gap(self):
        self.learn();self.check(60);self.check(60)
        self.m.enable(self.id,False);self.m.enable(self.id,False);self.m.enable(self.id,True)
        self.check(60)
        snap=self.snapshot()
        self.assertEqual(snap["state_at_read"],"learning")
        self.assertEqual(snap["baseline_samples_at_read"],1)
        self.assertEqual([x["type"] for x in snap["journal"]],["tracking.started","anomaly.detected","anomaly.interrupted","monitor.paused","monitor.resumed"])
        self.assertIsNone(snap["journal"][2]["evidence_id"])
        self.drain()
        self.assertEqual(self.events(),["anomaly.detected"])
    def test_queue_overflow_preserves_journal(self):
        self.m.max_evidence_pending=0
        self.learn();self.check(60);self.check(60)
        self.assertTrue(self.snapshot()["active_at_read"])
        self.assertIsNone(self.snapshot()["journal"][-1]["evidence_id"])
        self.assertEqual(self.m.evidence_status()["dropped"],14)
        self.assertEqual(self.m.evidence_status()["pending"],0)
        self.assertEqual(self.m.delivery_counts(),{})
    def test_atomic_rollback_and_migration(self):
        self.learn();self.check(60)
        self.m.claim()
        with self.m.db() as c:
            c.execute("CREATE TRIGGER fail_journal BEFORE INSERT ON observatory_journal BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.m.finish(self.id,{"outcome":"healthy","latency_ms":60,"details":{"ip":"127.0.0.1"}})
        self.assertFalse(self.snapshot()["active_at_read"])
        self.assertEqual(self.m.evidence_status()["pending"],13)
        self.m.initialize()
        with self.m.db() as c:
            c.execute("DROP TRIGGER fail_journal")
            c.execute("DROP TABLE observatory_journal")
            c.execute("DROP TABLE observatory_state")
            c.execute("PRAGMA user_version=1")
        self.m.initialize()
        self.assertEqual(len(self.m.history(self.id,100)),13)
        self.assertEqual(self.snapshot()["baseline_samples_at_read"],0)
        self.assertEqual(self.snapshot()["journal"][0]["reason"],"migration_start_enabled")
        self.check(60)
        self.assertEqual(self.snapshot()["state_at_read"],"learning")
    def test_window_boundary_and_delete(self):
        self.m.enable(self.id,False);self.now+=60
        self.m.enable(self.id,True);self.now+=60
        s=self.m.observatory_snapshot(self.id,self.now,self.now+1)
        self.assertEqual(s["prior_boundary"]["type"],"monitor.resumed")
        self.assertEqual(s["journal"],[])
        self.assertTrue(self.m.delete(self.id))
        self.assertIsNone(self.snapshot())

if __name__=="__main__": unittest.main()
