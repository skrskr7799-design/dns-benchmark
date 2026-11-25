import tempfile
import sqlite3
import unittest
from pathlib import Path
from backend.ndc.monitoring import MonitorStore
from backend.ndc.models import MonitorConfig
from backend.ndc.storage import Store
from backend.ndc.evidence import EvidenceStore,Capacity
from backend.ndc.evidence_drain import EvidenceDrain
from backend.ndc.monitor_evidence import STREAM,decode

CFG={"endpoints":["udp://127.0.0.1"],"mode":"cold","family":"ipv4","parallel":1,"count":1}

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.now=1000000.0
        self.m=MonitorStore(self.root/"monitoring.sqlite",lambda:self.now);self.m.initialize()
        self.b=Store(self.root/"history.sqlite");self.b.initialize()
        self.e=EvidenceStore(self.root/"intelligence.sqlite",clock=lambda:self.now);self.e.initialize()
        self.d=EvidenceDrain(self.b,self.m,self.e,lambda:self.now)
        self.id=self.m.create(MonitorConfig(name="test",host="localhost",kind="tcp",
            failure_count=2,recovery_count=2,interval_seconds=60,notify=True))["id"]

    def check(self,outcome):
        self.assertEqual(self.m.claim()["id"],self.id)
        self.m.finish(self.id,{"outcome":outcome,"latency_ms":12.0 if outcome=="healthy" else None,
            "reason":"sensitive example not copied","details":{"ip":"127.0.0.1"}})
        self.now+=60

    def test_transitions_replay_and_restart(self):
        for outcome in ("failed","failed","degraded","healthy","healthy"):
            self.check(outcome)
        self.assertEqual(self.m.evidence_status()["pending"],5)
        self.assertEqual(self.m.delivery_counts(),{"pending":2})
        self.assertTrue(self.d.once(STREAM))
        def crash(): raise RuntimeError("after commit")
        with self.assertRaises(RuntimeError): self.d.once(STREAM,crash)
        self.assertEqual(self.e.status()["rows"],3)
        self.m.initialize();self.e.initialize()
        d=EvidenceDrain(self.b,self.m,self.e,lambda:self.now)
        while d.once(STREAM): pass
        events=self.e.page("events")["items"]
        self.assertEqual([x["record"]["event_type"] for x in events],["incident.opened","incident.closed"])
        self.assertEqual(len(self.e.page("observations")["items"]),5)
        self.assertEqual(self.e.status()["rows"],7)
        self.assertEqual(self.m.evidence_status()["pending"],0)
        self.assertEqual(self.m.delivery_counts(),{"pending":2})
        self.assertNotIn("sensitive example",str(self.e.page("observations")))

    def test_atomic_rollback(self):
        self.m.claim()
        with self.m.db() as c:
            c.execute("CREATE TRIGGER fail_queue BEFORE INSERT ON monitor_evidence_outbox BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.m.finish(self.id,{"outcome":"healthy","details":{}})
        self.assertEqual(self.m.history(self.id,10),[])
        self.assertEqual(self.m.evidence_status()["pending"],0)
        self.m.initialize()
        with self.m.db() as c: c.execute("DROP TRIGGER fail_queue")
        self.check("healthy")
        self.assertEqual(self.m.pending_evidence()["seq"],1)

    def test_full_queue_keeps_monitoring_and_tracks_gaps(self):
        self.m.max_evidence_pending=1
        self.check("failed");self.check("failed")
        self.assertEqual(self.m.get(self.id)["state"],"incident")
        self.assertEqual(self.m.delivery_counts(),{"pending":1})
        status=self.m.evidence_status()
        self.assertEqual((status["pending"],status["dropped"],status["dropped_transitions"]),(1,1,1))
        self.assertEqual(status["first_dropped_at"],status["last_dropped_at"])
        self.m.initialize()
        self.assertEqual(self.m.evidence_status()["dropped"],1)
        self.d.once(STREAM)
        self.check("healthy")
        self.assertEqual(self.m.pending_evidence()["seq"],2)
        self.d.once(STREAM)
        self.assertEqual(self.e.status()["rows"],2)

    def test_two_streams_independent(self):
        self.check("healthy")
        job=self.b.create(CFG);self.b.claim();self.b.add_result(job,0,{"count":1,"ok":1});self.b.finish(job,"completed")
        self.d.tick()
        self.assertEqual({r["record"]["source_kind"] for r in self.e.page("observations")["items"]},{"benchmark","monitor"})
        self.assertEqual(self.m.evidence_status()["pending"],0)
        self.assertEqual(self.b.evidence_pending_count(),0)
        self.check("healthy")
        with self.b.connect() as c:
            c.execute("INSERT INTO benchmark_evidence_outbox(payload) VALUES('invalid')")
        self.d.tick()
        self.assertIsNotNone(self.d.last_error)
        self.assertIsNone(self.d.errors[STREAM])
        self.assertEqual(self.m.evidence_status()["pending"],0)

    def test_delete_retains_pending_and_unknown(self):
        self.check("unknown")
        self.assertTrue(self.m.delete(self.id))
        self.d.once(STREAM)
        row=self.e.page("observations")["items"][0]["record"]
        self.assertEqual(row["outcome"],"unknown")
        self.assertIsNone(row["measurements"][0]["value"])

    def test_migration_preserves_existing_history(self):
        self.check("healthy")
        with self.m.db() as c:
            c.execute("DROP TABLE observatory_journal")
            c.execute("DROP TABLE observatory_state")
            c.execute("DROP TABLE monitor_evidence_outbox")
            c.execute("DROP TABLE monitor_evidence_coverage")
            c.execute("PRAGMA user_version=0")
        self.m.initialize()
        self.assertEqual(len(self.m.history(self.id,10)),1)
        self.assertEqual(self.m.evidence_status()["pending"],0)
        self.check("healthy")
        self.assertEqual(self.m.pending_evidence()["seq"],1)

if __name__=="__main__":
    unittest.main()
