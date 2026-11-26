import tempfile
import unittest
import threading
import sqlite3
from pathlib import Path
from backend.ndc.models import MonitorConfig
from backend.ndc.monitoring import MonitorStore,MonitorScheduler
from backend.ndc.maintenance import MaintenanceConflict

class Disabled: enabled=False

class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.path=Path(t.name)/"monitoring.sqlite";self.now=100000.
        self.m=MonitorStore(self.path,lambda:self.now);self.m.initialize()
        self.cfg=MonitorConfig(name="fixture",host="localhost",interval_seconds=60,failure_count=1)
        self.id=self.m.create(self.cfg)["id"]
    def finish(self,outcome="healthy"):
        self.m.finish(self.id,{"outcome":outcome,"latency_ms":10. if outcome=="healthy" else None,"details":{"ip":"127.0.0.1"}})
    def schedule(self):
        return self.m.maintenance_create(self.id,self.now+60,self.now+180)
    def test_start_end_and_incident_preserved(self):
        self.assertEqual(self.m.claim()["id"],self.id);self.finish("failed")
        w=self.schedule();self.now+=60
        self.assertIsNone(self.m.claim())
        self.assertEqual(self.m.maintenance_list(self.id)[0]["state"],"active")
        self.assertEqual(self.m.get(self.id)["state"],"incident")
        self.assertIsNone(self.m.incidents()[0]["closed"])
        self.m.initialize();self.assertIsNone(self.m.claim())
        self.now+=120
        self.assertEqual(self.m.claim()["id"],self.id);self.finish()
        self.assertEqual(self.m.maintenance_list(self.id)[0]["state"],"completed")
        self.assertEqual(len(self.m.history(self.id,10)),2)
        j=self.m.observatory_snapshot(self.id,0,self.now+1)["journal"]
        self.assertEqual([x["type"] for x in j],["tracking.started","maintenance.scheduled","maintenance.started","maintenance.ended"])
        self.assertEqual(w["starts_at"],self.now-120)
    def test_manual_pause_independent_and_cancel(self):
        w=self.schedule();self.now+=60;self.assertIsNone(self.m.claim())
        self.m.enable(self.id,False)
        self.m.maintenance_cancel(self.id,w["id"])
        self.assertFalse(self.m.get(self.id)["enabled"])
        self.assertIsNone(self.m.claim())
        self.assertEqual(self.m.maintenance_cancel(self.id,w["id"])["state"],"cancelled")
        self.m.enable(self.id,True);self.assertEqual(self.m.claim()["id"],self.id)
    def test_missed_window_and_validation(self):
        w=self.schedule()
        with self.assertRaises(MaintenanceConflict): self.schedule()
        self.now+=200
        self.assertEqual(self.m.claim()["id"],self.id)
        self.assertEqual(self.m.maintenance_list(self.id)[0]["state"],"skipped")
        self.assertIsNone(self.m.maintenance_list(self.id)[0]["applied_at"])
        with self.assertRaises(MaintenanceConflict): self.m.maintenance_cancel(self.id,w["id"])
        with self.assertRaises(ValueError): self.m.maintenance_create(self.id,self.now,self.now+60)
    def test_inflight_not_preempted_and_other_monitor_runs(self):
        w=self.schedule()
        self.assertEqual(self.m.claim()["id"],self.id)
        self.now+=70
        self.finish()
        other=self.m.create(self.cfg)["id"]
        self.assertEqual(self.m.claim()["id"],other)
        self.assertEqual(self.m.maintenance_list(self.id)[0]["applied_at"],self.now)
        self.assertEqual(len(self.m.history(self.id,10)),1)
    def test_finish_failure_releases_claim(self):
        with self.m.db() as c:
            c.execute("CREATE TRIGGER fail_queue BEFORE INSERT ON monitor_evidence_outbox BEGIN SELECT RAISE(ABORT,'injected'); END")
        scheduler=MonitorScheduler(self.m,threading.Lock(),Disabled(),lambda cfg:{"outcome":"healthy","latency_ms":10.,"details":{"ip":"127.0.0.1"}})
        with self.assertRaises(sqlite3.IntegrityError): scheduler.tick()
        self.assertFalse(self.m.get(self.id)["running"])
        self.assertIsNone(self.m.claim())
        with self.m.db() as c: c.execute("DROP TRIGGER fail_queue")
        self.now+=60;scheduler.tick()
        self.assertEqual(len(self.m.history(self.id,10)),1)
    def test_v2_migration_and_delete(self):
        with self.m.db() as c:
            c.execute("DROP TABLE maintenance_windows")
            c.execute("PRAGMA user_version=2")
        self.m.initialize()
        self.assertEqual(self.m.maintenance_list(self.id),[])
        self.schedule();self.assertTrue(self.m.delete(self.id))
        self.assertIsNone(self.m.maintenance_list(self.id))
if __name__=="__main__": unittest.main()
