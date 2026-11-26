import tempfile
import unittest
import threading
from pathlib import Path
from unittest.mock import patch
from backend.ndc.evidence import EvidenceStore,Capacity,Conflict
from backend.ndc.monitoring import MonitorStore,MonitorScheduler
from backend.ndc.models import MonitorConfig
from backend.ndc.time_machine import SnapshotStore
from backend.ndc.snapshot_schedule import Schedules,ScheduleConfig
from backend.ndc.snapshot_probes import DNSCapture

class Disabled:enabled=False

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        root=Path(tmp.name);self.now=100000.
        self.e=EvidenceStore(root/"intelligence.sqlite",clock=lambda:self.now);self.e.initialize()
        self.m=MonitorStore(root/"monitoring.sqlite",lambda:self.now);self.m.initialize()
        self.s=SnapshotStore(self.e,max_snapshots=3)
        self.q=Schedules(self.e,self.m,self.s)
        self.cfg=ScheduleConfig(label="inventory",interval_seconds=3600)
    def test_fixed_delay_no_catchup(self):
        a=self.q.create(self.cfg)
        self.assertFalse(self.q.tick())
        self.now+=10*3600
        self.assertTrue(self.q.tick())
        self.assertFalse(self.q.tick())
        row=self.q.list()[0]
        self.assertEqual(row["runs"],1)
        self.assertEqual(row["next_at"],self.now+3600)
        self.assertEqual(row["last_status"],"captured")
        self.assertEqual(self.s.get(row["last_snapshot_id"])["snapshot"]["scope"],"configured_monitors")
        self.assertTrue(self.q.delete(a["id"]))
        self.assertEqual(len(self.s.list()["items"]),1)
    def test_gate_capacity_and_pause(self):
        a=self.q.create(self.cfg);b=self.q.create(self.cfg)
        self.now+=3600
        self.assertTrue(self.q.tick());self.assertFalse(self.q.tick())
        self.now+=60;self.assertTrue(self.q.tick())
        self.now+=3600;self.assertTrue(self.q.tick())
        self.now+=60;self.assertTrue(self.q.tick())
        rows=self.q.list();blocked=next(r for r in rows if r["last_status"]=="capacity")
        self.assertFalse(blocked["enabled"])
        self.assertEqual(len(self.s.list()["items"]),3)
        self.s.delete(self.s.list()["items"][-1]["id"])
        enabled=self.q.enable(blocked["id"],True)
        self.assertEqual(enabled["next_at"],self.now+3600)
        self.assertFalse(self.q.tick())
    def test_restart_after_commit_and_before_commit(self):
        self.q.create(self.cfg);self.now+=3600;claim=self.q.claim()
        self.s.create(claim["pending_id"],self.cfg.label,self.m)
        with self.assertRaises(Conflict):self.s.delete(claim["pending_id"])
        with self.assertRaises(Conflict):self.q.enable(claim["id"],False)
        self.e.initialize()
        self.q=Schedules(self.e,self.m,self.s);self.q.recover()
        row=self.q.list()[0]
        self.assertEqual(row["last_status"],"captured")
        self.assertEqual(row["last_snapshot_id"],claim["pending_id"])
        self.assertFalse(self.q.finish(claim,"captured"))
        self.now+=3600;claim=self.q.claim()
        self.q.recover()
        row=self.q.list()[0]
        self.assertEqual(row["last_status"],"interrupted")
        self.assertEqual(row["runs"],2)
        self.assertEqual(row["errors"],1)
        self.assertEqual(len(self.s.list()["items"]),1)
        self.assertFalse(self.q.tick())
    def test_probe_dispatch_and_error(self):
        self.q.create(ScheduleConfig(label="DNS",interval_seconds=3600,
            probe=DNSCapture(name="example.com",endpoints=["udp://127.0.0.1"])))
        self.now+=3600
        with patch("backend.ndc.snapshot_probes.inspect_one",side_effect=RuntimeError("private error")):
            self.assertTrue(self.q.tick())
        r=self.q.list()[0]
        self.assertEqual(r["last_error"],"RuntimeError")
        self.assertEqual(r["last_status"],"error")
        self.assertEqual(r["next_at"],self.now+3600)
        self.assertEqual(self.s.list()["items"],[])
    def test_shared_lane_and_monitor_priority(self):
        self.q.create(self.cfg);self.now+=3600
        self.m.create(MonitorConfig(name="fixture",host="localhost"))
        slot=threading.Lock();calls=[]
        def probe(cfg):
            calls.append("monitor")
            return {"outcome":"healthy","latency_ms":10.,"details":{"ip":"127.0.0.1"}}
        scheduler=MonitorScheduler(self.m,slot,Disabled(),probe,snapshot_schedules=self.q)
        with slot:scheduler.tick()
        self.assertEqual(calls,[])
        self.assertEqual(self.q.list()[0]["runs"],0)
        scheduler.tick()
        self.assertEqual(calls,["monitor"])
        self.assertEqual(self.q.list()[0]["runs"],1)
        self.assertFalse(self.q.list()[0]["running"])
    def test_validation_and_migration(self):
        with self.assertRaises(ValueError):ScheduleConfig(label="x",interval_seconds=60)
        for _ in range(8):self.q.create(self.cfg)
        with self.assertRaises(Capacity):self.q.create(self.cfg)
        with self.e.db() as c:
            c.execute("DROP TABLE snapshot_schedules")
            c.execute("DROP TABLE snapshot_schedule_gate")
            c.execute("PRAGMA user_version=3")
        self.e.initialize();self.assertEqual(self.q.list(),[])

if __name__=="__main__":unittest.main()
