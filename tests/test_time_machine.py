import tempfile
import unittest
import uuid
import sqlite3
from pathlib import Path
from backend.ndc.evidence import EvidenceStore,Capacity,Conflict
from backend.ndc.models import MonitorConfig
from backend.ndc.monitoring import MonitorStore
from backend.ndc.storage import Store
from backend.ndc.evidence_drain import EvidenceDrain
from backend.ndc.time_machine import SnapshotStore
from backend.ndc.backup import backup,restore

class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name);self.data=self.root/"data";self.data.mkdir();self.now=100000.
        self.m=MonitorStore(self.data/"monitoring.sqlite",lambda:self.now);self.m.initialize()
        self.b=Store(self.data/"history.sqlite");self.b.initialize()
        self.e=EvidenceStore(self.data/"intelligence.sqlite",clock=lambda:self.now);self.e.initialize()
        self.d=EvidenceDrain(self.b,self.m,self.e,lambda:self.now)
        self.s=SnapshotStore(self.e,max_snapshots=4)
        self.id=self.m.create(MonitorConfig(name="fixture",host="localhost",kind="http",path="/private-path",interval_seconds=60))["id"]
    def capture(self,label="fixture",id=None):
        return self.s.create(id or str(uuid.uuid4()),label,self.m)
    def check(self,ip="127.0.0.1"):
        self.assertEqual(self.m.claim()["id"],self.id)
        self.m.finish(self.id,{"outcome":"healthy","latency_ms":10.0,"reason":"private raw error",
            "details":{"ip":ip,"http_status":200,"secret":"private body"}})
        self.d.once("monitor-v1")
    def test_immutable_diff_and_idempotency(self):
        self.check();a=self.capture("before")
        self.now+=60;self.check("127.0.0.2");b=self.capture("after")
        self.assertEqual(self.capture("before",a["id"]),a)
        with self.assertRaises(Conflict): self.capture("different",a["id"])
        self.assertNotIn("private",str(a))
        with self.e.db() as c:
            with self.assertRaises(sqlite3.IntegrityError): c.execute("UPDATE network_snapshots SET label='edited'")
        d=self.s.compare(a["id"],b["id"])["changes"][0]
        self.assertEqual(next(x for x in d["observations"] if x["field"]=="address")["status"],"changed")
        self.assertTrue(d["before_evidence_id"])
        self.assertEqual(self.s.get(a["id"]),a)
        with self.assertRaises(ValueError): self.s.compare(b["id"],a["id"])
    def test_unknown_not_removed_and_inventory(self):
        self.check();a=self.capture()
        self.now+=181;b=self.capture()
        d=self.s.compare(a["id"],b["id"])["changes"][0]
        self.assertEqual(d["after_status"],"stale")
        self.assertTrue(all(x["status"]=="unknown" for x in d["observations"]))
        self.m.enable(self.id,False);c=self.capture()
        self.assertEqual(c["snapshot"]["monitors"][0]["observation_status"],"paused")
        self.m.delete(self.id);d=self.capture()
        self.assertEqual(self.s.compare(c["id"],d["id"])["changes"][0]["kind"],"monitor_removed")
        self.assertEqual(self.s.get(a["id"]),a)
    def test_not_collected_and_no_link_at_overflow(self):
        a=self.capture()
        self.assertEqual(a["snapshot"]["monitors"][0]["observation_status"],"not_collected")
        self.m.max_evidence_pending=0
        self.assertEqual(self.m.claim()["id"],self.id)
        self.m.finish(self.id,{"outcome":"healthy","latency_ms":1.,"details":{"ip":"127.0.0.1","http_status":200}})
        b=self.capture()
        self.assertIsNone(b["snapshot"]["monitors"][0]["observation"]["evidence_id"])
        self.m.enable(self.id,False);self.m.enable(self.id,True)
        c=self.capture()
        self.assertEqual(c["snapshot"]["monitors"][0]["observation_status"],"not_collected_since_boundary")
    def test_capacity_pagination_backup_and_migration(self):
        self.check();a=self.capture();b=self.capture();c=self.capture();d=self.capture()
        with self.assertRaises(Capacity): self.capture()
        p=self.s.list(limit=2)
        self.assertEqual([x["id"] for x in p["items"]],[d["id"],c["id"]])
        self.assertEqual([x["id"] for x in self.s.list(before=p["next_before"])["items"]],[b["id"],a["id"]])
        self.e.prune(before=self.now+1)
        self.assertEqual(self.s.get(a["id"]),a)
        backup(self.data,self.root/"backup");restore(self.root/"backup",self.root/"restored")
        restored=EvidenceStore(self.root/"restored"/"intelligence.sqlite");restored.initialize()
        self.assertEqual(SnapshotStore(restored).get(a["id"]),a)
        self.assertTrue(self.s.delete(a["id"]))
        self.capture()
        with self.e.db() as c:
            c.execute("DROP TABLE network_snapshots")
            c.execute("PRAGMA user_version=2")
        self.e.initialize()
        self.assertEqual(self.s.list()["items"],[])
    def test_same_check_not_new_measurement(self):
        self.check();a=self.capture();b=self.capture()
        d=self.s.compare(a["id"],b["id"])["changes"][0]
        self.assertEqual(next(x for x in d["observations"] if x["field"]=="address")["status"],"same_observation")

if __name__=="__main__": unittest.main()
