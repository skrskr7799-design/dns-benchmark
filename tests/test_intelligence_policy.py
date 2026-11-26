import tempfile
import sqlite3
import unittest
from pathlib import Path
from backend.ndc.evidence import EvidenceStore,Observation,Measurement,Event,Capacity,digest,RUNTIME_QUOTAS

def observation(source,i,**kw):
    return Observation(**(dict(source_kind=source,source_id=source,source_revision=i,source_part="check",
        vantage_id="agent:a" if source=="agent" else "controller",target_id=digest("target"),
        profile_revision=digest("profile"),probe_kind="dns",outcome="success",
        provenance="agent_claim" if source=="agent" else "controller",
        measurements=(Measurement(name="p95",unit="ms",value=10.0),))|kw))

def event(o):
    return Event(event_type="incident.opened",source_kind=o.source_kind,source_id=o.source_id,
        source_revision=o.source_revision,deduplication_key="state",rule_version="v1",
        severity="warning",confidence="observed",evidence_ids=(o.identity,))

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)/"intelligence.sqlite";self.now=100.0
        self.store=EvidenceStore(self.path,max_rows=8,max_bytes=32768,
            quotas={"benchmark":(2,8192),"monitor":(4,16384),"agent":(2,8192)},clock=lambda:self.now)
        self.store.initialize()

    def test_reserved_capacity_and_protected_events(self):
        a=observation("monitor",1)
        self.store.ingest("monitor",1,(a,),(event(a),))
        self.store.ingest("monitor",2,(observation("monitor",2),))
        self.store.ingest("monitor",3,(observation("monitor",3),))
        self.now=101.0
        self.store.ingest("monitor",4,(observation("monitor",4),))
        self.assertIsNone(self.store.detail("observations",observation("monitor",2).identity))
        self.assertIsNotNone(self.store.detail("observations",a.identity))
        e=self.store.detail("events",event(a).identity)
        self.assertEqual(e["evidence"][0]["id"],a.identity)
        self.store.ingest("benchmark",1,(observation("benchmark",1),observation("benchmark",2)))
        self.store.ingest("agent",1,(observation("agent",1),observation("agent",2)))
        self.assertEqual(self.store.status()["rows"],8)
        with self.assertRaises(Capacity): self.store.ingest("benchmark",2,(observation("benchmark",3),))
        self.assertEqual(self.store.status()["sources"]["monitor"]["evicted"],1)
        self.assertEqual(self.store.status()["sources"]["monitor"]["last_evicted_at"],101.0)
        self.assertTrue(self.store.ingest("monitor",4,(observation("monitor",4),))["replayed"])

    def test_atomic_eviction_rollback(self):
        for i in (1,2):
            o=observation("monitor",i)
            self.store.ingest("monitor",i,(o,),(event(o),))
        with self.assertRaises(Capacity): self.store.ingest("monitor",3,(observation("monitor",3),))
        self.assertEqual(self.store.status()["sources"]["monitor"]["evicted"],0)
        self.assertEqual(self.store.status()["cursors"]["monitor"],2)
        self.store.prune(before=101.0)
        self.assertEqual(self.store.status()["sources"]["monitor"]["rows"],0)
        self.store.ingest("monitor",3,(observation("monitor",3),))

    def test_filters_and_stable_high_water(self):
        a=observation("monitor",1)
        self.store.ingest("monitor",1,(a,))
        self.now=110.0
        self.store.ingest("monitor",2,(observation("monitor",2,outcome="unknown"),))
        self.store.ingest("agent",1,(observation("agent",1),))
        p=self.store.page("observations",source="monitor",limit=1)
        self.assertEqual(p["items"][0]["id"],a.identity)
        self.store.ingest("monitor",3,(observation("monitor",3),))
        q=self.store.page("observations",source="monitor",after=p["next_cursor"],until=p["until"],limit=1)
        self.assertEqual(q["items"][0]["record"]["outcome"],"unknown")
        self.assertIsNone(q["next_cursor"])
        self.assertEqual(len(self.store.page("observations",vantage="agent:a",probe="dns",outcome="success",since=110.0)["items"]),1)
        with self.assertRaises(ValueError): self.store.page("events",outcome="unknown")
        with self.assertRaises(ValueError): self.store.page("observations",since=100,before=100)

    def test_migration_and_usage(self):
        o=observation("benchmark",1)
        self.store.ingest("benchmark",1,(o,),(event(o),))
        with self.store.db() as c:
            c.execute("DROP TABLE network_snapshots")
            for name in ("source_observation_insert","source_observation_delete","source_event_insert","source_event_delete"):
                c.execute("DROP TRIGGER "+name)
            c.execute("DROP INDEX observations_source_seq")
            c.execute("DROP INDEX events_source_seq")
            c.execute("ALTER TABLE observations DROP COLUMN source_kind")
            c.execute("ALTER TABLE events DROP COLUMN source_kind")
            c.execute("DROP TABLE source_usage")
            c.execute("PRAGMA user_version=1")
        self.store.initialize()
        status=self.store.status()
        self.assertEqual(status["sources"]["benchmark"]["rows"],2)
        self.assertEqual(status["sources"]["benchmark"]["bytes"],status["bytes"])
        self.assertTrue(self.store.ingest("benchmark",1,(o,),(event(o),))["replayed"])
        self.store.prune(before=101)
        self.assertEqual(self.store.status()["bytes"],0)
        self.assertEqual(self.store.status()["sources"]["benchmark"]["bytes"],0)

    def test_runtime_budget(self):
        store=EvidenceStore(self.path,quotas=RUNTIME_QUOTAS)
        self.assertEqual(sum(x[0] for x in store.quotas.values()),50000)
        self.assertEqual(sum(x[1] for x in store.quotas.values()),32*1024*1024)

if __name__=="__main__":
    unittest.main()
