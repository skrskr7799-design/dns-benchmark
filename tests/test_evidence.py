import tempfile
import unittest
import concurrent.futures
import sqlite3
from pathlib import Path
from pydantic import ValidationError
from backend.ndc.evidence import Observation,Measurement,Event,EvidenceStore,Conflict,Capacity,digest

def observation(i=1,**kw):
    data=dict(source_kind="benchmark",source_id="run",source_revision=1,source_part=str(i),
        vantage_id="controller",observed_at=100.0,target_id=digest("resolver"),profile_revision=digest("profile"),
        probe_kind="dns",outcome="success",provenance="controller",
        measurements=(Measurement(name="p95",unit="ms",value=12.0),Measurement(name="p99",unit="ms",value=None)))
    return Observation(**(data|kw))

def event(o):
    return Event(event_type="degraded",source_kind="benchmark",source_id="run",source_revision=1,
        deduplication_key="first",rule_version="v1",observed_at=100.0,severity="warning",confidence="hypothesis",
        evidence_ids=(o.identity,))

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)/"intelligence.sqlite"
        self.now=1000.0
        self.store=EvidenceStore(self.path,clock=lambda:self.now,max_rows=10,max_bytes=32768)
        self.store.initialize()

    def test_contract(self):
        self.assertIsNone(observation().measurements[1].value)
        for value,unit in [(float("nan"),"ms"),(-1.0,"ms"),(1.1,"ratio"),(1.5,"count")]:
            with self.assertRaises(ValidationError):
                Measurement(name="x",unit=unit,value=value)
        with self.assertRaises(ValidationError):
            observation(measurements=(Measurement(name="x",unit="ms",value=1.0),Measurement(name="x",unit="count",value=1.0)))
        with self.assertRaises(ValidationError):
            observation(secret="never persist")

    def test_atomic_restart_replay_and_conflict(self):
        o=observation();e=event(o)
        self.assertEqual(self.store.ingest("bench",1,(o,),(e,))["inserted"],2)
        restarted=EvidenceStore(self.path);restarted.initialize()
        self.assertTrue(restarted.ingest("bench",1,(o,),(e,))["replayed"])
        self.assertEqual(restarted.status()["rows"],2)
        with self.assertRaises(Conflict): restarted.ingest("bench",1,(observation(2),))
        with self.assertRaises(Conflict): restarted.ingest("bench",3,(observation(3),))
        with self.assertRaises(Conflict): restarted.ingest("bench",2,(observation(outcome="failure"),))
        self.assertEqual(restarted.ingest("bench",2,(observation(2),))["inserted"],1)
        self.assertEqual(restarted.page("observations")["items"][0]["received_at"],1000.0)

    def test_rollback_missing_reference_and_capacity(self):
        o=observation()
        with self.assertRaises(Conflict): self.store.ingest("bench",1,(o,),(event(observation(2)),))
        self.assertEqual(self.store.status()["rows"],0)
        small=EvidenceStore(self.path,max_rows=1)
        with self.assertRaises(Capacity): small.ingest("bench",1,(o,),(event(o),))
        self.assertEqual(small.status()["rows"],0)
        self.assertEqual(small.ingest("bench",1,(o,))["inserted"],1)

    def test_concurrent_replay(self):
        o=observation()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results=list(pool.map(lambda _:self.store.ingest("bench",1,(o,)),range(12)))
        self.assertEqual(sum(x["inserted"] for x in results),1)
        self.assertEqual(self.store.status()["rows"],1)

    def test_pages_and_retention(self):
        a,b=observation(),observation(2)
        self.store.ingest("bench",1,(a,b))
        self.now=2000.0
        self.store.ingest("bench",2,(),(event(a),))
        p=self.store.page("observations",limit=1)
        self.assertEqual(len(p["items"]),1)
        self.assertEqual(self.store.page("observations",after=p["next_cursor"],limit=1)["items"][0]["id"],b.identity)
        self.assertEqual(self.store.prune(before=1500.0),{"events":0,"observations":1})
        self.assertEqual(self.store.status()["rows"],2)
        self.assertEqual(self.store.prune(before=2500.0),{"events":1,"observations":1})
        self.assertEqual(self.store.status()["bytes"],0)
        self.assertTrue(self.store.ingest("bench",2,(),(event(a),))["replayed"])
        with self.assertRaises(Conflict): self.store.ingest("bench",1,(a,b))
        self.store.ingest("bench",3,(observation(3),))
        self.assertGreater(self.store.page("observations")["items"][0]["seq"],p["next_cursor"])

    def test_unknown_schema(self):
        with sqlite3.connect(self.path) as db: db.execute("PRAGMA user_version=99")
        with self.assertRaises(RuntimeError): self.store.initialize()

if __name__=="__main__":
    unittest.main()
