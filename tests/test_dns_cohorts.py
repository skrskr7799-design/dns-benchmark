import unittest
import tempfile
from pathlib import Path
from backend.ndc.evidence import EvidenceStore,Observation,Measurement,digest
from backend.ndc.dns_cohorts import aggregate,NarrowQuery,MAX_RECORDS

def obs(i,*,source="benchmark",vantage="controller",profile="cold",target="resolver",protocol="udp",family="ipv4",
        attempted=10,successful=10,requested=10,outcome="success",limitations=(),mean=10.0):
    m=tuple(Measurement(name=k,unit=u,value=v) for k,u,v in (
        ("attempted","count",attempted),("successful","count",successful),("requested","count",requested),
        ("mean","ms",mean),("p50","ms",10.0),("p95","ms",15.0),("p99","ms",20.0),("jitter","ms",2.0)))
    return Observation(source_kind=source,source_id="run"+str(i),source_revision=1,source_part="0",vantage_id=vantage,
        target_id=digest(target),profile_revision=digest(profile),probe_kind="dns",outcome=outcome,
        provenance="agent_claim" if source=="agent" else "controller",family=family,protocol=protocol,
        measurements=m,limitations=limitations)

def item(o,i=1):
    return {"id":o.identity,"received_at":100.0+i,"record":o.model_dump(mode="json")}

class Tests(unittest.TestCase):
    def test_weighted_latency_and_failure_denominator(self):
        records=[obs(1),obs(2,successful=5,outcome="partial",mean=40.0),obs(3,successful=0,outcome="failure",protocol=None)]
        r=aggregate([item(x,i) for i,x in enumerate(records)])
        t=r["cohorts"][0]["targets"][0]
        self.assertEqual(t["attempted"],30)
        self.assertEqual(t["successful"],15)
        self.assertEqual(t["observed_success_ratio"],.5)
        self.assertEqual(t["latency_by_protocol"][0]["approx_weighted_mean_ms"],20)
        self.assertEqual(t["latency_by_protocol"][0]["median_series_p95_ms"],15)
        self.assertEqual(t["latency_exclusions"]["no_successful_queries"],1)
        self.assertIsNone(r["ranking"])

    def test_separate_vantage_profile_family_protocol(self):
        records=[obs(1),obs(2,profile="warm"),obs(3,family="ipv6"),obs(4,source="agent",vantage="agent:a"),
                 obs(5,source="agent",vantage="agent:b"),obs(6,protocol="tcp"),obs(7,target="second")]
        r=aggregate([item(x) for x in records])
        self.assertEqual(len(r["cohorts"]),5)
        local=next(g for g in r["cohorts"] if g["source"]=="benchmark" and g["family"]=="ipv4" and g["profile_revision"]==digest("cold"))
        self.assertEqual(len(local["targets"]),2)
        t=next(t for t in local["targets"] if t["target_id"]==digest("resolver"))
        self.assertEqual({x["protocol"] for x in t["latency_by_protocol"]},{"udp","tcp"})

    def test_exclusions_and_unknown_protocol(self):
        records=[obs(1,attempted=5,successful=5,outcome="partial"),obs(2,limitations=("warmup_unverified_or_failed",)),
                 obs(3,family=None),obs(4,protocol=None),obs(5,outcome="unknown"),
                 obs(6,successful=8,outcome="success"),obs(7,mean=None)]
        r=aggregate([item(x) for x in records])
        self.assertEqual(r["excluded_records"],5)
        self.assertEqual(r["eligible_records"],2)
        t=r["cohorts"][0]["targets"][0]
        self.assertEqual(t["latency_by_protocol"],[])
        self.assertEqual(t["latency_exclusions"],{"unknown_or_mixed_protocol":1,"missing_or_inconsistent_latency":1})
        self.assertIn("incomplete_series",r["exclusion_reasons"])
        self.assertIn("inconsistent_outcome",r["exclusion_reasons"])

    def test_query_filters_empty_and_limits(self):
        with tempfile.TemporaryDirectory() as root:
            e=EvidenceStore(Path(root)/"intelligence.sqlite",clock=lambda:100.0);e.initialize()
            e.ingest("benchmark",1,(obs(1),obs(2,profile="warm")))
            e.ingest("agent",1,(obs(3,source="agent",vantage="agent:a"),))
            rows,usage=e.dns_cohort_rows(source="benchmark",since=99,before=101,profile=digest("cold"))
            self.assertEqual(len(rows),1)
            self.assertEqual(usage["rows"],2)
            self.assertEqual(e.dns_cohort_rows(source="benchmark",since=101,before=102)[0],[])
            self.assertEqual(aggregate([])["cohorts"],[])
            with self.assertRaises(ValueError): e.dns_cohort_rows(source="benchmark",since=0,before=31*86400)
        with self.assertRaises(NarrowQuery): aggregate([item(obs(1))]*(MAX_RECORDS+1))
        with self.assertRaises(NarrowQuery): aggregate([item(obs(i,target=str(i))) for i in range(101)])

if __name__=="__main__":
    unittest.main()
