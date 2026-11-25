import unittest
import tempfile
from pathlib import Path
from backend.ndc.dns_intelligence import rank,PRESETS,component
from backend.ndc.benchmark_evidence import project
from backend.ndc.storage import Store

A="udp://127.0.0.1"
B="udp://127.0.0.2"
CFG={"endpoints":[A,B],"count":10,"mode":"cold","family":"ipv4","parallel":1}
def make(run,ordinal,*,cfg=CFG,ok=10,ms=10,ip=None,mode="cold",protocol="udp",warm=True):
    endpoint=cfg["endpoints"][ordinal//2 if cfg["mode"]=="both" else ordinal]
    addr=ip or endpoint.split("://")[1]
    row={"endpoint":endpoint,"ip":addr,"mode":mode,"family":cfg["family"],"engine":"python-dns02",
        "count":cfg["count"],"requested_count":cfg["count"],"ok":ok,"mean":ms,"p50":ms,"p95":ms+5,"p99":ms+10,
        "jitter":2,"protocols":[protocol] if ok else [],"warmup":{"ok":warm},"peer_ips":[],
        "samples":[{"index":i,"domain":"example.com","qtype":"A","ok":i<ok} for i in range(cfg["count"])]}
    o=project(run,ordinal,cfg,row,100.0)
    return {"id":o.identity,"received_at":100.0,"record":o.model_dump(mode="json")}, {"endpoint":endpoint,"ip":addr,"mode":mode}
def fixture(n=3,slow=40,success=10,cfg=CFG):
    rows=[];meta={}
    for i in range(n):
        run="run"+str(i);results={}
        for j in range(2):
            item,m=make(run,j,cfg=cfg,ms=10 if j==0 else slow,ok=10 if j==0 else success)
            rows.append(item);results[j]=m
        meta[run]={"status":"completed","config":cfg,"results":results}
    return rows,meta

class Tests(unittest.TestCase):
    def test_rating_explanation_and_presets(self):
        rows,meta=fixture()
        for preset in PRESETS:
            g=rank(rows,meta,preset)["groups"][0]
            self.assertEqual(g["matched_runs"],3)
            self.assertEqual(g["targets"][0]["endpoint"],A)
            self.assertEqual(g["recommended_target_id"],g["targets"][0]["target_id"])
            t=g["targets"][0]
            self.assertAlmostEqual(sum(x["contribution"] for x in t["components"].values()),t["score"],places=2)
            self.assertEqual(t["observed_success_ratio"],1)
        self.assertGreater(component(10,20),component(40,20))

    def test_insufficient_and_missing_run(self):
        rows,meta=fixture(2)
        g=rank(rows,meta)["groups"][0]
        self.assertIsNone(g["recommended_target_id"])
        self.assertTrue(all(t["score"] is None for t in g["targets"]))
        rows,meta=fixture(3)
        rows.pop()
        r=rank(rows,meta)
        self.assertEqual(r["excluded_run_groups"]["unmatched_or_duplicate_target_set"],1)
        self.assertEqual(r["groups"][0]["matched_runs"],2)
        del meta["run0"]
        self.assertEqual(rank(rows,meta)["excluded_run_groups"]["missing_or_noncompleted_source_run"],1)

    def test_failure_denominator_and_no_false_latency(self):
        rows,meta=fixture(3,success=0)
        g=rank(rows,meta)["groups"][0]
        failed=next(t for t in g["targets"] if t["endpoint"]==B)
        self.assertEqual(failed["attempted"],30)
        self.assertEqual(failed["observed_success_ratio"],0)
        self.assertIsNone(failed["score"])
        self.assertIsNone(g["recommended_target_id"])

    def test_tie_pending_and_changed_ip(self):
        rows,meta=fixture(slow=10)
        g=rank(rows,meta)["groups"][0]
        self.assertIsNone(g["recommended_target_id"])
        self.assertEqual([t["rank"] for t in g["targets"]],[1,1])
        rows,meta=fixture()
        self.assertIsNone(rank(rows,meta,pending=1)["groups"][0]["recommended_target_id"])
        rows[-1],meta["run2"]["results"][1]=make("run2",1,ip="127.0.0.3")
        r=rank(rows,meta)
        self.assertEqual(sorted(g["matched_runs"] for g in r["groups"]),[1,2])
        self.assertTrue(all(g["recommended_target_id"] is None for g in r["groups"]))

    def test_mixed_protocol_and_failed_warmup(self):
        rows,meta=fixture()
        rows[-1],meta["run2"]["results"][1]=make("run2",1,protocol="tcp")
        self.assertEqual(rank(rows,meta)["excluded_run_groups"]["ineligible_or_mismatched_series"],1)
        cfg=CFG|{"mode":"warm"}
        rows,meta=fixture(cfg=cfg)
        for i in range(3):
            for j in range(2):
                rows[i*2+j],meta["run"+str(i)]["results"][j]=make("run"+str(i),j,cfg=cfg,mode="warm",warm=j==0)
        self.assertEqual(rank(rows,meta)["groups"],[])

    def test_source_metadata_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            s=Store(Path(root)/"history.sqlite");s.initialize()
            id=s.create(CFG);s.claim()
            s.add_result(id,0,{"endpoint":A,"ip":"127.0.0.1","mode":"cold","count":10,"ok":0})
            s.finish(id,"completed")
            meta=s.ranking_metadata([id])
            self.assertEqual(meta[id]["results"][0],{"endpoint":A,"ip":"127.0.0.1","mode":"cold"})
            s.delete_run(id)
            self.assertEqual(s.ranking_metadata([id]),{})

if __name__=="__main__":
    unittest.main()
