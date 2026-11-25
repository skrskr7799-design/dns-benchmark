import tempfile
import unittest
from pathlib import Path
from backend.ndc.observatory import analyze,MAX_ROWS
from backend.ndc.dns_cohorts import NarrowQuery
from backend.ndc.monitor_evidence import project
from backend.ndc.models import MonitorConfig
from backend.ndc.monitoring import MonitorStore
from backend.ndc.evidence import EvidenceStore
from backend.ndc.evidence_drain import EvidenceDrain
from backend.ndc.storage import Store

CFG=MonitorConfig(name="fixture",host="localhost",kind="tcp",interval_seconds=60)
MON={"id":"a"*32,"config":CFG.model_dump(),"enabled":True,"state":"healthy","last_at":None}
def row(i,latency=10.,outcome="healthy",ip="127.0.0.1",at=None,cfg=CFG):
    at=1000+i*60 if at is None else at
    o,_=project(MON["id"],i+1,cfg,{"outcome":outcome,"latency_ms":latency,"details":{"ip":ip}},at)
    return {"id":o.identity,"received_at":at+3,"record":o.model_dump(mode="json")}
def report(rows,monitor=MON,before=None):
    before=before or (rows[-1]["record"]["observed_at"]+1 if rows else 1000)
    return analyze(rows,monitor,since=0,before=before,now=before)

class Tests(unittest.TestCase):
    def test_baseline_detection_recovery(self):
        rows=[row(i) for i in range(12)]+[row(12,50),row(13,51),row(14,10),row(15,10)]
        r=report(rows)
        self.assertEqual([p["state"] for p in r["points"][-4:]],["candidate","anomaly","recovering","normal"])
        self.assertEqual(r["points"][12]["threshold_ms"],15)
        self.assertEqual([s["type"] for s in r["signals"]],["anomaly.detected","anomaly.recovered"])
        self.assertEqual(r["signals"][0]["evidence_id"],rows[13]["id"])
        self.assertEqual(r["observed_healthy_ratio"],1)

    def test_sparse_and_missing_are_not_failures(self):
        rows=[row(i) for i in range(12)]+[row(12,50),row(13,50),row(20,None,"unknown",None),row(21,50)]
        r=report(rows)
        self.assertEqual(r["gap_count"],1)
        self.assertEqual(r["counts"]["unknown"],1)
        self.assertEqual(r["counts"]["failure"],0)
        self.assertEqual(r["signals"][-1]["type"],"anomaly.interrupted")
        self.assertEqual(r["points"][-1]["state"],"learning")
        self.assertIsNone(r["points"][-2]["latency_ms"])

    def test_identity_and_degradation(self):
        rows=[row(i) for i in range(12)]+[row(12,50),row(13,50,ip="127.0.0.2")]
        r=report(rows)
        self.assertEqual(r["points"][-1]["state"],"learning")
        self.assertEqual(r["signals"],[])
        r=report([row(0,10,"degraded"),row(1,None,"failed"),row(2,None,"unknown")])
        self.assertEqual(r["observed_healthy_ratio"],0)
        self.assertEqual(r["counts"]["known"],2)
        self.assertEqual(r["points"][0]["baseline_samples"],0)

    def test_pause_stale_and_empty(self):
        r=report([])
        self.assertIsNone(r["observed_healthy_ratio"])
        self.assertEqual(r["current_state"],"stale")
        self.assertEqual(report([row(0)],MON|{"enabled":False})["current_state"],"paused")
        self.assertEqual(report([row(0)],before=2000)["current_state"],"stale")
        self.assertIsNone(analyze([row(0)],MON,since=0,before=1100,now=3000)["current_state"])
        with self.assertRaises(NarrowQuery): report([row(0)]*(MAX_ROWS+1))

    def test_store_projection_and_window(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);now=[1000.]
            m=MonitorStore(root/"monitoring.sqlite",lambda:now[0]);m.initialize()
            b=Store(root/"history.sqlite");b.initialize()
            e=EvidenceStore(root/"intelligence.sqlite",clock=lambda:now[0]+3);e.initialize()
            d=EvidenceDrain(b,m,e,lambda:now[0])
            id=m.create(CFG)["id"]
            for i in range(14):
                self.assertEqual(m.claim()["id"],id)
                m.finish(id,{"outcome":"healthy","latency_ms":10 if i<12 else 50,"details":{"ip":"127.0.0.1"}})
                d.once("monitor-v1");now[0]+=60
            rows,usage=e.observatory_rows(id,since=1000,before=now[0])
            self.assertEqual(usage["rows"],15)
            self.assertEqual(len(rows),14)
            result=report(rows,m.get(id),now[0])
            self.assertEqual(result["signals"][0]["type"],"anomaly.detected")
            self.assertEqual(len(e.observatory_rows(id,since=1000,before=1002)[0]),1)
            self.assertEqual(e.observatory_rows("b"*32,since=1000,before=now[0])[0],[])
            with self.assertRaises(ValueError): e.observatory_rows(id,since=0,before=8*86400)

if __name__=="__main__":
    unittest.main()
