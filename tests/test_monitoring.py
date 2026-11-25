import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from backend.ndc.models import MonitorConfig
from backend.ndc.monitoring import MonitorStore,MonitorScheduler,MonitorBusy,check

def obs(outcome):
    return {"outcome":outcome,"latency_ms":10 if outcome=="healthy" else None,"reason":outcome,"details":{}}

class MonitorTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.now=10000000
        self.s=MonitorStore(Path(tmp.name)/"monitoring.sqlite",lambda:self.now)
        self.s.initialize()
        self.cfg=MonitorConfig(name="fixture",host="localhost",failure_count=2,recovery_count=2,interval_seconds=60,notify=True)
        self.id=self.s.create(self.cfg)["id"]

    def advance(self,outcome):
        self.assertEqual(self.s.claim()["id"],self.id)
        self.assertIsNone(self.s.claim())
        self.s.finish(self.id,obs(outcome))
        self.assertIsNone(self.s.claim())
        self.now+=60

    def test_debounce_and_recovery(self):
        self.advance("failed")
        self.assertEqual(self.s.incidents(),[])
        self.advance("failed")
        self.assertEqual(len(self.s.incidents()),1)
        self.advance("degraded")
        self.assertEqual(len(self.s.incidents()),1)
        self.advance("healthy")
        self.assertIsNone(self.s.incidents()[0]["closed"])
        self.advance("healthy")
        self.assertIsNotNone(self.s.incidents()[0]["closed"])
        self.assertEqual(self.s.get(self.id)["state"],"healthy")
        self.assertEqual(len(self.s.history(self.id,100)),5)
        self.assertEqual(self.s.delivery_counts(),{"pending":2})

    def test_restart_and_pause(self):
        self.s.claim()
        self.s.initialize()
        self.assertEqual(self.s.claim()["id"],self.id)
        self.s.enable(self.id,False)
        with self.assertRaises(MonitorBusy):
            self.s.enable(self.id,True)
        self.s.finish(self.id,obs("failed"))
        self.assertEqual(self.s.history(self.id,100),[])
        self.assertIsNone(self.s.claim())
        self.s.enable(self.id,True)
        self.advance("healthy")

    def test_outbox_retry(self):
        self.advance("failed")
        self.advance("failed")
        row=self.s.delivery()
        self.assertEqual(row["attempts"],1)
        self.s.delivered(row,False)
        self.assertIsNone(self.s.delivery())
        self.now+=120
        row=self.s.delivery()
        self.assertEqual(row["attempts"],2)
        self.s.delivered(row,True)
        self.assertEqual(self.s.delivery_counts(),{"sent":1})

    def test_unknown_breaks_streak(self):
        self.advance("failed")
        self.advance("unknown")
        self.advance("failed")
        self.assertEqual(self.s.incidents(),[])

    def test_scheduler_busy_and_retention(self):
        class Disabled:
            enabled=False
        lock=threading.Lock()
        scheduler=MonitorScheduler(self.s,lock,Disabled(),lambda cfg:obs("healthy"))
        with lock:
            scheduler.tick()
        self.assertIsNone(self.s.get(self.id)["last_at"])
        scheduler.tick()
        self.assertEqual(len(self.s.history(self.id,10)),1)
        self.now+=31*86400
        self.s.prune()
        self.assertEqual(self.s.history(self.id,10),[])

    def test_thresholds(self):
        fixture={"ok":True,"http_status":200,"total_ms":120,"error":None,"ip":"127.0.0.1","stage":"complete","certificate":{"days_remaining":5}}
        cfg=MonitorConfig(name="tls",host="localhost",kind="https",latency_ms=100)
        with patch("backend.ndc.monitoring.probe_once",return_value=fixture):
            result=check(cfg)
        self.assertEqual(result["outcome"],"degraded")
        self.assertEqual(result["details"]["certificate_days"],5)
        with self.assertRaises(ValueError):
            MonitorConfig(name="invalid",host="localhost",interval_seconds=5)

if __name__=="__main__":
    unittest.main()
