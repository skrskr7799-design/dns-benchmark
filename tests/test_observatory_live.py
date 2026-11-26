"""Real scoped HTTP probes with accelerated scheduler clock, durable restore.
Latency measured by monotonic production probe; virtual clock advances only
monitor scheduling/retention. No external endpoints or injected latency values.
"""
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
from backend.ndc.models import MonitorConfig
from backend.ndc.monitoring import MonitorStore,MonitorScheduler
from backend.ndc.storage import Store
from backend.ndc.evidence import EvidenceStore
from backend.ndc.evidence_drain import EvidenceDrain
from backend.ndc.backup import backup,restore
from backend.ndc.observatory import analyze

class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.requests+=1
        time.sleep(self.server.delay)
        self.send_response(self.server.status)
        self.send_header("Content-Length","0")
        self.end_headers()
    def log_message(self,*args): pass

class Disabled:
    enabled=False

class Tests(unittest.TestCase):
    def test_real_latency_restart_restore_and_pause(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data=root/"data";data.mkdir()
            now=[100000.0];clock=lambda:now[0]
            server=HTTPServer(("127.0.0.1",0),Handler)
            server.delay=.001;server.status=200;server.requests=0
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(thread.join,3)
            self.addCleanup(server.shutdown)
            def open_stores(path):
                m=MonitorStore(path/"monitoring.sqlite",clock);m.initialize()
                b=Store(path/"history.sqlite");b.initialize()
                e=EvidenceStore(path/"intelligence.sqlite",clock=clock);e.initialize()
                return m,b,e,EvidenceDrain(b,m,e,clock)
            m,b,e,d=open_stores(data)
            cfg=MonitorConfig(name="controlled HTTP",host="127.0.0.1",port=server.server_port,
                kind="http",interval_seconds=60,notify=False)
            id=m.create(cfg)["id"]
            lock=threading.Lock()
            def tick():
                before=server.requests
                MonitorScheduler(m,lock,Disabled()).tick()
                self.assertEqual(server.requests,before+1)
                r=m.get(id)["last_result"]
                self.assertEqual(r["outcome"],"healthy",r)
                self.assertEqual(r["details"]["http_status"],200)
                now[0]+=60
                return r["latency_ms"]
            def snap():
                return m.observatory_snapshot(id,0,now[0]+1)
            def drain():
                while d.once("monitor-v1"): pass
            def types():
                return [x["type"] for x in snap()["journal"]]
            # Shared lane is not bypassed; no network check when occupied.
            with lock:
                MonitorScheduler(m,lock,Disabled()).tick()
            self.assertEqual(server.requests,0)
            normal=[tick() for _ in range(12)]
            self.assertEqual(snap()["baseline_samples_at_read"],12)
            server.delay=.200
            slow=[tick(),tick()]
            self.assertTrue(snap()["active_at_read"])
            self.assertEqual(types(),["tracking.started","anomaly.detected"])
            event=snap()["journal"][-1]
            self.assertGreater(event["latency_ms"],event["threshold_ms"])
            for _ in range(13): self.assertTrue(d.once("monitor-v1"))
            def crash(): raise RuntimeError("after derived commit")
            with self.assertRaises(RuntimeError): d.once("monitor-v1",crash)
            self.assertEqual(m.evidence_status()["pending"],1)
            backup(data,root/"backup");restore(root/"backup",root/"restored")
            m,b,e,d=open_stores(root/"restored")
            self.assertTrue(snap()["active_at_read"])
            drain()
            self.assertEqual(m.evidence_status()["pending"],0)
            self.assertEqual(len(e.page("events")["items"]),1)
            server.delay=.001
            recovery=[tick(),tick()]
            drain()
            self.assertFalse(snap()["active_at_read"])
            self.assertEqual(types(),["tracking.started","anomaly.detected","anomaly.recovered"])
            self.assertEqual([x["record"]["event_type"] for x in e.page("events")["items"]],["anomaly.detected","anomaly.recovered"])
            self.assertEqual(m.delivery_counts(),{})
            rows,_=e.observatory_rows(id,since=99999,before=now[0]+1)
            report=analyze(rows,m.get(id),since=99999,before=now[0]+1,now=now[0],boundaries=snap()["journal"])
            self.assertEqual(report["counts"]["total"],16)
            self.assertEqual(report["observed_healthy_ratio"],1)
            self.assertEqual([x["type"] for x in report["signals"]],["anomaly.detected","anomaly.recovered"])
            m.enable(id,False)
            before=server.requests
            MonitorScheduler(m,lock,Disabled()).tick()
            self.assertEqual(server.requests,before)
            now[0]+=30;m.enable(id,True);tick();drain()
            self.assertEqual(snap()["baseline_samples_at_read"],1)
            self.assertEqual(types()[-2:],["monitor.paused","monitor.resumed"])
            self.assertEqual(server.requests,17)
            self.assertEqual(len(e.page("events")["items"]),2)
            print({"healthy_latency_ms":normal,"degraded_latency_ms":slow,"recovery_latency_ms":recovery,
                "threshold_ms":event["threshold_ms"],"requests":server.requests,"backup_replay":"verified"})

if __name__=="__main__": unittest.main()
