import concurrent.futures
import os
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from backend.ndc.storage import Store,Busy
from backend.ndc.integration_worker import bounded

CFG={"endpoints":["udp://127.0.0.1"],"count":1,"mode":"cold","family":"ipv4","parallel":1}

class Slow(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length","10000")
        self.end_headers()
        try:
            for _ in range(100):
                self.wfile.write(b"x");self.wfile.flush();time.sleep(.1)
        except OSError:
            pass
    def log_message(self,*args):
        pass

class PerformanceTests(unittest.TestCase):
    def test_concurrent_admission_claim_and_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp)/"history.sqlite")
            store.initialize()
            def submit(_):
                try:
                    return store.create(CFG)
                except Busy:
                    return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                ids=[x for x in pool.map(submit,range(24)) if x]
                self.assertEqual(len(ids),8)
                claims=[x for x in pool.map(lambda _:store.claim(),range(12)) if x]
                self.assertEqual(len(claims),1)
                id=claims[0]
                r=store.get(id)
                self.assertEqual(store.get(id,since=r["revision"]),{"revision":r["revision"],"status":"running","unchanged":True})
                store.add_result(id,0,{"count":1,"ok":1,"samples":[{"index":0}]})
                changed=store.get(id,since=r["revision"])
                self.assertEqual(changed["done"],1)
                self.assertNotIn("samples",changed["results"][0])
                store.finish(id,"completed")
                with self.assertRaises(Busy):
                    store.add_result(id,1,{"count":1})
                self.assertIsNotNone(store.claim())

    def test_slow_body_worker_deadline(self):
        srv=ThreadingHTTPServer(("127.0.0.1",0),Slow)
        thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
        try:
            cfg={"origin":f"http://127.0.0.1:{srv.server_port}","ip":"127.0.0.1","allow_http":True,"path":"/"}
            started=time.monotonic()
            with patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32"}):
                with self.assertRaises(subprocess.TimeoutExpired):
                    bounded("throughput",cfg,seconds=2)
            self.assertLess(time.monotonic()-started,5)
        finally:
            srv.shutdown();srv.server_close();thread.join(3)

if __name__=="__main__":
    unittest.main()
