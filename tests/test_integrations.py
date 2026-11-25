import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
from backend.ndc.integrations import Target,snapshot,throughput,config_file,safe_upstream,MAX_DOWNLOAD
class Fixture(BaseHTTPRequestHandler):
    calls=[]
    def do_GET(self):
        self.calls.append((self.path,self.headers.get("Authorization")))
        if self.path=="/control/status":
            body={"version":"v0.fixture","running":True,"protection_enabled":True}
        elif self.path=="/control/stats":
            body={"num_dns_queries":100,"num_blocked_filtering":20,"avg_processing_time":.015,"top_queried_domains":[{"private.test":5}],"top_clients":[{"192.168.1.2":5}],"top_upstreams_avg_time":[{"https://resolver.test/secret":.02}]}
        elif self.path=="/control/dns_info":
            body={"upstream_dns":["https://resolver.test/secret","[/private.test/]1.1.1.1"]}
        elif self.path=="/file":
            payload=b"x"*32768
            self.send_response(200);self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload);return
        elif self.path=="/large":
            self.send_response(200);self.send_header("Content-Length",str(MAX_DOWNLOAD+32768));self.end_headers()
            try:
                for _ in range((MAX_DOWNLOAD+32768)//32768):
                    self.wfile.write(b"x"*32768)
            except OSError:
                pass
            return
        elif self.path=="/redirect":
            self.send_response(302);self.send_header("Location","http://169.254.169.254/");self.end_headers();return
        else:
            self.send_response(404);self.end_headers();return
        payload=json.dumps(body).encode()
        self.send_response(200);self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload)
    def log_message(self,*args):
        pass

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        Fixture.calls=[]
        self.server=ThreadingHTTPServer(("127.0.0.1",0),Fixture)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        env=patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32"})
        env.start();self.addCleanup(env.stop)
        self.cfg={"origin":f"http://fixture.invalid:{self.server.server_port}","ip":"127.0.0.1","allow_http":True}
    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3)
    def test_snapshot(self):
        r=snapshot(Target(self.cfg|{"username":"owner","password":"fixture"}))
        self.assertEqual(r["errors"],{},r)
        self.assertEqual(r["queries"],100)
        self.assertEqual(r["mean_ms"],15)
        self.assertEqual(r["upstreams"],["https://resolver.test"])
        self.assertEqual(r["upstream_timings"][0]["mean_ms"],20)
        self.assertEqual([p for p,_ in Fixture.calls],["/control/status","/control/stats","/control/dns_info"])
        self.assertTrue(all(a=="Basic b3duZXI6Zml4dHVyZQ==" for _,a in Fixture.calls))
        for secret in ("secret","private.test","192.168.1.2","fixture.invalid"):
            self.assertNotIn(secret,json.dumps(r))
    def test_download_and_redirect(self):
        r=throughput(Target(self.cfg),"/file")
        self.assertEqual(r["bytes"],32768,r)
        self.assertEqual(r["reason"],"complete")
        self.assertGreater(r["mbps"],0)
        r=throughput(Target(self.cfg),"/redirect")
        self.assertEqual(r["bytes"],0)
        self.assertIsNone(r["mbps"])
        self.assertEqual([p for p,_ in Fixture.calls],["/file","/redirect"])
    def test_byte_cap(self):
        r=throughput(Target(self.cfg),"/large")
        self.assertEqual(r["bytes"],MAX_DOWNLOAD,r)
        self.assertEqual(r["reason"],"byte_limit")
    def test_scope(self):
        for cfg in (self.cfg|{"ip":"169.254.169.254"},self.cfg|{"allow_http":False},self.cfg|{"ip":"1.1.1.1"},self.cfg|{"origin":"http://127.0.0.2"}):
            with self.assertRaises(ValueError):
                Target(cfg)
    def test_private_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"adguard.json"
            self.assertIsNone(config_file(tmp,"adguard.json"))
            p.write_text(json.dumps(self.cfg));p.chmod(0o644)
            with self.assertRaises(ValueError):
                config_file(tmp,"adguard.json")
            p.chmod(0o600)
            self.assertEqual(config_file(tmp,"adguard.json"),self.cfg)
    def test_redaction(self):
        self.assertEqual(safe_upstream("https://user:pass@resolver.test/token?secret=1"),"https://resolver.test")
        self.assertIsNone(safe_upstream("[/private.test/]1.1.1.1"))
        self.assertIsNone(safe_upstream("file:///etc/passwd"))
if __name__=="__main__":
    unittest.main()
