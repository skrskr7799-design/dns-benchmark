import os
import json
import tempfile
import unittest
import concurrent.futures
from pathlib import Path
from unittest.mock import patch
from fastapi import HTTPException,Request
from backend.ndc.security import Security,local_address,local_hostname,direct_local
from backend.ndc.backup import FILES

class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        p=patch.dict(os.environ,{},clear=False)
        p.start();self.addCleanup(p.stop)
        os.environ.pop("NDC_OWNER_PASSWORD",None)
        os.environ.pop("NDC_SECURE_COOKIE",None)
        os.environ.pop("NDC_ORIGIN",None)

    def test_one_owner_atomic_and_persistent(self):
        sec=Security(self.root)
        self.assertTrue(sec.setup_required)
        def create(_):
            try:
                sec.setup("admin","fixture-setup-password-2026")
                return 201
            except HTTPException as exc:
                return exc.status_code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(create,range(2))),[201,409])
        p=self.root/"owner-account.json"
        self.assertEqual(p.stat().st_mode&0o777,0o600)
        self.assertNotIn("fixture-setup-password-2026",p.read_text())
        self.assertIn(p.name,FILES)
        restarted=Security(self.root)
        self.assertFalse(restarted.setup_required)
        restarted.login("fixture-setup-password-2026","admin")
        for name,pwd in [("other","fixture-setup-password-2026"),("admin","incorrect")]:
            with self.assertRaises(HTTPException) as ctx:
                restarted.login(pwd,name)
            self.assertEqual(ctx.exception.status_code,401)

    def test_legacy(self):
        p=self.root/"owner-password"
        p.write_text("legacy-password-long");p.chmod(0o600)
        sec=Security(self.root)
        self.assertFalse(sec.setup_required)
        sec.login("legacy-password-long")
        with self.assertRaises(HTTPException):
            sec.setup("admin","fixture-setup-password-2026")
        self.assertFalse((self.root/"owner-account.json").exists())

    def test_local_scope(self):
        for ip in ("127.0.0.1","192.168.1.1","172.18.0.1","100.103.112.148","::1","fd00::1"):
            self.assertTrue(local_address(ip),ip)
        for ip in ("1.1.1.1","169.254.169.254","example.com","0.0.0.0"):
            self.assertFalse(local_address(ip),ip)

    def test_local_hostname_and_source_separation(self):
        for host in ("casaos.local","DNS-Benchmark.local","casaos.local.","room.server.local","192.168.0.108"):
            self.assertTrue(local_hostname(host),host)
        for host in ("local","evil.local.example.com","-bad.local","bad..local","1.1.1.1","example.com"):
            self.assertFalse(local_hostname(host),host)
        self.assertFalse(local_address("casaos.local"))
        def req(peer,host,headers=(),scheme="http"):
            return Request({"type":"http","method":"GET","path":"/api/auth/session",
                "root_path":"","scheme":scheme,"server":("127.0.0.1",8080),
                "client":(peer,12345),"headers":[(b"host",host.encode()),*headers]})
        sec=Security(self.root)
        valid=req("192.168.0.25","casaos.local:8099")
        self.assertTrue(direct_local(valid))
        self.assertFalse(sec.cookie_secure(valid))
        self.assertTrue(sec.cookie_secure(req("192.168.0.25","casaos.local:8099",scheme="https")))
        for denied in (req("8.8.8.8","casaos.local:8099"),
                       req("192.168.0.25","public.example.com"),
                       req("192.168.0.25","casaos.local:8099",[(b"x-forwarded-for",b"8.8.8.8")])):
            self.assertFalse(direct_local(denied))
            self.assertTrue(sec.cookie_secure(denied))

if __name__=="__main__":
    unittest.main()
