import os
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from backend.ndc.peer_contract import PeerDirection,RTTPlan,RTTReport,RTTSample,LocalGrants

class Tests(unittest.TestCase):
    def setUp(self):
        env=patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.0/8"})
        env.start();self.addCleanup(env.stop)
        self.now=100.
        self.d=PeerDirection(source_agent_id="a"*32,destination_agent_id="b"*32,
            source_ip="127.0.0.1",destination_ip="127.0.0.2",port=8443,
            source_certificate="1"*64,destination_certificate="2"*64)
        self.p=RTTPlan(request_id="c"*32,direction=self.d,samples=3)
        self.g=LocalGrants("b"*32,[self.d],clock=lambda:self.now)
    def test_one_use_and_binding(self):
        token=self.g.issue(self.p)
        other=self.d.model_copy(update={"source_certificate":"3"*64})
        self.assertIsNone(self.g.consume(token,self.p,verified_direction=other))
        other_plan=self.p.model_copy(update={"samples":5})
        self.assertIsNone(self.g.consume(token,other_plan,verified_direction=self.d))
        self.assertEqual(self.g.consume(token,self.p,verified_direction=self.d),110.)
        self.assertIsNone(self.g.consume(token,self.p,verified_direction=self.d))
    def test_expiry_restart_and_revoke(self):
        token=self.g.issue(self.p,ttl=2)
        self.now+=2
        self.assertIsNone(self.g.consume(token,self.p,verified_direction=self.d))
        token=self.g.issue(self.p)
        self.assertIsNone(LocalGrants("b"*32,[self.d]).consume(token,self.p,verified_direction=self.d))
        self.g.revoke_all()
        self.assertIsNone(self.g.consume(token,self.p,verified_direction=self.d))
    def test_concurrent_consume(self):
        token=self.g.issue(self.p);gate=threading.Barrier(8)
        def consume(_):
            gate.wait()
            return self.g.consume(token,self.p,verified_direction=self.d)
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(r is not None for r in pool.map(consume,range(8))),1)
    def test_default_deny_and_scope(self):
        with self.assertRaises(PermissionError):LocalGrants("b"*32,[]).issue(self.p)
        with self.assertRaises(ValueError):LocalGrants("a"*32,[self.d])
        blocked=self.d.model_copy(update={"source_ip":"169.254.169.254"})
        with self.assertRaises(PermissionError):LocalGrants("b"*32,[blocked]).issue(self.p.model_copy(update={"direction":blocked}))
        token=self.g.issue(self.p)
        with patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":""}):
            self.assertIsNone(self.g.consume(token,self.p,verified_direction=self.d))
    def test_rate_and_clock(self):
        for i in range(16):
            p=self.p.model_copy(update={"request_id":format(i,"032x")})
            token=self.g.issue(p)
            self.assertIsNotNone(self.g.consume(token,p,verified_direction=self.d))
        with self.assertRaises(RuntimeError):self.g.issue(self.p)
        self.now+=60
        token=self.g.issue(self.p)
        self.now-=1
        with self.assertRaises(RuntimeError):self.g.consume(token,self.p,verified_direction=self.d)
    def test_rtt_missing_is_unknown(self):
        report=RTTReport(plan=self.p,samples=[RTTSample(index=1,status="echo",rtt_ms=1.25),RTTSample(index=2,status="unknown")])
        self.assertEqual(report.summary()["unknown"],2)
        self.assertEqual(report.summary()["rtt_ms"],[1.25])
        self.assertIsNone(report.summary()["one_way_latency"])
        with self.assertRaises(ValueError):RTTSample(index=1,status="unknown",rtt_ms=0.)
        with self.assertRaises(ValueError):RTTPlan(request_id="c"*32,direction=self.d,samples=6)
        with self.assertRaises(ValueError):RTTReport(plan=self.p,samples=[RTTSample(index=2,status="unknown")])
if __name__=="__main__":unittest.main()
