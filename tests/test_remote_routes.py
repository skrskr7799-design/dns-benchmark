import os
import threading
import unittest
from unittest.mock import patch
from backend.ndc.remote_contract import RemoteRoute,RemoteResult,RouteObservation,RouteHop,config_key,validate_remote,project_remote
from backend.ndc.remote_worker import Approval,run_probe,probe,route_capabilities

class Tests(unittest.TestCase):
    def test_real_loopback(self):
        if not route_capabilities()["ipv4"]:self.skipTest("Kernel extended errors unavailable")
        cfg=RemoteRoute(host="127.0.0.1",max_hops=2)
        with patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32"}):
            row,error=run_probe(cfg,(Approval(config=cfg,cidrs=["127.0.0.1/32"]),),threading.Event())
            self.assertIsNone(error);self.assertTrue(row.reached);self.assertEqual(row.hops[0].address,"127.0.0.1")
            self.assertEqual(row.outcome,"success")
    def test_partial_timeout_and_denial(self):
        cfg=RemoteRoute(host="127.0.0.1",max_hops=2)
        approval=Approval(config=cfg,cidrs=["127.0.0.1/32"])
        samples=[{"status":"hop","address":"127.0.0.2","rtt_ms":0.0},{"status":"timeout","address":None,"rtt_ms":None}]
        with patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32"}),patch("backend.ndc.remote_worker.route_socket"),patch("backend.ndc.remote_worker.route_hop",side_effect=samples):
            row=probe(cfg,approval)
        self.assertEqual(row.outcome,"partial");self.assertFalse(row.reached)
        self.assertIsNone(row.hops[1].address)
        body=RemoteResult(version="2",engine="python-network-v2",kind="route",lease="a"*43,config_key=config_key(cfg),status="completed",observation=row)
        validate_remote(cfg,body)
        obs=project_remote("a"*32,"b"*32,cfg,body)
        self.assertEqual((obs.outcome,obs.protocol,obs.provenance),("partial","udp","agent_claim"))
        self.assertIsNone(next(m.value for m in obs.measurements if m.name=="destination_reached"))
        self.assertEqual(run_probe(cfg,(),threading.Event()),(None,"local_policy_denied"))
        with patch("backend.ndc.remote_worker.route_socket",side_effect=OSError):
            row=probe(cfg,approval)
        self.assertEqual((row.stage,row.outcome),("unavailable","unknown"))
    def test_strict_contract(self):
        cfg=RemoteRoute(host="127.0.0.1",max_hops=2)
        for kw in ({"max_hops":9},{"port":123},{"attempts":2}):
            with self.assertRaises(ValueError):RemoteRoute(**({"host":"127.0.0.1"}|kw))
        with self.assertRaises(ValueError):RouteHop(ttl=1,status="timeout",address="127.0.0.1")
        with self.assertRaises(ValueError):RouteObservation(outcome="success",stage="trace",address="127.0.0.1",reached=True,total_ms=2.,hops=[{"ttl":1,"status":"destination","address":"127.0.0.2","rtt_ms":1.}])
        row=RouteObservation(outcome="unknown",stage="trace",address="127.0.0.1",total_ms=2.,hops=[{"ttl":1,"status":"timeout"}])
        body=RemoteResult(version="2",engine="python-network-v2",kind="route",lease="a"*43,config_key=config_key(cfg),status="completed",observation=row)
        with self.assertRaises(ValueError):validate_remote(cfg,body)

if __name__=="__main__":unittest.main()
