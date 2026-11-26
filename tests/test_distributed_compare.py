import unittest
from backend.ndc.distributed import compare
from backend.ndc.remote_contract import RemoteTCP,RemoteHTTP,RemoteRoute

def row(i,observation,*,finished=101.,lease_until=400.,state="completed"):
    return {"id":str(i)*32,"agent_id":str(i+3)*32,"finished":finished,"lease_until":lease_until,
        "state":state,"payload":{"observation":observation} if observation is not None else None}

def tcp(ip,**kw):
    return {"address":ip,"outcome":"success","stage":"complete","connect_ms":2.,"total_ms":4.}|kw

def route(ip,hops):
    return {"address":ip,"outcome":"partial","stage":"trace","hops":hops,"reached":False}

def hop(ttl,address,status="hop",rtt=1.):
    return {"ttl":ttl,"address":address,"status":status,"rtt_ms":rtt}

class Tests(unittest.TestCase):
    def report(self,cfg,rows):
        return compare(cfg,100.,220.,rows)
    def test_matching_phase_delta_and_unknown(self):
        cfg=RemoteTCP(host="example.com",port=443)
        r=self.report(cfg,[row(1,tcp("192.0.2.1")),row(2,tcp("192.0.2.1",connect_ms=3.,total_ms=6.)),
            row(3,tcp("192.0.2.2")),row(4,None,state="interrupted")])
        self.assertEqual(len(r["pairs"]),6)
        a,b,c=r["pairs"][:3]
        self.assertEqual(a["status"],"matched_single_samples")
        self.assertEqual(a["phase_deltas_ms"]["connect_ms"],1.)
        self.assertIsNone(a["phase_deltas_ms"]["dns_ms"])
        self.assertEqual(b["fields"]["address"]["status"],"different_observed")
        self.assertEqual(b["phase_deltas_ms"],{})
        self.assertEqual(c["reason"],"observation_missing")
    def test_invalid_controller_window(self):
        cfg=RemoteTCP(host="example.com",port=443)
        r=self.report(cfg,[row(1,tcp("192.0.2.1")),row(2,tcp("192.0.2.1"),finished=550.,lease_until=520.)])
        self.assertEqual(r["pairs"][0]["reason"],"controller_window_unverified")
        self.assertEqual(r["pairs"][0]["fields"],{})
    def test_http_failure_and_tls_identity(self):
        cfg=RemoteHTTP(host="example.com",port=443)
        o=tcp("192.0.2.1",verified=True,fingerprint="a"*64,tls_version="TLSv1.3",http_status=200,http_ms=1.)
        r=self.report(cfg,[row(1,o),row(2,o|{"fingerprint":"b"*64}),row(3,o|{"outcome":"failure","http_status":503})])
        self.assertEqual(r["pairs"][0]["fields"]["fingerprint"]["status"],"different_observed")
        self.assertEqual(r["pairs"][1]["fields"]["http_status"]["right"],503)
        self.assertTrue(all(not p["phase_deltas_ms"] for p in r["pairs"]))
    def test_routes_partial_same_destination(self):
        cfg=RemoteRoute(host="example.com")
        a=route("192.0.2.1",[hop(1,"192.0.2.3"),hop(2,"192.0.2.4"),hop(3,"192.0.2.5")])
        b=route("192.0.2.1",[hop(1,"192.0.2.3"),hop(2,None,"timeout",None),hop(3,"192.0.2.6")])
        c=route("192.0.2.2",[hop(1,"192.0.2.3")])
        r=self.report(cfg,[row(1,a),row(2,b),row(3,c)])
        p=r["pairs"][0]
        self.assertEqual([x["address"]["status"] for x in p["hops"]],["same_observed","unknown","different_observed"])
        self.assertIsNone(p["hops"][1]["right_rtt_ms"])
        self.assertEqual(p["phase_deltas_ms"],{})
        self.assertEqual(r["pairs"][1]["reason"],"destination_not_matched")
        self.assertEqual(r["pairs"][1]["hops"],[])
    def test_route_missing_tail_not_removal(self):
        cfg=RemoteRoute(host="example.com")
        a=route("192.0.2.1",[hop(1,"192.0.2.3"),hop(2,"192.0.2.4")])
        b=route("192.0.2.1",[hop(1,"192.0.2.3")])
        r=self.report(cfg,[row(1,a),row(2,b)])
        self.assertEqual(r["pairs"][0]["hops"][1]["address"]["status"],"unknown")

if __name__=="__main__":unittest.main()
