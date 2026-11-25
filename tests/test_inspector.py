import unittest
from unittest.mock import patch
import dns.message
import dns.flags
import dns.rcode
import dns.rrset
from backend.ndc.models import Inspect
from backend.ndc.probes.inspector import inspect, inspect_one

ENDPOINTS=["udp://127.0.0.1","udp://127.0.0.2"]

def config(**kwargs):
    return Inspect(**({"name":"Example.COM","endpoints":ENDPOINTS}|kwargs))

def response(qtype="A",rcode=dns.rcode.NOERROR,answer=(),authority=(),flags=0):
    r=dns.message.make_response(dns.message.make_query("example.com",qtype))
    r.set_rcode(rcode)
    r.flags|=flags
    r.answer.extend(answer)
    r.authority.extend(authority)
    return r

def rr(name,ttl,kind,*values):
    return dns.rrset.from_text(name,ttl,"IN",kind,*values)

class InspectorTest(unittest.TestCase):
    def setUp(self):
        p=patch("backend.ndc.probes.inspector.bootstrap",return_value=("127.0.0.1",1.0,None))
        p.start()
        self.addCleanup(p.stop)

    def test_name_ptr_limits(self):
        self.assertEqual(config().name,"example.com.")
        self.assertEqual(config(name="192.0.2.1",qtype="PTR").name,"1.2.0.192.in-addr.arpa.")
        self.assertTrue(config(name="2001:db8::1",qtype="PTR").name.endswith(".ip6.arpa."))
        for options in [{"name":"https://example.com"},{"qtype":"AXFR"},{"endpoints":ENDPOINTS*3},{"endpoints":["https://x.test/?token=x"]}]:
            with self.subTest(options=options),self.assertRaises(ValueError):
                config(**options)

    def test_groups_ignore_ttl_and_order(self):
        a=response(answer=[rr("example.com.",60,"A","192.0.2.1","192.0.2.2")])
        b=response(answer=[rr("example.com.",10,"A","192.0.2.2","192.0.2.1")])
        with patch("backend.ndc.probes.inspector.query",side_effect=[a,b]):
            result=inspect(config())
        self.assertTrue(result["agreement"])
        self.assertEqual(result["groups"],1)
        self.assertEqual(result["results"][0]["answer"][0]["ttl"],60)
        self.assertEqual(result["results"][1]["answer"][0]["ttl"],10)
        b=response(answer=[rr("example.com.",10,"A","192.0.2.3")])
        with patch("backend.ndc.probes.inspector.query",side_effect=[a,b]):
            result=inspect(config())
        self.assertFalse(result["agreement"])
        self.assertEqual(result["groups"],2)

    def test_distinct_outcomes(self):
        for r,expected in [(response(rcode=dns.rcode.NXDOMAIN),"nxdomain"),
                           (response(rcode=dns.rcode.SERVFAIL),"dns_error"),
                           (response(),"no_data"),
                           (response(flags=dns.flags.TC),"truncated"),
                           (response(answer=[rr("example.com.",60,"CNAME","target.example.")]),"alias_only"),
                           (response(authority=[rr("example.com.",60,"NS","ns.example.")]),"referral")]:
            with self.subTest(expected=expected),patch("backend.ndc.probes.inspector.query",return_value=r):
                result,_=inspect_one(ENDPOINTS[0],config())
                self.assertEqual(result["outcome"],expected)
                self.assertIsNone(result["error"])
        with patch("backend.ndc.probes.inspector.query",side_effect=TimeoutError("fixture")):
            result,_=inspect_one(ENDPOINTS[0],config())
        self.assertEqual(result["outcome"],"transport_error")
        self.assertIn("TimeoutError",result["error"])

    def test_flags_cname_and_ipv6(self):
        r=response(qtype="AAAA",flags=dns.flags.AD|dns.flags.CD,answer=[
            rr("example.com.",60,"CNAME","target.example."),
            rr("target.example.",20,"AAAA","2001:db8::1")])
        r.use_edns(edns=0,ednsflags=dns.flags.DO,payload=1232)
        with patch("backend.ndc.probes.inspector.query",return_value=r) as query:
            result,_=inspect_one(ENDPOINTS[0],config(qtype="AAAA",dnssec=True,checking_disabled=True))
        self.assertEqual(result["outcome"],"answer")
        self.assertEqual(result["cname_chain"][0]["target"],"target.example.")
        self.assertEqual(result["edns"]["payload"],1232)
        self.assertTrue(result["dnssec"]["ad"])
        self.assertTrue(result["dnssec"]["response_do"])
        self.assertFalse(result["dnssec"]["independently_validated"])
        self.assertTrue(query.call_args.kwargs["dnssec"])
        self.assertTrue(query.call_args.kwargs["checking_disabled"])
        self.assertEqual(query.call_args.kwargs["qtype"],"AAAA")

    def test_fallback_is_explicit_and_pinned(self):
        truncated=response(flags=dns.flags.TC)
        complete=response(answer=[rr("example.com.",60,"A","192.0.2.1")])
        with patch("backend.ndc.probes.inspector.query",side_effect=[truncated,complete]) as query:
            result,_=inspect_one("udp://127.0.0.1:5353",config(tcp_fallback=True))
        self.assertTrue(result["fallback"])
        self.assertEqual(result["outcome"],"answer")
        self.assertEqual(query.call_args_list[1].args[0],"tcp://127.0.0.1:5353")
        self.assertEqual(query.call_args_list[1].args[2],"127.0.0.1")
        with patch("backend.ndc.probes.inspector.query",return_value=truncated) as query:
            result,_=inspect_one("https://resolver.example/dns-query",config(tcp_fallback=True))
        self.assertFalse(result["fallback"])
        self.assertEqual(query.call_count,1)

if __name__=="__main__":
    unittest.main()
