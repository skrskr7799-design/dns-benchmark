import unittest
from unittest.mock import patch
from backend.ndc.diagnostics import classify, diagnose
from backend.ndc.models import DiagnosticConfig
from backend.ndc.probes.connectivity import base

class DiagnosticTests(unittest.TestCase):
    def config(self,**kwargs):
        return DiagnosticConfig(**({"host":"example.com"}|kwargs))

    def probe(self,**kwargs):
        return base("example.com",443,"ipv4")|kwargs

    def codes(self,probe,dns=()):
        return [f["code"] for f in classify(probe,dns,self.config().thresholds.model_dump())]

    def test_failure_layers(self):
        for stage,expected,extra in [
            ("resolve","resolution_failed",{}),
            ("resolve","scope_denied",{"error":"ScopeError: blocked"}),
            ("tcp","tcp_failed",{}),
            ("tls","certificate_rejected",{"verified":False}),
            ("tls","tls_failed",{}),
            ("http","http_exchange_failed",{})]:
            with self.subTest(stage=stage,expected=expected):
                self.assertIn(expected,self.codes(self.probe(**({"stage":stage,"error":"fixture"}|extra))))

    def test_http_status_and_thresholds(self):
        for status,code in [(204,"no_issue_observed"),(302,"http_redirect"),(403,"http_client_response"),(503,"http_server_error")]:
            self.assertIn(code,self.codes(self.probe(ok=True,stage="complete",http_status=status)))
        codes=self.codes(self.probe(ok=True,stage="complete",dns_ms=300,connect_ms=301,handshake_ms=501,ttfb_ms=1001,certificate={"days_remaining":3}))
        self.assertEqual(set(codes),{"slow_dns_ms","slow_connect_ms","slow_handshake_ms","slow_ttfb_ms","certificate_expiring"})

    def test_possible_not_certain(self):
        findings=classify(self.probe(stage="resolve",error="gaierror"),[{"outcome":"answer","endpoint":"udp://1.1.1.1"}],self.config().thresholds.model_dump())
        self.assertEqual(findings[1]["confidence"],"possible")

    def test_family_and_dns_difference(self):
        a=self.probe(ok=True,stage="complete",ip="192.0.2.1")
        b=self.probe(stage="resolve",error="gaierror")
        rows=[{"outcome":"answer","endpoint":"udp://1.1.1.1","comparison_group":1,"rcode":"NOERROR"},{"outcome":"nxdomain","endpoint":"udp://8.8.8.8","comparison_group":2,"rcode":"NXDOMAIN"}]
        with patch("backend.ndc.diagnostics.probe_once",side_effect=[a,b]),patch("backend.ndc.diagnostics.inspect",return_value={"results":rows,"agreement":False}) as dns:
            report=diagnose(self.config(family="both",endpoints=["udp://1.1.1.1","udp://8.8.8.8"]))
        self.assertEqual([c.args[0].qtype for c in dns.call_args_list],["A","AAAA"])
        self.assertTrue(all("family_asymmetry" in [f["code"] for f in r["findings"]] for r in report["results"]))
        self.assertIn("dns_answers_differ",[f["code"] for f in report["results"][0]["findings"]])

    def test_no_dns_on_scope_or_literal(self):
        for host,err in [("169.254.169.254","ScopeError: blocked"),("example.com","ScopeError: blocked"),("127.0.0.1","fixture")]:
            with patch("backend.ndc.diagnostics.probe_once",return_value=self.probe(error=err)),patch("backend.ndc.diagnostics.inspect") as dns:
                report=diagnose(self.config(host=host,endpoints=["udp://1.1.1.1"]))
                dns.assert_not_called()
                self.assertIsNotNone(report["results"][0]["dns_skipped"])

    def test_validation(self):
        for options in [{"endpoints":["udp://1.1.1.1"]*3},{"kind":"icmp"},{"count":2},{"thresholds":{"dns_ms":0}},{"path":"/?secret=x"}]:
            with self.subTest(options=options),self.assertRaises(ValueError):
                self.config(**options)

if __name__=="__main__":
    unittest.main()
