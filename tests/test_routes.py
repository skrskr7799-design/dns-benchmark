import os
import socket
import struct
import unittest
from unittest.mock import patch
from backend.ndc.models import RouteTarget
from backend.ndc.probes.routes import decode_error,trace_family,route_capabilities
from backend.ndc.scope import ScopeError

class RouteTests(unittest.TestCase):
    def test_ipv4_parser(self):
        err=struct.pack("=IBBBBII",113,2,11,0,0,0,0)
        addr=struct.pack("=H",socket.AF_INET)+b"\0\0"+socket.inet_aton("192.0.2.1")+b"\0"*8
        row=decode_error([(socket.IPPROTO_IP,11,err+addr)],"ipv4")
        self.assertEqual(row["status"],"hop")
        self.assertEqual(row["address"],"192.0.2.1")
        self.assertIsNone(decode_error([(socket.IPPROTO_IP,11,b"short")],"ipv4"))

    def test_ipv6_parser(self):
        err=struct.pack("=IBBBBII",111,3,1,4,0,0,0)
        addr=struct.pack("=H",socket.AF_INET6)+b"\0"*6+socket.inet_pton(socket.AF_INET6,"2001:db8::1")+b"\0"*4
        row=decode_error([(socket.IPPROTO_IPV6,25,err+addr)],"ipv6")
        self.assertEqual(row["status"],"port_unreachable")
        self.assertEqual(row["address"],"2001:db8::1")

    def test_limits(self):
        for kwargs in ({"max_hops":21},{"attempts":3},{"port":443},{"host":"https://example.com"}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                RouteTarget(**({"host":"localhost"}|kwargs))

    def test_unavailable(self):
        with patch("backend.ndc.probes.routes.route_socket",side_effect=PermissionError("fixture")):
            r=trace_family(RouteTarget(host="localhost"),"ipv4")
        self.assertFalse(r["available"])
        self.assertEqual(r["hops"],[])

    def test_scope(self):
        with patch("backend.ndc.probes.routes.resolve_host",side_effect=ScopeError("blocked")),patch("backend.ndc.probes.routes.probe") as probe:
            r=trace_family(RouteTarget(host="169.254.169.254"),"ipv4")
            probe.assert_not_called()
        self.assertFalse(r["reached"])

    def test_loopback(self):
        if not route_capabilities()["ipv4"]:
            self.skipTest("Kernel error queue unavailable")
        with patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32"}):
            r=trace_family(RouteTarget(host="127.0.0.1",max_hops=2),"ipv4")
        self.assertTrue(r["reached"],r)
        self.assertEqual(r["hops"][0]["samples"][0]["address"],"127.0.0.1")
        self.assertEqual(len(r["hops"]),1)

if __name__=="__main__":
    unittest.main()
