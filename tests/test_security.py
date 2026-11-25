import ipaddress
import socket
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from urllib.parse import urlsplit
from backend.ndc.scope import validate_ip, ScopeError
from backend.ndc.probes.dns import resolve, query
from backend.ndc.models import Run

class ScopeTest(unittest.TestCase):
    def test_public_and_explicit_lan(self):
        self.assertEqual(validate_ip("1.1.1.1",()),"1.1.1.1")
        self.assertEqual(validate_ip("2606:4700:4700::1111",()),"2606:4700:4700::1111")
        with self.assertRaises(ScopeError):
            validate_ip("192.168.0.108",())
        self.assertEqual(validate_ip("192.168.0.108",(ipaddress.ip_network("192.168.0.108/32"),)),"192.168.0.108")

    def test_metadata_even_with_allowlist(self):
        all_networks=(ipaddress.ip_network("0.0.0.0/0"),ipaddress.ip_network("::/0"))
        for address in ["169.254.169.254","100.100.100.200","168.63.129.16","::ffff:169.254.169.254","fe80::1","fd00:ec2::254","64:ff9b::a9fe:a9fe","224.0.0.1"]:
            with self.subTest(address=address),self.assertRaises(ScopeError):
                validate_ip(address,all_networks)

    def test_mixed_resolution_rejected(self):
        addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("1.1.1.1",443)),(socket.AF_INET,socket.SOCK_STREAM,6,"",("169.254.169.254",443))]
        with patch("socket.getaddrinfo",return_value=addresses),self.assertRaises(ScopeError):
            resolve(urlsplit("https://resolver.example/dns-query"),"ipv4")

    def test_https_session_pinned_and_redirects_disabled(self):
        with ExitStack() as stack,patch("dns.query.https") as call:
            resources={}
            query("https://resolver.example/dns-query","example.com","1.1.1.1",stack,resources)
            kwargs=call.call_args.kwargs
            self.assertEqual(kwargs["bootstrap_address"],"1.1.1.1")
            self.assertTrue(kwargs["verify"])
            client=kwargs["session"]
            self.assertFalse(client.follow_redirects)
            self.assertEqual(client._transport._pool._network_backend._bootstrap_address,"1.1.1.1")
            query("https://resolver.example/dns-query","example.org","1.1.1.1",stack,resources)
            self.assertIs(call.call_args.kwargs["session"],client)
        with ExitStack() as stack,patch("dns.query.https") as call:
            with self.assertRaises(ScopeError):
                query("https://resolver.example/dns-query","example.com","169.254.169.254",stack,{})
            call.assert_not_called()

    def test_url_validation(self):
        for endpoint in ["https://name:secret@resolver.example/dns-query","https://resolver.example/dns-query?token=secret","https://resolver.example/dns-query#secret","udp://127.0.0.1:0"]:
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):
                Run(endpoints=[endpoint])

if __name__=="__main__":
    unittest.main()
