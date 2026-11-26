import ipaddress
import os
import socket
import threading
import unittest
from unittest.mock import patch
from backend.ndc.internet_atlas import AtlasRequest,iana_base,execute,run,provider_ip,rdap
from backend.ndc.web_xray import XRayRequest,canonical_url,header_projection,execute as xray_execute,run as xray_run

class Tests(unittest.TestCase):
    def test_atlas_scope_and_bootstrap(self):
        self.assertEqual(AtlasRequest(target="as123").target,"AS123")
        for ip in ("127.0.0.1","169.254.169.254","10.0.0.1"):
            with self.assertRaises(ValueError):AtlasRequest(target=ip)
        p=AtlasRequest(target="AS123")
        with patch.dict(os.environ,{"NDC_ATLAS_ENABLED":"0"}):
            with self.assertRaises(PermissionError):run(p)
        with patch("backend.ndc.internet_atlas.get",return_value={"services":[[["0.0.0.0/0"],["https://rdap.arin.net/registry/"]],[["8.8.8.0/24"],["https://attacker.test/"]]]}):
            self.assertIsNone(iana_base(None,ipaddress.ip_address("8.8.8.8")))
        with patch("backend.ndc.internet_atlas.get",return_value={"services":[[["8.8.8.0/24"],["https://rdap.arin.net/registry/"]]]}):
            self.assertEqual(iana_base(None,ipaddress.ip_address("8.8.8.8")),"https://rdap.arin.net/registry/")

    def test_atlas_metadata_projection(self):
        def get(client,url,params=None):
            if url.endswith("ipv4.json"):return {"services":[[["8.8.8.0/24"],["https://rdap.arin.net/registry/"]]]}
            if "/ip/" in url:return {"objectClassName":"ip network","startAddress":"8.8.8.0","endAddress":"8.8.8.255","name":"fixture allocation","country":"US","entities":[{"secret":"do not expose"}]}
            if "network-info" in url:return {"status":"ok","data":{"prefix":"8.8.8.0/24","asns":["15169"]}}
            if "rpki-validation" in url:return {"status":"ok","data":{"status":"valid"}}
            raise AssertionError(url)
        with patch.dict(os.environ,{"NDC_ATLAS_ENABLED":"1"}),patch("backend.ndc.internet_atlas.get",side_effect=get):
            r=execute(AtlasRequest(target="8.8.8.8"))
        self.assertEqual(r["errors"],{})
        self.assertEqual(r["data"]["ripe_network_info"]["value"]["origin_asns"],[15169])
        self.assertNotIn("secret",str(r))
        self.assertEqual(r["data"]["ripe_rpki"]["value"]["results"][0]["status"],"valid")

    def test_provider_resolution_and_resource_binding(self):
        addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("8.8.8.8",443)),
            (socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",443))]
        with patch("socket.getaddrinfo",return_value=addresses):
            with self.assertRaises(ValueError):provider_ip("stat.ripe.net")
        with patch("socket.getaddrinfo",return_value=addresses[:1]):
            self.assertEqual(provider_ip("stat.ripe.net"),"8.8.8.8")
            with self.assertRaises(ValueError):provider_ip("example.test")
        with patch("backend.ndc.internet_atlas.iana_base",return_value="https://rdap.arin.net/registry/"),patch("backend.ndc.internet_atlas.get",return_value={"objectClassName":"ip network","startAddress":"1.1.1.0","endAddress":"1.1.1.255"}):
            with self.assertRaises(ValueError):rdap(None,ipaddress.ip_address("8.8.8.8"))
        with patch("backend.ndc.internet_atlas.iana_base",return_value="https://rdap.arin.net/registry/"),patch("backend.ndc.internet_atlas.get",return_value={"objectClassName":"autnum","startAutnum":100,"endAutnum":200}):
            self.assertEqual(rdap(None,asn=123)["start_as"],100)
            with self.assertRaises(ValueError):rdap(None,asn=300)

    def test_xray_url_and_header_redaction(self):
        self.assertEqual(canonical_url("https://example.com:443/"),"https://example.com/")
        for url in ("file:///etc/passwd","https://u:p@example.com/","https://example.com/?token=x","https://example.com:8443/","https://example.com//x"):
            with self.assertRaises(ValueError):XRayRequest(url=url)
        h=header_projection(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nSet-Cookie: secret=x\r\nCache-Control: no-cache\r\nContent-Security-Policy: nonce-secret")
        self.assertEqual(h["_redirect_location"],"/next");self.assertNotIn("secret",str(h))
        self.assertIn("set-cookie",h["header_presence"])
        with self.assertRaises(ValueError):header_projection(b"HTTP/1.1 200 OK\r\n folded")

    def test_redirect_limits_and_no_downgrade(self):
        for location,expected in (("http://example.com/","https_downgrade_denied"),("/?token=x","redirect_policy_denied"),("/","redirect_loop")):
            with patch("backend.ndc.web_xray.probe_once",return_value={"ok":True,"http_status":302,"_redirect_location":location}) as probe:
                r=xray_execute(XRayRequest(url="https://example.com/",follow_redirects=True))
            self.assertEqual(r["status"],expected);self.assertEqual(probe.call_count,1)
            self.assertNotIn("_redirect_location",str(r));self.assertNotIn("token=x",str(r))
        def probe(host,port,family,kind,path,**kwargs):
            return {"ok":True,"http_status":302,"_redirect_location":path+"x"}
        with patch("backend.ndc.web_xray.probe_once",side_effect=probe):
            r=xray_execute(XRayRequest(url="https://example.com/",follow_redirects=True))
        self.assertEqual((r["status"],len(r["hops"])),("redirect_limit",4))

    def test_child_denied_scope(self):
        with patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":""}):
            r=xray_run(XRayRequest(url="http://127.0.0.1/"))
        self.assertEqual(r["status"],"probe_failed")
        self.assertIsNone(r["hops"][0]["peer_ip"])

if __name__=="__main__":unittest.main()
