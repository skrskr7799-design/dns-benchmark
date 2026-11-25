import datetime
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from backend.ndc.models import Connectivity, NetworkTarget
from backend.ndc.probes.connectivity import connectivity, inspect_tls, probe_once, ping_one, resolve_host
from backend.ndc.scope import ScopeError

class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.hits.append((self.path,self.headers["Host"]))
        self.send_response(302 if self.path=="/redirect" else 204)
        if self.path=="/redirect":
            self.send_header("Location","http://169.254.169.254/latest/meta-data/")
        self.end_headers()
    def log_message(self,*args):
        pass

@contextmanager
def server(tls=None):
    srv=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    srv.hits=[]
    if tls:
        srv.socket=tls.wrap_socket(srv.socket,server_side=True)
    thread=threading.Thread(target=srv.serve_forever,daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(3)

def certificate_files(root):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
          .not_valid_after(now+datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False)
          .sign(key,hashes.SHA256()))
    crt=root/"crt.pem"; pem=root/"key.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return crt,pem

class NetworkTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.crt,self.key=certificate_files(Path(tmp.name))
        env=patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32","NDC_CA_FILE":str(self.crt)})
        env.start(); self.addCleanup(env.stop)
        self.tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(self.crt,self.key)
        self.tls.set_alpn_protocols(["http/1.1"])

    def test_http_pinned_no_redirect(self):
        with server() as srv:
            port=srv.server_port
            result=connectivity(Connectivity(host="localhost",port=port,kind="http",path="/redirect",count=2))
            g=result["results"][0]
            self.assertEqual(g["success"],2)
            self.assertEqual(g["ip"],"127.0.0.1")
            for p in g["samples"]:
                self.assertEqual(p["http_status"],302)
                self.assertEqual(p["peer_ip"],"127.0.0.1")
                self.assertIsNotNone(p["connect_ms"])
                self.assertIsNotNone(p["ttfb_ms"])
                self.assertGreaterEqual(p["headers_ms"],p["ttfb_ms"])
            self.assertEqual(srv.hits,[("/redirect",f"localhost:{port}")]*2)

    def test_tls_verified_and_https(self):
        with server(self.tls) as srv:
            port=srv.server_port
            p=inspect_tls(NetworkTarget(host="localhost",port=port))["results"][0]
            self.assertTrue(p["ok"],p)
            self.assertTrue(p["verified"])
            self.assertEqual(p["certificate"]["san"],["localhost"])
            self.assertGreater(p["certificate"]["days_remaining"],28)
            self.assertEqual(len(p["certificate"]["sha256"]),64)
            self.assertEqual(p["alpn"],"http/1.1")
            self.assertIsNotNone(p["handshake_ms"])
            p=probe_once("localhost",port,"ipv4","https",ip="127.0.0.1")
            self.assertTrue(p["ok"],p)
            self.assertEqual(p["http_status"],204)
            p=probe_once("wrong.test",port,"ipv4","https",ip="127.0.0.1")
            self.assertFalse(p["ok"])
            self.assertFalse(p["verified"])
            self.assertEqual(p["stage"],"tls")
            self.assertIsNone(p["http_status"])

    def test_scope_and_bad_input(self):
        with patch("socket.getaddrinfo",return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("169.254.169.254",443))]),self.assertRaises(ScopeError):
            resolve_host("fixture.test",443,"ipv4")
        with patch("socket.create_connection") as connect:
            p=probe_once("fixture.test",443,"ipv4","https",ip="169.254.169.254")
            self.assertFalse(p["ok"])
            connect.assert_not_called()
        for options in [{"host":"https://example.com"},{"host":"example.com\r\nHost: injected"},{"path":"//other.test"},{"path":"/x\r\nX:a"},{"path":"/x?secret=1"},{"port":0},{"count":6}]:
            with self.subTest(options=options),self.assertRaises(ValueError):
                Connectivity(**({"host":"localhost"}|options))

    def test_icmp_unavailable_and_loopback_when_supported(self):
        with patch("backend.ndc.probes.connectivity.ping_socket",side_effect=PermissionError("fixture")):
            p=ping_one("localhost","ipv4",3)
        self.assertFalse(p["available"])
        self.assertIsNone(p["loss_pct"])
        p=ping_one("127.0.0.1","ipv4",2)
        if p["available"]:
            self.assertEqual(p["sent"],2,p)
            self.assertEqual(p["received"],2,p)
            self.assertEqual(p["loss_pct"],0)
        else:
            self.assertIsNone(p["loss_pct"])

    def test_tcp_failure(self):
        with patch("socket.create_connection",side_effect=ConnectionRefusedError("fixture")):
            p=probe_once("localhost",443,"ipv4","tcp",ip="127.0.0.1")
        self.assertEqual(p["stage"],"tcp")
        self.assertFalse(p["ok"])
        self.assertIsNone(p["connect_ms"])

if __name__=="__main__":
    unittest.main()
