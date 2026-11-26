import tempfile
import unittest
import socket
import threading
import uuid
from pathlib import Path
from unittest.mock import patch
import dns.message,dns.rrset
from backend.ndc.evidence import EvidenceStore
from backend.ndc.time_machine import SnapshotStore
from backend.ndc.snapshot_probes import DNSCapture,TLSCapture,RouteCapture,normalize_dns

def dns_row(values,ttl=60,**extra):
    return {"outcome":"answer","ip":"127.0.0.1","protocol":"udp","rcode":"NOERROR","flags":[],
        "answer":[{"name":"Example.COM.","type":"A","class":"IN","ttl":ttl,"values":values}]}|extra

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.e=EvidenceStore(Path(tmp.name)/"intelligence.sqlite");self.e.initialize()
        self.s=SnapshotStore(self.e)
        self.cfg=DNSCapture(name="example.com",endpoints=["udp://127.0.0.1"])
    def capture(self,cfg,row):
        path={"dns":"inspect_one","tls":"inspect_tls","route":"trace"}[cfg.kind]
        value=(row,None) if cfg.kind=="dns" else {"results":[row]}
        with patch("backend.ndc.snapshot_probes."+path,return_value=value):
            return self.s.create_probe(str(uuid.uuid4()),"fixture",cfg)
    def diff(self,a,b):
        return self.s.compare(a["id"],b["id"])["changes"]
    def test_rrsets_and_ttl(self):
        a=self.capture(self.cfg,dns_row(["192.0.2.2","192.0.2.1"]))
        b=self.capture(self.cfg,dns_row(["192.0.2.1","192.0.2.2"],10))
        d=self.diff(a,b)
        self.assertEqual(next(x for x in d if x["field"]=="rrset")["status"],"unchanged")
        self.assertEqual(next(x for x in d if x["field"].startswith("ttl:"))["status"],"changed")
        with patch("backend.ndc.snapshot_probes.inspect_one") as probe:
            self.assertEqual(self.s.create_probe(a["id"],"fixture",self.cfg),a)
            probe.assert_not_called()
        self.assertEqual(self.s.list()["items"][0]["scope"],"dns")
    def test_partial_and_changed_resolver(self):
        a=self.capture(self.cfg,dns_row(["192.0.2.1"]))
        for row,expected in [(dns_row([],outcome="truncated"),"unknown"),(dns_row([],outcome="nxdomain"),"unknown"),
            (dns_row(["192.0.2.2"],ip="127.0.0.2"),"not_comparable")]:
            b=self.capture(self.cfg,row)
            self.assertEqual(next(x for x in self.diff(a,b) if x["field"]=="rrsets")["status"],expected)
        self.assertFalse(normalize_dns(dns_row(["192.0.2.1"]*129))["answer_complete"])
    def test_cname_canonicalization(self):
        def alias(v):
            return dns_row([],answer=[{"name":"Example.COM.","class":"IN","type":"CNAME","ttl":10,"values":[v]}])
        self.assertEqual(normalize_dns(alias("Target.EXAMPLE."))["rrsets"],normalize_dns(alias("target.example."))["rrsets"])
    def test_tls_trust_separate_from_identity(self):
        cfg=TLSCapture(host="localhost")
        row={"ok":True,"verified":True,"stage":"complete","ip":"127.0.0.1","certificate":{"sha256":"a"*64,"not_after":"fixture"},"tls_version":"TLSv1.3"}
        a=self.capture(cfg,row)
        b=self.capture(cfg,row|{"certificate":{"sha256":"b"*64,"not_after":"fixture"}})
        self.assertEqual(next(x for x in self.diff(a,b) if x["field"]=="fingerprint")["status"],"changed")
        c=self.capture(cfg,row|{"ok":False,"verified":False,"stage":"tls","certificate":None})
        d=self.diff(b,c)
        self.assertEqual(next(x for x in d if x["field"]=="verified")["status"],"changed")
        self.assertEqual(next(x for x in d if x["field"]=="fingerprint")["status"],"unknown")
    def test_route_unknown_not_removed(self):
        cfg=RouteCapture(host="127.0.0.1")
        def row(address,status):
            return {"available":True,"reached":False,"ip":"127.0.0.1","hops":[{"ttl":1,"samples":[{"address":address,"status":status}]}]}
        a=self.capture(cfg,row("192.0.2.1","hop"));b=self.capture(cfg,row(None,"timeout"))
        self.assertEqual(next(x for x in self.diff(a,b) if x["field"]=="ttl:1")["status"],"unknown")
        c=self.capture(cfg,row("192.0.2.2","hop"))
        self.assertEqual(next(x for x in self.diff(a,c) if x["field"]=="ttl:1")["status"],"changed")
    def test_real_dns_capture(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1",0));sock.settimeout(4)
            errors=[]
            def respond():
                try:
                    for addr in ("192.0.2.1","192.0.2.2"):
                        raw,peer=sock.recvfrom(65535)
                        q=dns.message.from_wire(raw);r=dns.message.make_response(q)
                        r.answer.append(dns.rrset.from_text(q.question[0].name,60,"IN","A",addr))
                        sock.sendto(r.to_wire(),peer)
                except Exception as e: errors.append(e)
            thread=threading.Thread(target=respond,daemon=True);thread.start()
            cfg=DNSCapture(name="example.com",endpoints=["udp://127.0.0.1:"+str(sock.getsockname()[1])])
            a=self.s.create_probe(str(uuid.uuid4()),"before",cfg);b=self.s.create_probe(str(uuid.uuid4()),"after",cfg)
            thread.join(5)
            self.assertFalse(thread.is_alive());self.assertFalse(errors)
            d=next(x for x in self.diff(a,b) if x["field"]=="rrset")
            self.assertEqual((d["before"],d["after"],d["status"]),(["192.0.2.1"],["192.0.2.2"],"changed"))
    def test_bounds_and_scope(self):
        with self.assertRaises(ValueError): RouteCapture(host="localhost",max_hops=9)
        with self.assertRaises(ValueError): DNSCapture(name="example.com",endpoints=["udp://127.0.0.1","udp://127.0.0.2"])
        with patch("socket.create_connection") as connect:
            a=self.s.create_probe(str(uuid.uuid4()),"blocked",TLSCapture(host="169.254.169.254"))
            connect.assert_not_called()
        self.assertIsNone(a["snapshot"]["observation"]["fingerprint"])

if __name__=="__main__": unittest.main()
