import datetime
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from backend.ndc.peer_contract import PeerDirection,RTTPlan,LocalGrants
from backend.ndc.peer_transport import Receiver,measure,PeerDenied
import ipaddress

def authority(root):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Time Machine test CA")])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
        .not_valid_after(now+datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,
            data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,
            encipher_only=False,decipher_only=False),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
        .sign(key,hashes.SHA256()))
    path=root/"ca.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path,cert,key

def leaf(root,n,ip,ca,ca_key):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"peer "+str(n))])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
        .not_valid_after(now+datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,
            data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,
            encipher_only=False,decipher_only=False),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),critical=False)
        .sign(ca_key,hashes.SHA256()))
    crt=root/f"crt{n}.pem";pem=root/f"key{n}.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return crt,pem,cert.fingerprint(hashes.SHA256()).hex()

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        root=Path(cls.tmp.name);cls.ca,ca,key=authority(root)
        cls.a=leaf(root,1,"127.0.0.1",ca,key)
        cls.b=leaf(root,2,"127.0.0.2",ca,key)
        cls.c=leaf(root,3,"127.0.0.1",ca,key)
    def setUp(self):
        env=patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.0/8"})
        env.start();self.addCleanup(env.stop)
    def setup_direction(self,reverse=False):
        source,dest=("127.0.0.2","127.0.0.1") if reverse else ("127.0.0.1","127.0.0.2")
        a,b=(self.b,self.a) if reverse else (self.a,self.b)
        ai,bi=("b"*32,"a"*32) if reverse else ("a"*32,"b"*32)
        with socket.socket() as sock:
            sock.bind((dest,0));port=sock.getsockname()[1]
        d=PeerDirection(source_agent_id=ai,destination_agent_id=bi,source_ip=source,destination_ip=dest,port=port,
            source_certificate=a[2],destination_certificate=b[2])
        plan=RTTPlan(request_id="c"*32,direction=d,samples=3)
        return a,b,d,plan,LocalGrants(bi,[d])
    def exchange(self,a,b,d,plan,grants,token,*,client_plan=None,client_cert=None):
        result=[];cancel=threading.Event()
        with Receiver(d.destination_ip,d.port,grants,cert=b[0],key=b[1],ca=self.ca) as server:
            thread=threading.Thread(target=lambda:result.append(server.serve_once(cancel)),daemon=True);thread.start()
            try:
                c=client_cert or a;p=client_plan or plan
                report,error=measure(p,token,[p.direction],cancel,cert=c[0],key=c[1],ca=self.ca)
            finally:
                cancel.set();thread.join(3)
            self.assertFalse(thread.is_alive())
        return report,error,result[0]
    def test_two_directions_real_mtls(self):
        for reverse in (False,True):
            a,b,d,p,g=self.setup_direction(reverse)
            report,error,server=self.exchange(a,b,d,p,g,g.issue(p))
            self.assertIsNone(error);self.assertEqual(report.summary()["echoes"],3)
            self.assertEqual(server,(3,None))
            self.assertIsNone(report.summary()["one_way_latency"])
            self.assertEqual(report.plan.direction,d)
        print("Real bidirectional local mTLS RTT echo verified")
    def test_replay_and_wrong_scope(self):
        a,b,d,p,g=self.setup_direction()
        token=g.issue(p)
        self.assertEqual(self.exchange(a,b,d,p,g,token)[0].summary()["echoes"],3)
        report,error,server=self.exchange(a,b,d,p,g,token)
        self.assertEqual(report.summary()["echoes"],0);self.assertIsNotNone(error);self.assertEqual(server[0],0)
        report,error=measure(p,g.issue(p),[],threading.Event(),cert=a[0],key=a[1],ca=self.ca)
        self.assertEqual(report.summary()["echoes"],0);self.assertIsNotNone(error)
    def test_trusted_but_wrong_peer_pin(self):
        a,b,d,p,g=self.setup_direction()
        wrong=p.model_copy(update={"direction":d.model_copy(update={"source_certificate":self.c[2]})})
        report,error,server=self.exchange(a,b,d,p,g,g.issue(p),client_plan=wrong,client_cert=self.c)
        self.assertEqual(report.summary()["echoes"],0);self.assertIsNotNone(error);self.assertEqual(server[0],0)
    def test_cancel_accept(self):
        a,b,d,p,g=self.setup_direction();cancel=threading.Event();cancel.set()
        with Receiver(d.destination_ip,d.port,g,cert=b[0],key=b[1],ca=self.ca) as r:
            self.assertEqual(r.serve_once(cancel),(0,"cancelled"))
            with self.assertRaises(RuntimeError):r.serve_once(cancel)
    def test_unapproved_bind(self):
        a,b,d,p,g=self.setup_direction()
        with self.assertRaises(PeerDenied):
            Receiver("127.0.0.1",d.port,g,cert=b[0],key=b[1],ca=self.ca)
    def test_exclusive_live_listener(self):
        a,b,d,p,g=self.setup_direction()
        with Receiver(d.destination_ip,d.port,g,cert=b[0],key=b[1],ca=self.ca):
            with self.assertRaises(OSError):
                Receiver(d.destination_ip,d.port,g,cert=b[0],key=b[1],ca=self.ca)

if __name__=="__main__":unittest.main()
