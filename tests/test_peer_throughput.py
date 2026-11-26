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

from backend.ndc.peer_throughput import ThroughputPolicy,ThroughputPlan,ThroughputReport,ThroughputGrants,ThroughputReceiver,measure_throughput,pace

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(tmp.cleanup)
        root=Path(tmp.name);cls.ca,ca,key=authority(root)
        cls.a=leaf(root,1,"127.0.0.1",ca,key);cls.b=leaf(root,2,"127.0.0.2",ca,key)
    def setUp(self):
        env=patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.0/8"})
        env.start();self.addCleanup(env.stop)
        with socket.socket() as sock:
            sock.bind(("127.0.0.2",0));port=sock.getsockname()[1]
        self.d=PeerDirection(source_agent_id="a"*32,destination_agent_id="b"*32,
            source_ip="127.0.0.1",destination_ip="127.0.0.2",port=port,
            source_certificate=self.a[2],destination_certificate=self.b[2])
        self.policy=ThroughputPolicy(direction=self.d,byte_count=65536,rate_bps=1000000)
        self.plan=ThroughputPlan(request_id="c"*32,policy=self.policy)
        self.g=ThroughputGrants("b"*32,[self.policy])
    def exchange(self,token,plan=None):
        cancel=threading.Event();rows=[]
        with ThroughputReceiver(self.d.destination_ip,self.d.port,self.g,cert=self.b[0],key=self.b[1],ca=self.ca) as r:
            worker=threading.Thread(target=lambda:rows.append(r.serve_once(cancel)),daemon=True);worker.start()
            try:
                p=plan or self.plan
                result=measure_throughput(p,token,[p.policy],cancel,cert=self.a[0],key=self.a[1],ca=self.ca)
            finally:
                cancel.set();worker.join(3)
            self.assertFalse(worker.is_alive())
        return result,rows[0]
    def test_real_paced_mtls_and_replay(self):
        token=self.g.issue(self.plan)
        start=time.monotonic();(client,error),(server,serror)=self.exchange(token)
        self.assertIsNone(error);self.assertIsNone(serror);self.assertEqual(client,server)
        self.assertGreaterEqual(time.monotonic()-start,.524)
        self.assertEqual(client.received_bytes,65536)
        self.assertLessEqual(client.summary()["application_goodput_bps"],1002000)
        self.assertIsNone(client.summary()["link_capacity_bps"])
        (client,error),(server,serror)=self.exchange(token)
        self.assertIsNone(client);self.assertIsNone(server);self.assertIsNotNone(error);self.assertIsNotNone(serror)
    def test_exact_policy_and_protocol_separation(self):
        other=self.plan.model_copy(update={"policy":self.policy.model_copy(update={"rate_bps":2000000})})
        with self.assertRaises(PermissionError):self.g.issue(other)
        token=self.g.issue(self.plan)
        (client,error),(server,serror)=self.exchange(token,other)
        self.assertIsNone(client);self.assertIsNone(server)
        with self.assertRaises(ValueError):
            ThroughputReceiver(self.d.destination_ip,self.d.port,LocalGrants("b"*32,[self.d]),cert=self.b[0],key=self.b[1],ca=self.ca)
        self.assertIsNone(measure_throughput(self.plan,token,[],threading.Event(),cert=self.a[0],key=self.a[1],ca=self.ca)[0])
    def test_bounds_and_invalid_receipts(self):
        for kw in ({"byte_count":4194305},{"byte_count":65537},{"rate_bps":8000001},{"byte_count":4194304,"rate_bps":256000}):
            with self.assertRaises(ValueError):ThroughputPolicy(**({"direction":self.d,"byte_count":65536,"rate_bps":1000000}|kw))
        for count,elapsed in ((32768,600000),(65536,1)):
            with self.assertRaises(ValueError):ThroughputReport(plan=self.plan,received_bytes=count,receiver_elapsed_us=elapsed,payload_sha256="a"*64)
    def test_cancel_before_network(self):
        cancel=threading.Event();cancel.set()
        report,error=measure_throughput(self.plan,self.g.issue(self.plan),[self.policy],cancel,cert=self.a[0],key=self.a[1],ca=self.ca)
        self.assertIsNone(report);self.assertEqual(error,"cancelled")

if __name__=="__main__":unittest.main()
