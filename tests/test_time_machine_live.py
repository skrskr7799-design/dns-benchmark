"""Real loopback TLS scheduled captures, certificate rotation and restore.
Only scheduler clock accelerated; actual TLS verification and handshake.
"""
import datetime
import json
import os
import socket
import ssl
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from backend.ndc.evidence import EvidenceStore
from backend.ndc.storage import Store
from backend.ndc.agent_store import AgentStore
from backend.ndc.monitoring import MonitorStore,MonitorScheduler
from backend.ndc.time_machine import SnapshotStore
from backend.ndc.snapshot_schedule import Schedules,ScheduleConfig
from backend.ndc.snapshot_probes import TLSCapture,RouteCapture
from backend.ndc.probes.routes import route_capabilities
from backend.ndc.backup import backup,restore

class Disabled: enabled=False

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

def certificate(root,n,ca,ca_key):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
        .not_valid_after(now+datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,
            data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,
            encipher_only=False,decipher_only=False),critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False)
        .sign(ca_key,hashes.SHA256()))
    crt=root/f"crt{n}.pem";pem=root/f"key{n}.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt,pem);ctx.set_alpn_protocols(["http/1.1"])
    return ctx,cert.fingerprint(hashes.SHA256()).hex()

class Tests(unittest.TestCase):
    def test_scheduled_tls_rotation_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data=root/"data";data.mkdir()
            bundle,ca,ca_key=authority(root)
            a,fp_a=certificate(root,1,ca,ca_key)
            b,fp_b=certificate(root,2,ca,ca_key)
            self.assertNotEqual(fp_a,fp_b)
            now=[100000.0];clock=lambda:now[0]
            listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            listener.bind(("127.0.0.1",0));listener.listen(4);listener.settimeout(.2)
            stop=threading.Event();ctx=[a];hits=[];errors=[]
            def serve():
                while not stop.is_set():
                    try:raw,_=listener.accept()
                    except socket.timeout:continue
                    except OSError:break
                    try:
                        with raw:
                            raw.settimeout(4)
                            with ctx[0].wrap_socket(raw,server_side=True):
                                hits.append(1)
                    except ssl.SSLError as exc:errors.append(type(exc).__name__)
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            try:
                with patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32","NDC_CA_FILE":str(bundle)}):
                    def stores(path):
                        e=EvidenceStore(path/"intelligence.sqlite",clock=clock);e.initialize()
                        m=MonitorStore(path/"monitoring.sqlite",clock);m.initialize()
                        return e,m,SnapshotStore(e),Schedules(e,m)
                    # Match the deployed data-directory contract. Backup must
                    # still reject a directory missing its mandatory history DB.
                    history=Store(data/"history.sqlite");history.initialize()
                    agents=AgentStore(data/"agents.sqlite",clock);agents.initialize()
                    e,m,s,q=stores(data)
                    cfg=TLSCapture(host="localhost",port=listener.getsockname()[1])
                    job=q.create(ScheduleConfig(label="TLS rotation",interval_seconds=3600,probe=cfg))
                    now[0]+=3600
                    # Commit capture but deliberately omit schedule acknowledgement.
                    claim=q.claim();first=s.create_probe(claim["pending_id"],"TLS rotation",cfg)
                    self.assertTrue(first["snapshot"]["observation"]["verified"],first)
                    self.assertEqual(first["snapshot"]["observation"]["fingerprint"],fp_a)
                    backup(data,root/"backup")
                    manifest=json.loads((root/"backup"/"manifest.json").read_text())
                    self.assertEqual(set(manifest["files"]),{"history.sqlite","monitoring.sqlite","agents.sqlite","intelligence.sqlite"})
                    restore(root/"backup",root/"restored")
                    Store(root/"restored"/"history.sqlite").initialize()
                    AgentStore(root/"restored"/"agents.sqlite",clock).initialize()
                    e,m,s,q=stores(root/"restored");q.recover()
                    self.assertEqual(q.list()[0]["last_snapshot_id"],first["id"])
                    self.assertEqual(q.list()[0]["runs"],1)
                    self.assertEqual(s.get(first["id"]),first)
                    ctx[0]=b;now[0]+=3600
                    MonitorScheduler(m,threading.Lock(),Disabled(),snapshot_schedules=q).tick()
                    row=q.list()[0];self.assertEqual(row["id"],job["id"])
                    self.assertEqual(row["runs"],2);self.assertEqual(row["errors"],0)
                    second=s.get(row["last_snapshot_id"])
                    self.assertTrue(second["snapshot"]["observation"]["verified"],second)
                    self.assertEqual(second["snapshot"]["observation"]["fingerprint"],fp_b)
                    changes=s.compare(first["id"],second["id"])["changes"]
                    fp=next(f for f in changes if f["field"]=="fingerprint")
                    self.assertEqual((fp["before"],fp["after"],fp["status"]),(fp_a,fp_b,"changed"))
                    self.assertEqual(next(f for f in changes if f["field"]=="verified")["status"],"unchanged")
                    self.assertEqual(len(s.list()["items"]),2)
                    self.assertFalse(q.tick())
                    print("TLS schedule certificate rotation, trust verification and backup replay verified")
            finally:
                stop.set();listener.close();thread.join(5)
            self.assertFalse(thread.is_alive());self.assertEqual(len(hits),2);self.assertFalse(errors)
    def test_real_route_snapshot(self):
        if not route_capabilities()["ipv4"]:self.skipTest("Kernel extended errors unavailable")
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32"}):
            e=EvidenceStore(Path(tmp)/"intelligence.sqlite");e.initialize();s=SnapshotStore(e)
            cfg=RouteCapture(host="127.0.0.1",max_hops=2)
            a=s.create_probe(str(uuid.uuid4()),"route before",cfg);b=s.create_probe(str(uuid.uuid4()),"route after",cfg)
            for x in (a,b):
                o=x["snapshot"]["observation"]
                self.assertTrue(o["reached"],o);self.assertEqual(o["hops"][0]["address"],"127.0.0.1")
            self.assertEqual(next(f for f in s.compare(a["id"],b["id"])["changes"] if f["field"]=="ttl:1")["status"],"unchanged")
            print("Real IPv4 loopback route snapshot verified")

if __name__=="__main__":unittest.main()
