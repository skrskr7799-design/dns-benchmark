import datetime
import os
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from backend.ndc.remote_contract import RemoteTLS,RemoteHTTP,RemoteResult,ServiceObservation,config_key,validate_remote,project_remote
from backend.ndc.remote_worker import Approval,run_probe

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
    def test_real_tls_and_https(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);bundle,ca,key=authority(root);ctx,fp=certificate(root,1,ca,key)
            with socket.socket() as listener,patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32","NDC_CA_FILE":str(bundle)}):
                listener.bind(("127.0.0.1",0));listener.listen(4);listener.settimeout(5)
                hits=[];errors=[]
                def serve():
                    try:
                        for i in range(3):
                            raw,_=listener.accept()
                            with raw:
                                raw.settimeout(4)
                                try:
                                    with ctx.wrap_socket(raw,server_side=True) as tls:
                                        hits.append(i)
                                        if i==1:
                                            data=b""
                                            while b"\r\n\r\n" not in data and len(data)<4096:
                                                chunk=tls.recv(4096)
                                                if not chunk:break
                                                data+=chunk
                                            if not data.startswith(b"HEAD /ready HTTP/1.1\r\n"):errors.append("wrong request")
                                            tls.sendall(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                except ssl.SSLError:
                                    if i!=2:errors.append("unexpected TLS failure")
                    except Exception as exc:errors.append(type(exc).__name__)
                thread=threading.Thread(target=serve,daemon=True);thread.start()
                port=listener.getsockname()[1]
                def run(cfg):
                    row,error=run_probe(cfg,(Approval(config=cfg,cidrs=["127.0.0.1/32"]),),threading.Event())
                    self.assertIsNone(error);return row
                tls=run(RemoteTLS(host="localhost",port=port))
                self.assertTrue(tls.verified);self.assertEqual(tls.fingerprint,fp)
                https=run(RemoteHTTP(host="localhost",port=port,path="/ready"))
                self.assertTrue(https.verified);self.assertEqual(https.http_status,503)
                self.assertEqual(https.outcome,"failure")
                wrong=run(RemoteTLS(host="127.0.0.1",port=port))
                self.assertFalse(wrong.verified);self.assertIsNone(wrong.fingerprint)
                thread.join(6);self.assertFalse(thread.is_alive());self.assertEqual(hits,[0,1]);self.assertFalse(errors)
    def test_contract_and_projection(self):
        cfg=RemoteHTTP(host="localhost",port=443)
        data={"kind":"http","outcome":"success","stage":"complete","address":"127.0.0.1","peer_ip":"127.0.0.1",
            "connect_ms":1.0,"http_ms":2.0,"total_ms":4.0,"http_status":200}
        body=RemoteResult(version="2",engine="python-network-v2",kind="http",lease="a"*43,config_key=config_key(cfg),status="completed",observation=data)
        with self.assertRaises(ValueError):validate_remote(cfg,body)
        plain=RemoteHTTP(host="localhost",port=443,scheme="http")
        body=body.model_copy(update={"config_key":config_key(plain)})
        validate_remote(plain,body)
        evidence=project_remote("a"*32,"b"*32,plain,body)
        self.assertEqual((evidence.probe_kind,evidence.protocol,evidence.provenance),("http","http/1.1","agent_claim"))
        self.assertEqual(next(x.value for x in evidence.measurements if x.name=="http_status"),200.)
        for path in ("//example.com","/x?token=x","/x#fragment","/x\r\nHost: x"):
            with self.assertRaises(ValueError):RemoteHTTP(host="localhost",port=443,path=path)
        with self.assertRaises(ValueError):ServiceObservation(**(data|{"http_status":503}))
        with self.assertRaises(ValueError):ServiceObservation(**(data|{"verified":False}))
if __name__=="__main__":unittest.main()
