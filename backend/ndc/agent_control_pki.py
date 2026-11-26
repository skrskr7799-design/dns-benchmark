"""Controller-agent trust domain, separate from peer-measurement TLS."""
import datetime as dt
import ipaddress
import json
import os
import ssl
import stat
import tempfile
from pathlib import Path
from contextvars import ContextVar
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

# Set only by the TLS protocol adapter, not HTTP headers. AnyIO copies
# context into FastAPI's synchronous workers.
peer_fingerprint=ContextVar("ndc_control_peer_fingerprint",default=None)
peer_public_key=ContextVar("ndc_control_peer_public_key",default=None)
PKI_FILE="agent-control-pki.json"
UTC=dt.timezone.utc

def private_read(path,limit=65536):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_mode&0o077:
            raise ValueError("Private regular file required")
        data=f.read(limit+1)
        if len(data)>limit:raise ValueError("Private file too large")
        return data

def private_write(path,data):
    path=Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent,prefix=".control-",delete=False) as f:
        tmp=Path(f.name)
        try:
            f.write(data);f.flush();os.fsync(f.fileno())
            os.replace(tmp,path)
            fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:tmp.unlink(missing_ok=True)

def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM).decode("ascii")

def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())

def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])

def public_bytes(key):
    return key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)

def base(subject,issuer,public,now,days):
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(public).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=days)))

class Authority:
    def __init__(self,root,ip):
        self.ip=ipaddress.ip_address(ip)
        if self.ip.version!=4 or self.ip not in ipaddress.ip_network("100.64.0.0/10") or str(self.ip)=="100.100.100.200":
            raise ValueError("Set the explicit NetBird IPv4 address")
        self.path=Path(root)/PKI_FILE
        now=dt.datetime.now(UTC)
        if self.path.exists() or self.path.is_symlink():
            data=json.loads(private_read(self.path))
            self.ca=x509.load_pem_x509_certificate(data["ca"].encode())
            self.key=serialization.load_pem_private_key(data["key"].encode(),None)
            if not isinstance(self.key,ec.EllipticCurvePrivateKey) or public_bytes(self.key.public_key())!=public_bytes(self.ca.public_key()):
                raise ValueError("CA key mismatch")
            if not self.ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("Invalid CA")
            self.ca.verify_directly_issued_by(self.ca)
        else:
            self.key=ec.generate_private_key(ec.SECP256R1())
            self.ca=(base(name("NDC Agent Control CA"),name("NDC Agent Control CA"),self.key.public_key(),now,3650)
                .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),critical=False)
                .sign(self.key,hashes.SHA256()))
            private_write(self.path,json.dumps({"ca":pem(self.ca),"key":key_pem(self.key).decode()}).encode())
        if not self.ca.not_valid_before_utc<=now or self.ca.not_valid_after_utc<=now+dt.timedelta(days=365):
            raise ValueError("Control CA needs explicit renewal")
        self.ca_pem=pem(self.ca)
        self.ca_fingerprint=self.ca.fingerprint(hashes.SHA256()).hex()

    def leaf(self,public,cn,usage,days,ip=None):
        now=dt.datetime.now(UTC)
        builder=(base(name(cn),self.ca.subject,public,now,days)
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=None,decipher_only=None),critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]),critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),critical=False))
        if ip is not None:builder=builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip)]),critical=False)
        return builder.sign(self.key,hashes.SHA256())

    def sign_client(self,agent_id,csr_pem,expected_key=None):
        if len(csr_pem)>4096:raise ValueError("CSR too large")
        csr=x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        public=csr.public_key()
        if not isinstance(public,ec.EllipticCurvePublicKey) or not isinstance(public.curve,ec.SECP256R1) or not csr.is_signature_valid:
            raise ValueError("Invalid P-256 CSR")
        if expected_key is not None and public_bytes(public)!=expected_key:
            raise ValueError("Renewal must use the authenticated local key")
        # Ignore all requested subject/extensions; only controller chooses identity.
        cert=self.leaf(public,agent_id,ExtendedKeyUsageOID.CLIENT_AUTH,90)
        return pem(cert),cert.fingerprint(hashes.SHA256()).hex(),cert.not_valid_after_utc.timestamp()

    def server_context(self):
        # New server leaf at each restart; trust anchor stays persistent.
        key=ec.generate_private_key(ec.SECP256R1())
        cert=self.leaf(key.public_key(),"NDC Agent Controller",ExtendedKeyUsageOID.SERVER_AUTH,365,self.ip)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
        # Enrollment requires server-auth TLS before a client has a certificate.
        # Every other machine request MUST provide a verified, bound certificate.
        ctx.verify_mode=ssl.CERT_OPTIONAL
        ctx.load_verify_locations(cadata=self.ca_pem)
        ctx.num_tickets=0
        ctx.set_alpn_protocols(["http/1.1"])
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            private_write(p/"leaf",pem(cert).encode())
            private_write(p/"key",key_pem(key))
            ctx.load_cert_chain(p/"leaf",p/"key")
        return ctx

def client_context(ca_file,key_file=None,certificate=None):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(ca_file))
    if certificate is not None:
        private_read(key_file)
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"leaf"
            private_write(p,certificate.encode("ascii"))
            ctx.load_cert_chain(p,str(key_file))
    return ctx

def client_csr(path):
    path=Path(path)
    if path.exists() or path.is_symlink():
        key=serialization.load_pem_private_key(private_read(path),None)
    else:
        key=ec.generate_private_key(ec.SECP256R1())
        private_write(path,key_pem(key))
    if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1):
        raise ValueError("Invalid control key")
    return pem(x509.CertificateSigningRequestBuilder().subject_name(name("NDC enrollment")).sign(key,hashes.SHA256()))

def public_trust(root):
    # Read-only export; never initialize/replace authority or print private key.
    data=json.loads(private_read(Path(root)/PKI_FILE))
    ca=x509.load_pem_x509_certificate(data["ca"].encode("ascii"))
    ca.verify_directly_issued_by(ca)
    return pem(ca),ca.fingerprint(hashes.SHA256()).hex()

def main():
    import argparse
    parser=argparse.ArgumentParser(description="Export existing public agent-control trust only")
    parser.add_argument("action",choices=["public-ca","fingerprint"])
    args=parser.parse_args()
    ca,fp=public_trust(os.getenv("DATA_DIR","/data"))
    print(ca if args.action=="public-ca" else fp,end="" if args.action=="public-ca" else "\n")

if __name__=="__main__":main()
