"""Single-file local agent bootstrap. No remote execution or automatic trust."""
import argparse
import hmac
import ipaddress
import json
import os
import re
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from .agent_control_pki import private_read,private_write,pem
from .agent_contract import AgentRun

BOOTSTRAP=Path("/run/ndc-bootstrap.json")

def exists(path):
    return path.exists() or path.is_symlink()

def load(path=BOOTSTRAP):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):raise ValueError("Bootstrap must be a regular file")
        data=f.read(32769)
    if len(data)>32768:raise ValueError("Bootstrap too large")
    obj=json.loads(data)
    if not isinstance(obj,dict) or set(obj)!={"version","agent_id","origin","ca_pem","ca_sha256","endpoints","token","expires_at"}:
        raise ValueError("Invalid bootstrap fields")
    if type(obj["version"]) is not int or obj["version"]!=1:raise ValueError("Unsupported bootstrap version")
    if not isinstance(obj["agent_id"],str) or not re.fullmatch(r"[a-f0-9]{32}",obj["agent_id"]):raise ValueError("Invalid agent ID")
    if not isinstance(obj["origin"],str):raise ValueError("Invalid controller")
    ip=ipaddress.IPv4Address(urlsplit(obj["origin"]).hostname)
    if ip not in ipaddress.ip_network("100.64.0.0/10") or obj["origin"]!=f"https://{ip}:8443":
        raise ValueError("Explicit NetBird controller origin required")
    ca=obj["ca_pem"];pin=obj["ca_sha256"]
    if not isinstance(ca,str) or not isinstance(pin,str) or not re.fullmatch(r"[a-f0-9]{64}",pin):
        raise ValueError("Invalid CA metadata")
    cert=x509.load_pem_x509_certificate(ca.encode("ascii"))
    if ca.strip()!=pem(cert).strip() or not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Exactly one public CA required")
    cert.verify_directly_issued_by(cert)
    if not hmac.compare_digest(cert.fingerprint(hashes.SHA256()).hex(),pin):raise ValueError("CA fingerprint mismatch")
    endpoints=obj["endpoints"]
    if not isinstance(endpoints,list) or not 1<=len(endpoints)<=100 or any(not isinstance(e,str) for e in endpoints) or len(set(endpoints))!=len(endpoints):
        raise ValueError("Invalid resolver allowlist")
    for endpoint in endpoints:AgentRun(endpoints=[endpoint])
    token=obj["token"];expiry=obj["expires_at"]
    if not isinstance(token,str) or (token and not re.fullmatch(r"[A-Za-z0-9_-]{43}",token)):
        raise ValueError("Invalid invitation")
    if type(expiry) is not int or expiry<0 or bool(token)!=bool(expiry):raise ValueError("Invalid invitation expiry")
    return obj

def prepare(root,obj):
    """Caller holds exclusive volume lock; never overwrite identity, key or spool."""
    root=Path(root)
    if os.getenv("NDC_AGENT_MTLS")!="1" or os.getenv("NDC_AGENT_PROTOCOL")!="2" or os.getenv("NDC_CONTROLLER_URL")!=obj["origin"] or os.getenv("NDC_AGENT_CA_FILE")!=str(root/"controller-ca.pem"):
        raise ValueError("Bootstrap and agent environment differ")
    identity=root/"identity.json";enrolled=exists(identity)
    if enrolled:
        saved=json.loads(private_read(identity))
        if saved.get("id")!=obj["agent_id"] or saved.get("controller")!=obj["origin"] or not saved.get("certificate"):
            raise ValueError("Volume belongs to another agent; use a fresh volume")
    elif not obj["token"] or obj["expires_at"]<=time.time():
        raise ValueError("Fresh invitation required for a new volume")
    ca=root/"controller-ca.pem";allowed=root/"allowed-endpoints.json";token_path=root/"enrollment-token"
    if exists(ca) and private_read(ca)!=obj["ca_pem"].encode("ascii"):
        raise ValueError("Existing controller CA differs")
    if exists(allowed) and json.loads(private_read(allowed))!=obj["endpoints"]:
        raise ValueError("Existing allowlist differs; deliberate local migration required")
    if not enrolled and exists(token_path) and private_read(token_path).decode().strip()!=obj["token"]:
        raise ValueError("Existing invitation differs; deliberate re-enrollment required")
    if not exists(ca):private_write(ca,obj["ca_pem"].encode("ascii"))
    if not exists(allowed):private_write(allowed,json.dumps(obj["endpoints"]).encode())
    if not enrolled and not exists(token_path):private_write(token_path,(obj["token"]+"\n").encode())
    if enrolled and exists(token_path):token_path.unlink()

def main():
    parser=argparse.ArgumentParser(description="Verify embedded CA against independently obtained fingerprint")
    parser.add_argument("action",choices=["verify"])
    parser.add_argument("fingerprint")
    args=parser.parse_args()
    obj=load()
    expected=args.fingerprint.lower().replace(":","")
    if not re.fullmatch(r"[a-f0-9]{64}",expected) or not hmac.compare_digest(expected,obj["ca_sha256"]):
        raise SystemExit("Controller CA fingerprint mismatch")
    print("Controller CA SHA-256 verified: "+obj["ca_sha256"])

if __name__=="__main__":main()
