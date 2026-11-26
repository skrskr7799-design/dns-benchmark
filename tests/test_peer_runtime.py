import datetime
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import ipaddress
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.ndc.agent_client import atomic
from backend.ndc.agent_store import AgentStore
from backend.ndc.peer_api import router
from backend.ndc.security import Security,guard,router as auth_router
from backend.ndc.peer_contract import PeerDirection,RTTPlan
from backend.ndc.peer_runtime import PeerRuntime,Journal
from backend.ndc.agent_evidence import decode

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
    def test_runtime_real_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.0/8","NDC_OWNER_PASSWORD":"test-owner-password-long","NDC_SECURE_COOKIE":"0","NDC_ORIGIN":""}):
            root=Path(tmp);s=AgentStore(root/"agents.sqlite");s.initialize();s.peer_enabled=True
            a=s.enroll(s.invite("A","fixture")["token"]);b=s.enroll(s.invite("B","fixture")["token"])
            ca_path,ca,key=authority(root)
            certs=[leaf(root,1,"127.0.0.1",ca,key),leaf(root,2,"127.0.0.2",ca,key)]
            with socket.socket() as sock:
                sock.bind(("127.0.0.2",0));port=sock.getsockname()[1]
            d=PeerDirection(source_agent_id=a["id"],destination_agent_id=b["id"],source_ip="127.0.0.1",destination_ip="127.0.0.2",
                port=port,source_certificate=certs[0][2],destination_certificate=certs[1][2])
            p=RTTPlan(request_id="a"*32,direction=d,samples=3)
            app=FastAPI();app.state.agents=s;app.state.security=Security(root)
            app.middleware("http")(guard);app.include_router(router);app.include_router(auth_router)
            clients=[];runtimes=[]
            try:
                for i,node in enumerate((a,b)):
                    folder=root/str(i);folder.mkdir()
                    atomic(folder/"peer-directions.json",[d.model_dump(mode="json")])
                    for name,path in (("peer-cert.pem",certs[i][0]),("peer-key.pem",certs[i][1]),("peer-ca.pem",ca_path)):
                        target=folder/name;target.write_bytes(path.read_bytes());target.chmod(0o600)
                    client=TestClient(app,base_url="http://127.0.0.1");clients.append(client)
                    def post(path,body,client=client,node=node):
                        return client.post("/api/v1/agents/machine/peer/"+path,json=body,headers={"Authorization":"Bearer "+node["credential"]})
                    r=PeerRuntime(folder,node["id"],post,atomic);runtimes.append(r)
                    self.assertFalse(r.step())
                self.assertFalse(s.peer_admit(p)["duplicate"])
                errors=[]
                def receive():
                    try:runtimes[1].step()
                    except Exception as exc:errors.append(type(exc).__name__)
                worker=threading.Thread(target=receive,daemon=True);worker.start()
                until=time.monotonic()+5
                while s.peer_detail(p.request_id)["state"]!="ready" and time.monotonic()<until:time.sleep(.025)
                self.assertEqual(s.peer_detail(p.request_id)["state"],"ready")
                self.assertTrue(runtimes[0].step())
                worker.join(12);self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
                detail=s.peer_detail(p.request_id)
                self.assertEqual((detail["state"],detail["outcome"],detail["receiver_echoes"]),("completed","success",3),detail)
                obs,_=decode(s.pending_evidence()["payload"])
                self.assertEqual(obs[0].source_part,"peer-rtt-v1")
                self.assertEqual(sum(m.unit=="ms" for m in obs[0].measurements),3)
                for r in runtimes:
                    journal=Journal(r.journal.path,atomic)
                    self.assertFalse(journal.begin(p.request_id))
                    self.assertIsNone(journal.data["pending"])
                print("Real two-agent mTLS RTT via peer control API and durable evidence verified")
            finally:
                for c in clients:c.close()
    def test_journal_restart_never_reexecutes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"peer-journal.json";j=Journal(path,atomic)
            self.assertTrue(j.begin("a"*32))
            self.assertFalse(Journal(path,atomic).begin("a"*32))
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            path.chmod(0o644)
            with self.assertRaises(ValueError):Journal(path,atomic)

    def test_goodput_real_end_to_end(self):
        from backend.ndc.peer_throughput_runtime import GoodputAgentRuntime
        from backend.ndc.peer_throughput import ThroughputPlan,ThroughputPolicy
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.0/8","NDC_OWNER_PASSWORD":"test-owner-password-long","NDC_SECURE_COOKIE":"0","NDC_ORIGIN":""}):
            root=Path(tmp);s=AgentStore(root/"agents.sqlite");s.initialize()
            s.peer_enabled=s.goodput_enabled=s.goodput_session_enabled=True
            nodes=[s.enroll(s.invite(n,"fixture")["token"]) for n in ("A","B")]
            ca_path,ca,key=authority(root)
            certs=[leaf(root,1,"127.0.0.1",ca,key),leaf(root,2,"127.0.0.2",ca,key)]
            with socket.socket() as sock:
                sock.bind(("127.0.0.2",0));port=sock.getsockname()[1]
            d=PeerDirection(source_agent_id=nodes[0]["id"],destination_agent_id=nodes[1]["id"],
                source_ip="127.0.0.1",destination_ip="127.0.0.2",port=port,
                source_certificate=certs[0][2],destination_certificate=certs[1][2])
            p=ThroughputPlan(request_id="b"*32,policy=ThroughputPolicy(direction=d,byte_count=65536,rate_bps=1000000))
            app=FastAPI();app.state.agents=s;app.state.security=Security(root)
            app.middleware("http")(guard);app.include_router(router);app.include_router(auth_router)
            clients=[];runtimes=[];errors=[]
            try:
                owner=TestClient(app,base_url="http://127.0.0.1");clients.append(owner)
                login=owner.post("/api/auth/login",json={"password":"test-owner-password-long"},headers={"X-NDC-Request":"1"})
                self.assertEqual(login.status_code,200,login.text)
                csrf={"X-CSRF-Token":login.json()["csrf"]}
                self.assertEqual(owner.post("/api/v1/agents/goodput-requests",json=p.model_dump(mode="json")).status_code,403)
                for i,node in enumerate(nodes):
                    folder=root/str(i);folder.mkdir()
                    atomic(folder/"peer-throughput.json",[p.policy.model_dump(mode="json")])
                    for name,path in (("peer-cert.pem",certs[i][0]),("peer-key.pem",certs[i][1]),("peer-ca.pem",ca_path)):
                        target=folder/name;target.write_bytes(path.read_bytes());target.chmod(0o600)
                    client=TestClient(app,base_url="http://127.0.0.1");clients.append(client)
                    def post(path,body,client=client,node=node):
                        return client.post("/api/v1/agents/machine/goodput/"+path,json=body,headers={"Authorization":"Bearer "+node["credential"]})
                    runtime=GoodputAgentRuntime(folder,node["id"],post,atomic);runtimes.append(runtime)
                    self.assertFalse(runtime.step())
                self.assertEqual(owner.post("/api/v1/agents/goodput-requests",json=p.model_dump(mode="json"),headers=csrf).status_code,202)
                self.assertEqual(owner.post("/api/v1/agents/machine/goodput/offer",json={}).status_code,403)
                self.assertEqual(clients[1].get("/api/v1/agents/goodput-requests").status_code,401)
                def receive():
                    try:runtimes[1].step()
                    except Exception as exc:errors.append(type(exc).__name__)
                worker=threading.Thread(target=receive,daemon=True);worker.start()
                until=time.monotonic()+5
                while s.goodput_detail(p.request_id)["state"]!="ready" and time.monotonic()<until:time.sleep(.025)
                self.assertEqual(s.goodput_detail(p.request_id)["state"],"ready")
                self.assertTrue(runtimes[0].step())
                worker.join(12);self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
                detail=owner.get("/api/v1/agents/goodput-requests/"+p.request_id).json()
                self.assertEqual(detail["state"],"completed",detail)
                self.assertEqual(detail["source_report"],detail["receiver_report"])
                self.assertNotIn("receiver_lease",detail)
                obs,_=decode(s.pending_evidence()["payload"])
                self.assertEqual((obs[0].source_part,obs[0].outcome),("peer-goodput-v1","success"))
                self.assertGreater(next(m.value for m in obs[0].measurements if m.name=="application_goodput"),0)
                for runtime in runtimes:
                    restored=GoodputAgentRuntime(runtime.local.root,runtime.agent_id,runtime.post,atomic)
                    self.assertFalse(restored.journal.begin(p.request_id))
                    self.assertIsNone(restored.journal.data["pending"])
                print("Real two-agent paced mTLS goodput through owner/machine API and evidence verified")
            finally:
                for c in clients:c.close()

    def test_claim_refresh_and_disabled_retry_are_bounded(self):
        import httpx
        from backend.ndc.peer_runtime import ClaimRefresh
        now=[0.];calls=[];status=[200]
        def post(path,body):
            calls.append((path,body))
            return httpx.Response(status[0],request=httpx.Request("POST","https://fixture.test"))
        refresh=ClaimRefresh(lambda:now[0])
        for i in range(12):
            now[0]=float(i)
            self.assertTrue(refresh.refresh(post,{"directions":[]}))
        self.assertEqual(len(calls),1)
        now[0]=12.;status[0]=409
        self.assertFalse(refresh.refresh(post,{}))
        now[0]=15.;status[0]=200
        self.assertFalse(refresh.refresh(post,{}))
        self.assertEqual(len(calls),2)
        now[0]=24.
        self.assertTrue(refresh.refresh(post,{}))
        refresh.invalidate();status[0]=401
        with self.assertRaises(httpx.HTTPStatusError):refresh.refresh(post,{})
        self.assertEqual(len(calls),4)

if __name__=="__main__":unittest.main()
