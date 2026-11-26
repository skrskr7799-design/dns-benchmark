import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.ndc.agent_store import AgentStore
from backend.ndc.peer_api import router
from backend.ndc.security import Security,guard,router as auth_router
from backend.ndc.peer_contract import PeerDirection,RTTPlan,RTTReport,RTTSample

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        env=patch.dict(os.environ,{"NDC_OWNER_PASSWORD":"test-owner-password-long","NDC_SECURE_COOKIE":"0","NDC_ORIGIN":""})
        env.start();self.addCleanup(env.stop)
        self.path=Path(tmp.name)/"agents.sqlite";self.now=100000.
        self.s=AgentStore(self.path,lambda:self.now);self.s.initialize()
        self.a=self.s.enroll(self.s.invite("source","fixture")["token"])
        self.b=self.s.enroll(self.s.invite("receiver","fixture")["token"])
        self.c=self.s.enroll(self.s.invite("other","fixture")["token"])
        d=PeerDirection(source_agent_id=self.a["id"],destination_agent_id=self.b["id"],source_ip="127.0.0.1",destination_ip="127.0.0.2",
            port=8443,source_certificate="1"*64,destination_certificate="2"*64)
        self.plan=RTTPlan(request_id="a"*32,direction=d,samples=1)
        self.id=self.plan.request_id;self.grant="g"*43
        self.app=FastAPI();self.app.state.agents=self.s;self.app.state.security=Security(tmp.name)
        self.app.middleware("http")(guard);self.app.include_router(router);self.app.include_router(auth_router)
        self.owner=TestClient(self.app,base_url="http://127.0.0.1")
        self.machine=TestClient(self.app,base_url="http://127.0.0.1")
        self.addCleanup(self.owner.close);self.addCleanup(self.machine.close)
        login=self.owner.post("/api/auth/login",json={"password":"test-owner-password-long"},headers={"X-NDC-Request":"1"})
        self.assertEqual(login.status_code,200,login.text)
        self.csrf={"X-CSRF-Token":login.json()["csrf"]}
    def send(self,node,path,body,code=200):
        r=self.machine.post("/api/v1/agents/machine/peer/"+path,json=body,headers={"Authorization":"Bearer "+node["credential"]})
        self.assertEqual(r.status_code,code,r.text)
        self.assertEqual(r.headers.get("cache-control"),"no-store")
        return r.json()
    def admit(self):
        self.s.peer_enabled=True
        for n in (self.a,self.b):self.send(n,"claims",{"directions":[self.plan.direction.model_dump(mode="json")]})
        r=self.owner.post("/api/v1/agents/peer-requests",json=self.plan.model_dump(mode="json"),headers=self.csrf)
        self.assertEqual(r.status_code,202,r.text)
    def ready(self):
        self.admit()
        self.assertIsNone(self.send(self.a,"offer",{})["offer"])
        self.assertEqual(self.send(self.b,"offer",{})["offer"]["role"],"receiver")
        r=self.send(self.b,"prepare",{"id":self.id})
        self.send(self.b,"ready",{"id":self.id,"lease":r["lease"],"grant":self.grant})
        return r["lease"]
    def test_gate_machine_and_owner(self):
        self.send(self.a,"offer",{},409)
        self.s.peer_enabled=True
        self.assertEqual(self.machine.post("/api/v1/agents/machine/peer/offer",json={}).status_code,401)
        self.assertEqual(self.owner.post("/api/v1/agents/machine/peer/offer",json={}).status_code,403)
        self.assertEqual(self.machine.get("/api/v1/agents/peer-requests").status_code,401)
        self.assertEqual(self.owner.post("/api/v1/agents/peer-requests",json=self.plan.model_dump(mode="json")).status_code,403)
    def test_one_shot_grant_and_results(self):
        receiver=self.ready()
        self.send(self.c,"start",{"id":self.id},409)
        self.assertEqual(self.send(self.a,"offer",{})["offer"]["role"],"source")
        self.assertNotIn(self.grant,self.owner.get("/api/v1/agents/peer-requests/"+self.id).text)
        start=self.send(self.a,"start",{"id":self.id})
        self.assertEqual(start["grant"],self.grant)
        self.assertFalse(self.s.peer_handoffs)
        self.send(self.a,"start",{"id":self.id},409)
        self.send(self.b,"ready",{"id":self.id,"lease":receiver,"grant":self.grant},409)
        self.assertTrue(self.send(self.b,"status",{"id":self.id,"lease":receiver})["active"])
        self.send(self.c,"status",{"id":self.id,"lease":receiver},409)
        report=RTTReport(plan=self.plan,samples=[RTTSample(index=1,status="echo",rtt_ms=2.)])
        self.send(self.a,"finish",{"id":self.id,"lease":start["lease"],"report":report.model_dump(mode="json")})
        self.assertEqual(self.send(self.b,"finish",{"id":self.id,"lease":receiver,"echoes":1})["state"],"completed")
        detail=self.owner.get("/api/v1/agents/peer-requests/"+self.id).text
        for secret in (self.grant,receiver,start["lease"]):self.assertNotIn(secret,detail)
        self.assertEqual(self.s.evidence_status()["pending"],1)
    def test_restart_fails_closed(self):
        self.ready()
        self.s=AgentStore(self.path,lambda:self.now);self.s.initialize();self.s.peer_enabled=True;self.app.state.agents=self.s
        self.send(self.a,"start",{"id":self.id},409)
        self.assertEqual(self.s.peer_detail(self.id)["state"],"interrupted")
        self.assertIsNone(self.send(self.a,"offer",{})["offer"])
    def test_cancel_and_redaction(self):
        receiver=self.ready()
        invalid=self.send(self.b,"ready",{"id":self.id,"lease":receiver,"grant":"sensitive-invalid-token"},422)
        self.assertEqual(invalid,{"detail":"Invalid peer payload"})
        self.assertEqual(self.owner.post("/api/v1/agents/peer-requests/"+self.id+"/cancel",json={},headers=self.csrf).status_code,200)
        self.assertFalse(self.s.peer_handoffs)
        self.assertFalse(self.send(self.b,"status",{"id":self.id,"lease":receiver})["active"])
        self.send(self.a,"start",{"id":self.id},409)

if __name__=="__main__":unittest.main()
