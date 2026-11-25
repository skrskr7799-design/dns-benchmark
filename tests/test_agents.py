import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from backend.ndc.agent_store import AgentStore,AgentError
from backend.ndc.agent_contract import AgentRun,Heartbeat,ActiveHeartbeat,Result
from backend.ndc.agent_client import execute,controller_url,atomic,Agent
from backend.ndc.probes.dns import domains

class AgentsTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.now=100000
        self.store=AgentStore(self.root/"agents.sqlite",lambda:self.now)
        self.store.initialize()
        self.invite=self.store.invite("fixture","local")
        self.agent=self.store.enroll(self.invite["token"])
        self.credential=self.agent["credential"]
        self.cfg=AgentRun(endpoints=["udp://127.0.0.1"],count=1)

    def lease(self):
        id=self.store.enqueue(self.agent["id"],self.cfg)["id"]
        task=self.store.poll(self.credential,Heartbeat())["task"]
        self.assertEqual(task["id"],id)
        return task

    def failure(self,task):
        return Result(lease=task["lease"],status="failed",error="fixture")

    def test_invite_single_use_and_rotation(self):
        with self.assertRaises(AgentError):
            self.store.enroll(self.invite["token"])
        new=self.store.rotate(self.agent["id"])
        with self.assertRaises(AgentError):
            self.store.poll(self.credential,Heartbeat())
        credential=self.store.enroll(new["token"])["credential"]
        self.assertIsNone(self.store.poll(credential,Heartbeat())["task"])
        self.store.revoke(self.agent["id"])
        with self.assertRaises(AgentError):
            self.store.poll(credential,Heartbeat())

    def test_lease_idempotency_cross_agent_and_expiration(self):
        task=self.lease()
        self.assertIsNone(self.store.poll(self.credential,Heartbeat())["task"])
        other=self.store.enroll(self.store.invite("second","")["token"])
        with self.assertRaises(AgentError):
            self.store.complete(other["credential"],task["id"],self.failure(task))
        self.assertFalse(self.store.complete(self.credential,task["id"],self.failure(task))["duplicate"])
        self.store.initialize()
        self.assertTrue(self.store.complete(self.credential,task["id"],self.failure(task))["duplicate"])
        with self.assertRaises(AgentError):
            self.store.complete(self.credential,task["id"],Result(lease=task["lease"],status="failed",error="different"))
        task=self.lease()
        self.now+=301
        self.assertEqual(self.store.detail(task["id"])["state"],"interrupted")
        with self.assertRaises(AgentError):
            self.store.complete(self.credential,task["id"],self.failure(task))
        self.assertIsNone(self.store.poll(self.credential,Heartbeat())["task"])

    def test_heartbeat_and_cancellation(self):
        task=self.lease()
        hb=ActiveHeartbeat(task_id=task["id"],lease=task["lease"])
        self.assertTrue(self.store.heartbeat(self.credential,hb)["active"])
        self.assertTrue(self.store.list()[0]["online"])
        self.store.cancel(task["id"])
        self.assertFalse(self.store.heartbeat(self.credential,hb)["active"])
        self.now+=46
        self.assertFalse(self.store.list()[0]["online"])

    def test_contract_and_allowlist(self):
        for kwargs in ({"count":11},{"parallel":2},{"endpoints":["udp://1.1.1.1","udp://8.8.8.8"]},{"command":"id"}):
            with self.assertRaises(ValueError):
                AgentRun(**({"endpoints":["udp://1.1.1.1"]}|kwargs))
        task=self.lease()
        with patch("backend.ndc.agent_client.measure") as probe:
            with self.assertRaises(ValueError):
                execute(task,[])
            probe.assert_not_called()
        with self.assertRaises(ValueError):
            controller_url("http://example.com")
        with self.assertRaises(ValueError):
            controller_url("https://user:pass@example.com")

    def test_result_validation(self):
        task=self.lease()
        row={"endpoint":self.cfg.endpoints[0],"mode":"cold","family":"ipv4","engine":"python-dns02","count":1,"ok":1,"samples":[{"index":0,"domain":domains[0],"qtype":"A","ok":True,"duration_ms":1}]}
        bad=dict(row)|{"endpoint":"udp://8.8.8.8"}
        with self.assertRaises(AgentError):
            self.store.complete(self.credential,task["id"],Result(lease=task["lease"],status="completed",results=[bad]))
        self.assertTrue(self.store.complete(self.credential,task["id"],Result(lease=task["lease"],status="completed",results=[row]))["accepted"])

    def test_spool_restart(self):
        task=self.lease()
        with patch.dict(os.environ,{"NDC_AGENT_TEST_HTTP":"1"}):
            agent=Agent(self.root/"client","http://127.0.0.1:8080",self.cfg.endpoints)
        self.addCleanup(agent.client.close)
        atomic(agent.spool,{"state":"executing","id":task["id"],"lease":task["lease"]})
        class Reply:
            status_code=200
        with patch.object(agent,"post",return_value=Reply()) as post:
            self.assertTrue(agent.flush())
        self.assertEqual(post.call_args.args[1]["status"],"failed")
        self.assertFalse(agent.spool.exists())

if __name__=="__main__":
    unittest.main()
