import tempfile
import unittest
import os
from pathlib import Path
from unittest.mock import patch
from backend.ndc.agent_store import AgentStore,AgentError
from backend.ndc.agent_contract import AgentRun,Heartbeat,ActiveHeartbeat,Result,PollV2
from backend.ndc.agent_client import Agent,atomic

def report(kinds=("dns",)):
    return PollV2(version="2",engine="python-network-v2",capabilities=list(kinds))

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.now=100000.
        self.s=AgentStore(self.root/"agents.sqlite",lambda:self.now);self.s.initialize()
        self.s.remote_kinds=() # isolate pre-executor negotiation tests
        self.a=self.s.enroll(self.s.invite("one","site")["token"])
        self.b=self.s.enroll(self.s.invite("two","site")["token"])
        self.cfg=AgentRun(endpoints=["udp://127.0.0.1"],count=1)
    def claim(self,kinds=("dns",)):
        return self.s.poll_v2(self.a["credential"],report(kinds))
    def capabilities(self):
        return next(x for x in self.s.capability_list()["agents"] if x["id"]==self.a["id"])
    def test_v2_v1_dns_lease_and_single_active(self):
        task=self.s.enqueue(self.a["id"],self.cfg)["id"]
        self.assertIsNone(self.claim(("tcp","route"))["task"])
        self.assertEqual(self.capabilities()["dispatchable"],[])
        reply=self.claim(("dns","tcp"));lease=reply["task"]
        self.assertEqual(reply["dispatchable"],["dns"])
        self.assertEqual((lease["id"],lease["version"],lease["engine"]),(task,"1","python-dns02"))
        self.assertEqual(set(lease),{"id","lease","lease_seconds","config","version","engine"})
        self.assertIsNone(self.s.poll(self.a["credential"],Heartbeat())["task"])
        self.assertEqual(self.capabilities()["provenance"],"unreported")
        self.assertIsNone(self.claim()["task"])
        hb=ActiveHeartbeat(task_id=task,lease=lease["lease"])
        self.assertTrue(self.s.heartbeat(self.a["credential"],hb)["active"])
        self.assertFalse(self.s.heartbeat(self.b["credential"],hb)["active"])
        result=Result(lease=lease["lease"],status="failed",error="fixture")
        with self.assertRaises(AgentError):self.s.complete(self.b["credential"],task,result)
        self.assertFalse(self.s.complete(self.a["credential"],task,result)["duplicate"])
        self.assertTrue(self.s.complete(self.a["credential"],task,result)["duplicate"])
        self.assertEqual(self.s.evidence_status()["pending"],1)
    def test_stale_clock_rollback_and_rotation(self):
        self.claim(("dns","tls"))
        self.assertEqual(self.capabilities()["dispatchable"],["dns"])
        self.now+=45
        self.assertFalse(self.capabilities()["fresh"])
        self.assertEqual(self.capabilities()["capabilities"],["dns","tls"])
        self.now-=46
        self.assertFalse(self.capabilities()["fresh"])
        self.claim()
        token=self.s.rotate(self.a["id"])["token"]
        with self.assertRaises(AgentError):self.claim()
        self.a=self.s.enroll(token)
        self.assertEqual(self.capabilities()["capabilities"],[])
        self.claim();self.s.revoke(self.a["id"])
        self.assertEqual(self.capabilities()["capabilities"],[])
        self.assertFalse(self.capabilities()["fresh"])
    def test_migration_preserves_old_active_lease(self):
        task=self.s.enqueue(self.a["id"],self.cfg)["id"]
        lease=self.s.poll(self.a["credential"],Heartbeat())["task"]
        with self.s.db() as c:
            c.execute("DROP TABLE remote_batch_policy")
            c.execute("DROP TABLE agent_capabilities")
            c.execute("ALTER TABLE tasks DROP COLUMN contract_version")
            c.execute("ALTER TABLE tasks DROP COLUMN probe_kind")
            c.execute("PRAGMA user_version=1")
        self.s.initialize()
        with self.s.db() as c:
            self.assertEqual(tuple(c.execute("SELECT contract_version,probe_kind FROM tasks WHERE id=?",(task,)).fetchone()),("1","dns"))
        self.assertIsNone(self.claim()["task"])
        result=Result(lease=lease["lease"],status="failed",error="legacy lease")
        self.assertTrue(self.s.complete(self.a["credential"],task,result)["accepted"])
        self.assertEqual(self.s.detail(task)["state"],"failed")
    def test_future_task_is_not_dispatched(self):
        task=self.s.enqueue(self.a["id"],self.cfg)["id"]
        with self.s.db() as c:
            c.execute("UPDATE tasks SET contract_version='2',probe_kind='tcp' WHERE id=?",(task,))
        self.assertIsNone(self.s.poll(self.a["credential"],Heartbeat())["task"])
        self.assertIsNone(self.claim(("dns","tcp"))["task"])
        self.assertEqual(self.s.tasks(),[])
        with self.assertRaises(AgentError):self.s.detail(task)
        with self.assertRaises(AgentError):self.s.cancel(task)
        for _ in range(3):self.s.enqueue(self.a["id"],self.cfg)
        with self.assertRaises(AgentError):self.s.enqueue(self.a["id"],self.cfg)
    def test_strict_claims(self):
        for kw in ({"version":"1"},{"engine":"unknown"},{"capabilities":["dns","dns"]},{"capabilities":["shell"]},{"extra":True},{"capabilities":"dns"}):
            with self.assertRaises(ValueError):
                PollV2(**({"version":"2","engine":"python-network-v2","capabilities":["dns"]}|kw))
    def test_opt_in_client_and_old_spool(self):
        with patch.dict(os.environ,{"NDC_AGENT_TEST_HTTP":"1"}):
            a=Agent(self.root/"client","http://127.0.0.1:8080",self.cfg.endpoints,protocol_v2=True)
        self.addCleanup(a.client.close)
        atomic(a.spool,{"state":"ready","id":"a"*32,"body":{"lease":"b"*43,"status":"failed","results":[],"error":"legacy"}})
        class Reply:
            status_code=200
            def raise_for_status(self):pass
            def json(self):return {"version":"2","dispatchable":["dns"],"task":None}
        with patch.object(a,"post",return_value=Reply()) as post:
            a.step()
        self.assertEqual(post.call_args_list[0].args[0],"results/"+"a"*32)
        self.assertEqual(post.call_args_list[1].args,("v2/poll",{"version":"2","engine":"python-network-v2","capabilities":["dns"]}))
        self.assertFalse(a.spool.exists())

if __name__=="__main__":unittest.main()
