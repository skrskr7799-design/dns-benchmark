import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from backend.ndc.scenario import Definition,Save,Run,Schedule,ScenarioStore,evaluate
from backend.ndc.network_twin import TwinStore
from backend.ndc.evidence import Conflict
from backend.ndc.chaos_lab import Experiment,execute,run

M="a"*32
def definition():
    return {"name":"fixture","twin_revision":0,"steps":[
        {"id":"b","action":"summarize","depends_on":["a"],"condition":"any_failed"},
        {"id":"a","action":"monitor_state","target":M},
        {"id":"c","action":"summarize","depends_on":["a"],"condition":"all_healthy"}]}

class Tests(unittest.TestCase):
    def test_dag_and_conditions(self):
        d=Definition.model_validate(definition())
        self.assertEqual([s.id for s in d.steps],["a","b","c"])
        result=evaluate(d,{M:{"status":"fresh","outcome":"failure","evidence_id":None}}, {})
        self.assertEqual([(r["id"],r["state"]) for r in result],[("a","failed"),("b","failed"),("c",None)])
        result=evaluate(d,{M:{"status":"stale","outcome":"success","evidence_id":None}}, {})
        self.assertEqual(result[0]["state"],"unknown");self.assertEqual(result[2]["status"],"skipped")
        bad=definition();bad["steps"][1]["depends_on"]=["b"]
        with self.assertRaises(ValueError):Definition.model_validate(bad)

    def test_save_dry_run_and_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);t=TwinStore(root/"twin.sqlite");t.initialize()
            s=ScenarioStore(root/"scenarios.sqlite");s.initialize()
            body=Save(request_id="1"*32,expected_revision=0,definition=definition())
            with self.assertRaises(ValueError):s.save(body,t,set())
            first=s.save(body,t,{M});self.assertEqual(first["revision"],1)
            self.assertEqual(first,s.save(body,t,set()))
            with self.assertRaises(Conflict):s.save(body.model_copy(update={"request_id":"2"*32}),t,{M})
            req=Run(request_id="3"*32,revision=1,dry_run=True)
            with patch("backend.ndc.scenario.monitor_observations",side_effect=AssertionError("dry run reads no observations")):
                r=s.run(req,t,None,None)
            self.assertEqual(r["result"]["status"],"dry_run")
            s=ScenarioStore(root/"scenarios.sqlite");s.initialize()
            self.assertEqual(r,s.run(req,t,None,None))
            with self.assertRaises(Conflict):s.run(req.model_copy(update={"dry_run":False}),t,None,None)
            with patch("backend.ndc.scenario.monitor_observations",return_value=(100.,{M:{"status":"fresh","outcome":"failure","evidence_id":None}})):
                r=s.run(Run(request_id="4"*32,revision=1,dry_run=False),t,None,None)
            self.assertEqual(r["result"]["steps"][1]["state"],"failed")

    def test_automatic_interval_restart_capacity_and_pause(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);now=[10000.]
            t=TwinStore(root/"twin.sqlite");t.initialize()
            s=ScenarioStore(root/"scenarios.sqlite",lambda:now[0]);s.initialize()
            s.save(Save(request_id="1"*32,expected_revision=0,definition=definition()),t,{M})
            policy=Schedule(expected_generation=0,revision=1,enabled=True,interval_seconds=900)
            self.assertEqual(s.configure_schedule(policy,{M})["next_at"],10900.)
            with self.assertRaises(Conflict):s.configure_schedule(policy,{M})
            with patch("backend.ndc.scenario.monitor_observations",return_value=(now[0],{})):
                self.assertFalse(s.tick(t,None,None))
                now[0]+=9000
                self.assertTrue(s.tick(t,None,None))
                self.assertFalse(s.tick(t,None,None))
                first=s.schedule()["last_run_id"]
                self.assertEqual(s.get_run(first)["result"]["trigger"],"interval")
                s=ScenarioStore(root/"scenarios.sqlite",lambda:now[0]);s.initialize()
                self.assertEqual(s.schedule()["last_run_id"],first)
                self.assertFalse(s.tick(t,None,None))
                now[0]+=900
                with patch("backend.ndc.scenario.MAX_RUNS",1):
                    self.assertFalse(s.tick(t,None,None))
                self.assertFalse(s.schedule()["enabled"])
                self.assertEqual(s.schedule()["last_error"],"Capacity")
                self.assertTrue(s.delete_run(first))
                self.assertFalse(s.delete_run(first))
                s.configure_schedule(policy.model_copy(update={"expected_generation":s.schedule()["generation"]}),{M})
                s.configure_schedule(policy.model_copy(update={"expected_generation":s.schedule()["generation"],"enabled":False}),{M})
                now[0]+=900
                self.assertFalse(s.tick(t,None,None))

    def test_incident_requires_observed_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);now=[10000.]
            t=TwinStore(root/"twin.sqlite");t.initialize()
            s=ScenarioStore(root/"scenarios.sqlite",lambda:now[0]);s.initialize()
            s.save(Save(request_id="1"*32,expected_revision=0,definition=definition()),t,{M})
            s.configure_schedule(Schedule(expected_generation=0,revision=1,enabled=True,mode="incident",monitor_id=M,interval_seconds=900),{M})
            def tick(outcome,status="fresh"):
                now[0]+=60
                observation={M:{"status":status,"outcome":outcome,"observed_at":now[0],"evidence_id":None}}
                with patch("backend.ndc.scenario.monitor_observations",return_value=(now[0],observation)):
                    return s.tick(t,None,None)
            self.assertFalse(tick("failure"))
            self.assertFalse(tick("failure"))
            self.assertFalse(tick("success"))
            self.assertTrue(tick("failure"))
            first=s.schedule()["last_run_id"]
            self.assertEqual(s.get_run(first)["result"]["trigger"],"incident")
            self.assertFalse(tick("failure"))
            self.assertFalse(tick("success","stale"))
            self.assertFalse(tick("failure"))
            self.assertFalse(tick("success"))
            self.assertFalse(tick("failure")) # cooldown suppresses another transition
            self.assertEqual(len(s.runs()),1)

    def test_chaos_deterministic_and_child(self):
        cfg=Experiment(seed=42,samples=20,loss_pct=25,delay_ms=100)
        self.assertEqual(execute(cfg),execute(cfg))
        self.assertEqual(execute(cfg),run(cfg))
        self.assertEqual(sum(execute(cfg)["counts"].values()),20)
        self.assertEqual(execute(Experiment(seed=1,loss_pct=100))["counts"]["simulated_loss"],20)
        self.assertEqual(execute(Experiment(seed=1,dns="servfail"))["counts"]["dns_servfail"],20)
        self.assertEqual(execute(Experiment(seed=1,delay_ms=2000))["counts"]["simulated_deadline"],20)
        with self.assertRaises(ValueError):Experiment(seed=1,samples=101)

if __name__=="__main__":unittest.main()
