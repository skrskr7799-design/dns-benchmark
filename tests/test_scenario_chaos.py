import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from backend.ndc.scenario import Definition,Save,Run,ScenarioStore,evaluate
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
