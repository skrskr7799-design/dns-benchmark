import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from backend.ndc.network_twin import TwinStore,Save,Graph,analyze
from backend.ndc.evidence import Conflict

A="a"*32;B="b"*32;C="c"*32;M="d"*32
def graph():
    return {"nodes":[{"id":A,"name":"Gateway","kind":"gateway","monitor_id":M},{"id":B,"name":"Service","kind":"service"},{"id":C,"name":"Site","kind":"site"}],
        "edges":[{"source":B,"target":A,"kind":"requires"},{"source":A,"target":B,"kind":"requires"},{"source":C,"target":A,"kind":"located_at"}]}
def body(request="1"*32,expected=0):
    return Save(request_id=request,expected_revision=expected,graph=Graph.model_validate(graph()))

class Tests(unittest.TestCase):
    def test_cycle_safe_impact_and_unknown(self):
        rows={r["id"]:r for r in analyze(body().graph.model_dump(mode="json"),{M:{"status":"fresh","outcome":"failure","observed_at":100.,"evidence_id":None}})}
        self.assertEqual(rows[A]["direct"],"failed")
        self.assertEqual(rows[B]["direct"],"unknown")
        self.assertEqual(rows[B]["failed_dependencies"],[A])
        self.assertTrue(rows[A]["cycle"]);self.assertTrue(rows[B]["cycle"])
        self.assertEqual(rows[A]["potentially_affected"],[B])
        self.assertEqual(rows[C]["dependency_impact"],"none_observed")
        stale={r["id"]:r for r in analyze(body().graph.model_dump(mode="json"),{M:{"status":"stale","outcome":"success","observed_at":100.,"evidence_id":None}})}
        self.assertEqual(stale[A]["direct"],"unknown")
        self.assertEqual(stale[B]["dependency_impact"],"unknown")

    def test_revision_conflict_replay_and_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"twin.sqlite";s=TwinStore(path);s.initialize()
            self.assertEqual(s.get()["revision"],0)
            with self.assertRaises(ValueError):s.save(body(),set())
            first=s.save(body(),{M});self.assertEqual(first["revision"],1)
            self.assertEqual(s.save(body(),set()),first)
            with self.assertRaises(Conflict):s.save(body("2"*32),{M})
            with self.assertRaises(Conflict):s.save(body(expected=1),{M})
            s=TwinStore(path);s.initialize();self.assertEqual(s.get(),first)
            self.assertEqual(s.save(body("2"*32,1),set())["revision"],2)
            self.assertEqual(s.get(1),first);self.assertIsNone(s.get(3))
            self.assertEqual(len(s.history()),2)

    def test_concurrent_cas(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=TwinStore(Path(tmp)/"twin.sqlite");s.initialize()
            def save(i):
                try:return s.save(body(str(i)*32),{M})["revision"]
                except Conflict:return "conflict"
            with ThreadPoolExecutor(max_workers=2) as pool:r=list(pool.map(save,[1,2]))
            self.assertCountEqual(r,[1,"conflict"])

    def test_invalid_edges(self):
        g=graph();g["edges"].append(g["edges"][0])
        with self.assertRaises(ValueError):Graph.model_validate(g)
        g=graph();g["edges"][0]["target"]="e"*32
        with self.assertRaises(ValueError):Graph.model_validate(g)

if __name__=="__main__":unittest.main()
