import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from backend.ndc.experiment_history import ExperimentHistory,optionally_save
from backend.ndc.evidence import Conflict

class Tests(unittest.TestCase):
    def test_persistence_capacity_and_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"experiments.sqlite";s=ExperimentHistory(path);s.initialize()
            report={"status":"completed","rows":[{"p50":1.2}]}
            self.assertEqual(optionally_save(s,"protocol_lab",report,False)["history_status"],"not_requested")
            self.assertEqual(s.list("protocol_lab"),[])
            first=optionally_save(s,"protocol_lab",report,True)
            id=first["history_id"];self.assertEqual(first["history_status"],"saved")
            s=ExperimentHistory(path);s.initialize()
            self.assertEqual(s.get(id)["report"],report)
            self.assertEqual(s.list("website_xray"),[])
            with patch("backend.ndc.experiment_history.MAX_ROWS",1):
                failed=optionally_save(s,"website_xray",report,True)
                self.assertEqual(failed["history_status"],"not_saved")
                self.assertEqual(failed["rows"],report["rows"])
            self.assertTrue(s.delete(id));self.assertFalse(s.delete(id));self.assertIsNone(s.get(id))
            id=s.save("website_xray",report)
            with s.db() as c:c.execute("UPDATE reports SET payload='{}' WHERE id=?",(id,))
            with self.assertRaises(Conflict):s.get(id)

if __name__=="__main__":unittest.main()
