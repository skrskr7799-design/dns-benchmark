import tempfile
import unittest
import os
import fcntl
from pathlib import Path
from unittest.mock import patch
from backend.ndc.storage import Store, Busy
from backend.ndc.backup import backup,restore
from backend.ndc.security import Security,matches_csrf
from backend.ndc.evidence import EvidenceStore
from backend.ndc.benchmark_evidence import BenchmarkDrain
from unittest.mock import patch as env_patch

CFG={"endpoints":["udp://127.0.0.1"],"count":1,"mode":"cold","family":"ipv4","parallel":1}
class ReleaseTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.data=self.root/"data"
        self.data.mkdir()
        with patch.dict(os.environ,{"NDC_MAX_JOBS":"10"}):
            self.store=Store(self.data/"history.sqlite")
        self.store.initialize()

    def test_capacity_and_explicit_delete(self):
        for _ in range(10):
            id=self.store.create(CFG)
            with self.assertRaises(Busy):
                self.store.delete_run(id)
            self.store.cancel(id)
        with self.assertRaises(Busy):
            self.store.create(CFG)
        self.assertTrue(self.store.delete_run(id))
        self.assertIsNone(self.store.get(id))
        self.store.create(CFG)

    def test_backup_restore_and_integrity(self):
        id=self.store.create(CFG)
        self.store.claim()
        self.store.add_result(id,0,{"count":1,"ok":1})
        self.store.finish(id,"completed")
        password=self.data/"owner-password"
        password.write_text("fixture-password-long");password.chmod(0o600)
        with env_patch.dict(os.environ,{},clear=False):
            os.environ.pop("NDC_OWNER_PASSWORD",None)
            account_dir=self.root/"account"
            account_dir.mkdir()
            Security(account_dir).setup("admin","fixture-account-password")
            (account_dir/"owner-account.json").replace(self.data/"owner-account.json")
        evidence=EvidenceStore(self.data/"intelligence.sqlite");evidence.initialize()
        # Simulate power loss after derived commit and before source acknowledgement.
        def crash(): raise RuntimeError("injected after derived commit")
        with self.assertRaises(RuntimeError): BenchmarkDrain(self.store,evidence).once(crash)
        self.assertEqual(self.store.evidence_pending_count(),1)
        self.assertEqual(evidence.status()["rows"],1)
        dest=self.root/"backup"
        with open(self.data/"coordinator.lock","a") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                backup(self.data,dest)
        backup(self.data,dest)
        restored=self.root/"restore"
        restore(dest,restored)
        self.assertEqual(Store(restored/"history.sqlite").get(id)["status"],"completed")
        self.assertEqual((restored/"owner-password").stat().st_mode&0o777,0o600)
        self.assertEqual((restored/"owner-account.json").stat().st_mode&0o777,0o600)
        Security(restored).login("fixture-account-password","admin")
        restored_store=Store(restored/"history.sqlite");restored_store.initialize()
        restored_evidence=EvidenceStore(restored/"intelligence.sqlite");restored_evidence.initialize()
        self.assertEqual(restored_evidence.status()["rows"],1)
        self.assertTrue(BenchmarkDrain(restored_store,restored_evidence).once())
        self.assertEqual(restored_store.evidence_pending_count(),0)
        self.assertEqual(restored_evidence.status()["rows"],1)
        with self.assertRaises(FileExistsError):
            restore(dest,restored)
        (dest/"owner-password").write_text("changed")
        with self.assertRaises(ValueError):
            restore(dest,self.root/"bad")
        self.assertFalse((self.root/"bad").exists())

    def test_secret_permissions_and_csrf(self):
        p=self.data/"owner-password"
        p.write_text("fixture-password-long");p.chmod(0o644)
        with self.assertRaises(RuntimeError):
            Security(self.data)
        p.chmod(0o600)
        Security(self.data)
        self.assertFalse(matches_csrf("é","ascii"))
        self.assertTrue(matches_csrf("ascii","ascii"))

if __name__=="__main__":
    unittest.main()
