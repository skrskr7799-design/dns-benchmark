import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event
from backend.ndc.storage import Store, Busy
from backend.ndc.jobs import Coordinator

CONFIG={"endpoints":["udp://127.0.0.1","udp://127.0.0.2"],"count":2,"mode":"cold","family":"ipv4","parallel":1}
class JobsTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"history.sqlite"
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE runs(id INTEGER PRIMARY KEY,payload TEXT)")
            db.execute("INSERT INTO runs(payload) VALUES(?)", ('{"time":1,"results":[]}',))
        self.store=Store(self.path)
        self.store.initialize()

    def wait(self,job_id,state):
        for _ in range(200):
            job=self.store.get(job_id)
            if job["status"]==state:
                return job
            time.sleep(.02)
        self.fail(str(self.store.get(job_id)))

    def test_migration_and_restart(self):
        self.assertEqual(self.store.history(),[{"time":1,"results":[]}])
        self.assertTrue(self.path.with_name("history.before-fnd02.sqlite").exists())
        first=self.store.create(CONFIG)
        second=self.store.create(CONFIG)
        self.assertEqual(self.store.claim(),first)
        self.store.add_result(first,0,{"count":2,"ok":2})
        self.store.initialize()
        self.assertEqual(self.store.get(first)["status"],"interrupted")
        self.assertEqual(self.store.get(first)["results"],[{"count":2,"ok":2}])
        self.assertEqual(self.store.get(second)["status"],"queued")

    def test_completion(self):
        def probe(endpoint,count,mode,family,cancel):
            return {"endpoint":endpoint,"count":count,"ok":count}
        c=Coordinator(self.store,probe)
        self.addCleanup(c.stop)
        c.start()
        job=c.submit(CONFIG)
        result=self.wait(job,"completed")
        self.assertEqual(result["done"],2)
        self.assertEqual(len(self.store.history()),2)

    def test_cancel_and_no_new_work(self):
        entered=Event()
        calls=[]
        def probe(endpoint,count,mode,family,cancel):
            calls.append(endpoint)
            entered.set()
            cancel.wait(5)
            return {"endpoint":endpoint,"count":1,"requested_count":count,"ok":1}
        c=Coordinator(self.store,probe)
        self.addCleanup(c.stop)
        c.start()
        job=c.submit(CONFIG)
        self.assertTrue(entered.wait(2))
        with self.assertRaises(Busy):
            c.submit(CONFIG,legacy=True)
        c.cancel(job)
        result=self.wait(job,"cancelled")
        self.assertEqual(len(calls),1)
        self.assertEqual(result["done"],0)
        self.assertEqual(len(result["results"]),1)
        self.assertEqual(len(self.store.history()),1)

    def test_queued_cancel_and_profile(self):
        job=self.store.create(CONFIG)
        self.assertEqual(self.store.cancel(job)["status"],"cancelled")
        self.assertIsNone(self.store.claim())
        p=self.store.put_profile({"name":"test","config":CONFIG})
        self.assertEqual(self.store.profiles()[0]["config"],CONFIG)
        self.assertTrue(self.store.delete_profile(p["id"]))
        self.assertEqual(self.store.profiles(),[])

if __name__=="__main__":
    unittest.main()
