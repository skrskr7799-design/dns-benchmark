import os
import subprocess
import sys
import time
import unittest
from backend.ndc.bounded_worker import bounded_worker

class Tests(unittest.TestCase):
    def worker(self,code,body="",timeout=3,limit=1024):
        return bounded_worker([sys.executable,"-c",code],body,timeout=timeout,max_output=limit)
    def test_echo_and_boundaries(self):
        self.assertEqual(self.worker("import sys; print(sys.stdin.read(),end='')","hello"),"hello")
        self.assertEqual(len(self.worker("print('x'*1024,end='')")),1024)
        with self.assertRaises(RuntimeError):self.worker("print('x'*1025,end='')")
        with self.assertRaises(RuntimeError):self.worker("import sys;sys.stderr.write('x'*65537)")
        with self.assertRaises(RuntimeError):self.worker("raise SystemExit(1)")
    def test_real_deadline_and_reap(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        with TemporaryDirectory() as tmp:
            pidfile=Path(tmp)/"pid"
            code="import os,time;from pathlib import Path;Path("+repr(str(pidfile))+").write_text(str(os.getpid()));time.sleep(30)"
            start=time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):self.worker(code,timeout=1.5)
            self.assertLess(time.monotonic()-start,5)
            pid=int(pidfile.read_text())
            with self.assertRaises(ProcessLookupError):os.kill(pid,0)
    def test_nonreading_child(self):
        with self.assertRaises(subprocess.TimeoutExpired):self.worker("import time;time.sleep(30)","x"*16384,timeout=.3)
    def test_input_limit(self):
        with self.assertRaises(ValueError):self.worker("pass","x"*16385)

if __name__=="__main__":unittest.main()
