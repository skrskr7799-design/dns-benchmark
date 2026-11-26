import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from backend.ndc.remote_contract import RemoteTCP,config_key
from backend.ndc.remote_worker import Approval,load_approvals,run_tcp,probe
from backend.ndc.agent_client import Agent,atomic

class Tests(unittest.TestCase):
    def test_real_tcp_and_denial(self):
        with socket.socket() as sock,patch.dict(os.environ,{"NDC_ALLOWED_CIDRS":"127.0.0.1/32"}):
            sock.bind(("127.0.0.1",0));sock.listen(2);sock.settimeout(2)
            cfg=RemoteTCP(host="127.0.0.1",port=sock.getsockname()[1])
            approval=Approval(config=cfg,cidrs=["127.0.0.1/32"])
            cancel=threading.Event()
            self.assertEqual(run_tcp(cfg,(),cancel),(None,"local_policy_denied"))
            self.assertEqual(run_tcp(cfg,(Approval(config=cfg,cidrs=["127.0.0.2/32"]),),cancel),(None,"local_policy_denied"))
            row,error=run_tcp(cfg,(approval,),cancel)
            self.assertIsNone(error);self.assertEqual(row.outcome,"success")
            self.assertEqual(row.peer_ip,"127.0.0.1")
            conn,_=sock.accept();conn.close()
            sock.settimeout(.1)
            with self.assertRaises(TimeoutError):sock.accept()
    def test_all_addresses_checked_before_socket(self):
        cfg=RemoteTCP(host="example.com",port=443)
        approval=Approval(config=cfg,cidrs=["1.1.1.1/32"])
        answers=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("1.1.1.1",443)),(socket.AF_INET,socket.SOCK_STREAM,6,"",("169.254.169.254",443))]
        with patch("socket.getaddrinfo",return_value=answers),patch("socket.socket") as connect:
            with self.assertRaises(PermissionError):probe(cfg,approval)
            connect.assert_not_called()
    def test_deadline_and_cancel_reap(self):
        cfg=RemoteTCP(host="localhost",port=443);a=Approval(config=cfg,cidrs=["127.0.0.1/32"])
        original=subprocess.Popen;children=[]
        def slow(*args,**kwargs):
            p=original([sys.executable,"-c","import time;time.sleep(30)"],**kwargs)
            children.append(p);return p
        with patch("backend.ndc.remote_worker.subprocess.Popen",side_effect=slow):
            start=time.monotonic()
            self.assertEqual(run_tcp(cfg,(a,),threading.Event(),deadline=.2),(None,"deadline"))
            self.assertLess(time.monotonic()-start,3);self.assertIsNotNone(children[-1].poll())
            cancel=threading.Event();timer=threading.Timer(.2,cancel.set);timer.start()
            try:self.assertEqual(run_tcp(cfg,(a,),cancel),(None,"cancelled"))
            finally:timer.cancel()
            self.assertIsNotNone(children[-1].poll())
    def test_approval_file_and_spool(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{"NDC_AGENT_TEST_HTTP":"1"}):
            root=Path(tmp);path=root/"allowed-probes.json"
            self.assertEqual(load_approvals(path),())
            cfg=RemoteTCP(host="localhost",port=443);a=Approval(config=cfg,cidrs=["127.0.0.1/32"])
            path.write_text(json.dumps([a.model_dump(mode="json")]))
            self.assertEqual(load_approvals(path),(a,))
            path.write_text(json.dumps([a.model_dump(mode="json")]*2))
            with self.assertRaises(ValueError):load_approvals(path)
            with self.assertRaises(ValueError):Approval(config=cfg,cidrs=["0.0.0.0/0"])
            agent=Agent(root,"http://127.0.0.1:8080",["udp://127.0.0.1"],protocol_v2=True,approvals=(a,))
            self.addCleanup(agent.client.close)
            atomic(agent.spool,{"state":"executing","version":"2","id":"a"*32,"result_base":{"version":"2","engine":"python-network-v2","kind":"tcp","lease":"b"*43,"config_key":config_key(cfg)}})
            class Reply:
                status_code=200
            with patch.object(agent,"post",return_value=Reply()) as post:
                self.assertTrue(agent.flush())
            self.assertEqual(post.call_args.args[0],"v2/results/"+"a"*32)
            self.assertEqual(post.call_args.args[1]["execution_error"],"interrupted")
            self.assertFalse(agent.spool.exists())

if __name__=="__main__":unittest.main()
