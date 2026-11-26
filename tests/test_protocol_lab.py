import os
import socket
import subprocess
import threading
import unittest
from unittest.mock import patch
import dns.message
import dns.rrset
from backend.ndc.protocol_lab import LabProfile,run,execute,authorize,configured

class Tests(unittest.TestCase):
    def test_bounds_and_allowlist(self):
        p=LabProfile(endpoints=["udp://127.0.0.1"],families=["ipv4"],modes=["cold","warm"],count=3)
        self.assertEqual(p.planned_queries,7)
        with patch.dict(os.environ,{"NDC_LAB_ENDPOINTS":"[]"}):
            with self.assertRaises(PermissionError):authorize(p)
        with self.assertRaises(ValueError):LabProfile(endpoints=["udp://127.0.0.1","udp://127.0.0.2"],families=["ipv4","ipv6"],modes=["cold","warm"],count=6)
        with self.assertRaises(ValueError):LabProfile(endpoints=["udp://127.0.0.1"],families=["ipv4"],modes=["cold"],parallel=2)
        with patch.dict(os.environ,{"NDC_LAB_ENDPOINTS":'["udp://127.0.0.1","udp://127.0.0.1"]'}):
            with self.assertRaises(ValueError):configured()

    def test_deadline_never_publishes_partial(self):
        p=LabProfile(endpoints=["udp://127.0.0.1"],families=["ipv4"],modes=["cold"])
        with patch.dict(os.environ,{"NDC_LAB_ENDPOINTS":'["udp://127.0.0.1"]'}),patch("backend.ndc.protocol_lab.subprocess.run",side_effect=subprocess.TimeoutExpired("fixture",45)):
            r=run(p)
        self.assertEqual((r["status"],r["rows"],r["comparisons"]),("deadline",[],[]))

    def test_real_udp_child_fixed_corpus(self):
        import json
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1",0));sock.settimeout(.2)
            ep="udp://127.0.0.1:"+str(sock.getsockname()[1]);stop=threading.Event();seen=[]
            def server():
                while not stop.is_set():
                    try:wire,addr=sock.recvfrom(65535)
                    except socket.timeout:continue
                    q=dns.message.from_wire(wire);seen.append(q.question[0].name.to_text())
                    r=dns.message.make_response(q)
                    r.answer.append(dns.rrset.from_text(q.question[0].name,60,"IN","A","192.0.2.1"))
                    sock.sendto(r.to_wire(),addr)
            worker=threading.Thread(target=server,daemon=True);worker.start()
            try:
                p=LabProfile(endpoints=[ep],families=["ipv4"],modes=["cold","warm"],count=2)
                with patch.dict(os.environ,{"NDC_LAB_ENDPOINTS":json.dumps([ep]),"NDC_ALLOWED_CIDRS":"127.0.0.0/8"}):
                    r=run(p)
                self.assertEqual(r["status"],"completed")
                self.assertEqual(seen,["example.com.","example.org.","example.net.","example.com.","example.org."])
                self.assertEqual([x["ok"] for x in r["rows"]],[2,2])
                self.assertTrue(all(x["transport_matched"] for x in r["rows"]))
                self.assertIsNone(r["comparisons"][0]["warm_minus_cold_p50_ms"])
            finally:stop.set();worker.join(2)

if __name__=="__main__":unittest.main()
