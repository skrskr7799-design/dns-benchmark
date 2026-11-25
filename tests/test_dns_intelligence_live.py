"""Real UDP loopback -> API -> SQLite outbox -> evidence -> ranking.
No external DNS, no mocked latency, no production credentials.
"""
import contextlib
import http.cookiejar
import json
import os
import socket
import threading
import time
import urllib.request
import dns.message
import dns.rrset

BASE="http://127.0.0.1:8080"
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf=None
def request(path,body=None):
    headers={"Content-Type":"application/json","X-NDC-Request":"1"}
    if csrf: headers["X-CSRF-Token"]=csrf
    req=urllib.request.Request(BASE+path,headers=headers,data=json.dumps(body).encode() if body is not None else None)
    with opener.open(req,timeout=10) as response:
        return json.load(response)

def wait_for(fn,timeout=30):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        value=fn()
        if value: return value
        time.sleep(.1)
    raise AssertionError("Timed out waiting for fixture state")

class Resolver:
    def __init__(self,delay):
        self.delay=delay;self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1",0));self.sock.settimeout(.2)
        self.endpoint="udp://127.0.0.1:"+str(self.sock.getsockname()[1])
        self.stop=threading.Event();self.errors=[];self.count=0
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        try:
            while not self.stop.is_set():
                try: raw,peer=self.sock.recvfrom(65535)
                except socket.timeout: continue
                q=dns.message.from_wire(raw)
                response=dns.message.make_response(q)
                response.answer.append(dns.rrset.from_text(q.question[0].name,60,"IN","A","192.0.2.1"))
                time.sleep(self.delay)
                self.sock.sendto(response.to_wire(),peer);self.count+=1
        except Exception as e:
            self.errors.append(e)
    def close(self):
        self.stop.set();self.thread.join(2);self.sock.close()
        assert not self.thread.is_alive()
        assert not self.errors,self.errors

csrf=request("/api/auth/login",{"password":os.environ["NDC_OWNER_PASSWORD"]})["csrf"]
since=time.time()-1
with contextlib.ExitStack() as stack:
    fast=Resolver(.001);stack.callback(fast.close)
    slow=Resolver(.075);stack.callback(slow.close)
    # Reverse order in second run to ensure target matching is not ordinal-based.
    ids=[]
    for i in range(3):
        endpoints=[fast.endpoint,slow.endpoint] if i!=1 else [slow.endpoint,fast.endpoint]
        job=request("/api/v1/runs",{"endpoints":endpoints,"count":10,"mode":"cold","family":"ipv4","parallel":1})["id"]
        ids.append(job)
        def completed():
            r=request("/api/v1/runs/"+job)
            if r["status"] in ("failed","cancelled","interrupted"): raise AssertionError(r)
            return r if r["status"]=="completed" else None
        run=wait_for(completed)
        assert len(run["results"])==2 and all(x["ok"]==10 for x in run["results"]),run
    assert fast.count==30 and slow.count==30,(fast.count,slow.count)
    wait_for(lambda:request("/api/v1/intelligence/status")["benchmark_pending"]==0)
    before=time.time()+1
    path="/api/v1/intelligence/dns/ranking?since="+str(since)+"&before="+str(before)
    for preset in ("balanced","reliability","speed"):
        ranking=request(path+"&preset="+preset)
        group=next(g for g in ranking["groups"] if {x["endpoint"] for x in g["targets"]}=={fast.endpoint,slow.endpoint})
        assert group["matched_runs"]==3,group
        assert group["targets"][0]["endpoint"]==fast.endpoint,group
        assert group["recommended_target_id"]==group["targets"][0]["target_id"],group
        for t in group["targets"]:
            assert t["attempted"]==t["successful"]==30,t
            assert t["score"] is not None and 0<=t["score"]<=100,t
            assert abs(sum(c["contribution"] for c in t["components"].values())-t["score"])<=.01,t
            record=request("/api/v1/intelligence/observations/"+t["example_evidence_id"])["record"]
            assert record["run_id"] in ids and record["protocol"]=="udp",record
        print(json.dumps({"preset":preset,"matched_runs":group["matched_runs"],
            "results":[{"endpoint":t["endpoint"],"score":t["score"],"p95":t["median_series_ms"]["p95"]} for t in group["targets"]]}))
    assert ranking["coverage"]["complete_window_verified"] is False
print("Real controlled UDP DNS ranking acceptance passed")
