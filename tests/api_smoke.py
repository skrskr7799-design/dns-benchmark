import json, socket, threading, time, sqlite3, urllib.request
import dns.message, dns.rrset, dns.flags, dns.rdatatype
import os, http.cookiejar, urllib.error
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf=''
def expect_error(req,code):
    try:
        opener.open(req,timeout=10)
    except urllib.error.HTTPError as exc:
        assert exc.code==code,exc.code
    else:
        raise AssertionError('Expected HTTP '+str(code))
base='http://127.0.0.1:8080'
expect_error(urllib.request.Request(base+'/api/status'),401)
expect_error(urllib.request.Request(base+'/api/v1/intelligence/observations'),401)
expect_error(urllib.request.Request(base+'/api/v1/intelligence/events'),401)
expect_error(urllib.request.Request(base+'/api/v1/intelligence/observatory/monitors'),401)
expect_error(urllib.request.Request(base+'/api/v1/intelligence/time-machine/snapshots'),401)
login=urllib.request.Request(base+'/api/auth/login',data=json.dumps({'password':os.environ['NDC_OWNER_PASSWORD']}).encode(),headers={'Content-Type':'application/json','X-NDC-Request':'1'})
with opener.open(login,timeout=10) as response:
    csrf=json.load(response)['csrf']
expect_error(urllib.request.Request(base+'/api/run',data=b'{}',headers={'Content-Type':'application/json'}),403)
expect_error(urllib.request.Request(base+'/api/run',data=b'{}',headers={'Content-Type':'application/json','X-CSRF-Token':csrf,'Origin':'https://other.example'}),403)

def request(path, body=None):
    req = urllib.request.Request("http://127.0.0.1:8080" + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json","X-CSRF-Token":csrf})
    with opener.open(req, timeout=10) as r:
        return json.load(r)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.settimeout(10)
    def respond():
        for _ in range(2):
            data, peer = sock.recvfrom(65535)
            q = dns.message.from_wire(data)
            r = dns.message.make_response(q)
            r.answer.append(dns.rrset.from_text(q.question[0].name, 60, "IN", "A", "192.0.2.1"))
            sock.sendto(r.to_wire(), peer)
    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    assert request("/api/run", {"endpoints":[f"udp://127.0.0.1:{port}"],"count":2,"mode":"cold","family":"ipv4","parallel":1})["started"]
    for _ in range(100):
        s = request("/api/status")
        if not s["running"]:
            break
        time.sleep(.1)
    assert not s["running"], s
    assert s["done"] == 1 and s["results"][0]["ok"] == 2, s
    thread.join(2)
    assert not thread.is_alive()
assert request("/api/history")[0]["results"][0]["ok"] == 2
legacy = {"time": 1234567890, "results": [{"endpoint":"https://legacy.example/dns-query",
    "ok":10,"count":10,"mean":20,"p50":20,"p95":25,"p99":25,"jitter":2,"error":""}]}
with sqlite3.connect("/data/history.sqlite") as db:
    db.execute("INSERT INTO runs(payload) VALUES (?)", (json.dumps(legacy),))
assert request("/api/history")[0] == legacy
print("Local UDP and legacy history smoke passed")

assert request("/api/v1/capabilities")["durable_runs"]
job_id = request("/api/status")["run_id"]
assert request("/api/v1/runs/"+job_id)["status"] == "completed"
for _ in range(100):
    evidence=request("/api/v1/intelligence/observations?source=benchmark&limit=200")
    item=next((x for x in evidence["items"] if x["record"]["run_id"]==job_id),None)
    if item: break
    time.sleep(.1)
assert item is not None
assert request("/api/v1/intelligence/observations/"+item["id"])==item
assert request("/api/v1/intelligence/status")["sources"]["benchmark"]["rows"]>=1
expect_error(urllib.request.Request(base+"/api/v1/intelligence/observations?limit=201"),422)
expect_error(urllib.request.Request(base+"/api/v1/intelligence/events?outcome=success"),422)
expect_error(urllib.request.Request(base+"/api/v1/intelligence/events/"+"0"*64),404)
now=time.time()
cohort_path="/api/v1/intelligence/dns/cohorts?since="+str(now-3600)+"&before="+str(now+1)
expect_error(urllib.request.Request(base+cohort_path.replace("since=","invalid=")),422)
cohorts=request(cohort_path)
assert cohorts["methodology"]=="dns-cohorts-v1" and cohorts["eligible_records"]>=1
assert cohorts["coverage"]["complete_window_verified"] is False
assert cohorts["ranking"] is None
assert any(t["attempted"]>=2 for g in cohorts["cohorts"] for t in g["targets"])
ranking_path=cohort_path.replace("/cohorts","/ranking")
ranking=request(ranking_path)
assert ranking["methodology"]=="dns-intelligence-v1"
assert ranking["coverage"]["complete_window_verified"] is False
assert all(g["recommended_target_id"] is None for g in ranking["groups"])
expect_error(urllib.request.Request(base+ranking_path+"&preset=bad"),422)
assert isinstance(request("/api/v1/intelligence/observatory/monitors"),list)
expect_error(urllib.request.Request(base+"/api/v1/intelligence/observatory/monitors/"+"0"*32+"?since=1&before=2"),404)
print("Authenticated intelligence read API, benchmark ingestion, cohort analysis and conservative ranking passed")
with opener.open("http://127.0.0.1:8080/api/v1/runs/"+job_id+"/events",timeout=10) as response:
    assert b"event: snapshot" in response.read()
profile=request("/api/v1/profiles",{"name":"smoke","config":{"endpoints":["udp://127.0.0.1"],"count":2}})
assert request("/api/v1/profiles")[0]["id"]==profile["id"]
req=urllib.request.Request("http://127.0.0.1:8080/api/v1/profiles/"+profile["id"],method="DELETE",headers={"X-CSRF-Token":csrf})
with opener.open(req,timeout=10) as response:
    assert response.status==204
assert request("/api/v1/profiles")==[]
print("v1 API, SSE and profiles smoke passed")
page=request("/api/v1/runs/"+job_id+"/samples?offset=1&limit=1")
assert page["total"]==2 and len(page["items"])==1 and page["items"][0]["index"]==1
assert "samples" not in request("/api/v1/runs/"+job_id)["results"][0]
assert len(request("/api/v1/runs/"+job_id+"/export")["results"][0]["samples"])==2
with opener.open(base+"/api/v1/runs/"+job_id+"/export?format=csv",timeout=10) as response:
    assert len(response.read().decode().splitlines())==3
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1",0))
    port=sock.getsockname()[1]
    sock.settimeout(10)
    def respond_both():
        for _ in range(5):
            data,peer=sock.recvfrom(65535)
            q=dns.message.from_wire(data)
            r=dns.message.make_response(q)
            r.answer.append(dns.rrset.from_text(q.question[0].name,60,"IN","A","192.0.2.1"))
            sock.sendto(r.to_wire(),peer)
    thread=threading.Thread(target=respond_both,daemon=True)
    thread.start()
    both_id=request("/api/v1/runs",{"endpoints":[f"udp://127.0.0.1:{port}"],"count":2,"mode":"both"})["id"]
    for _ in range(100):
        both=request("/api/v1/runs/"+both_id)
        if both["status"]=="completed":
            break
        time.sleep(.1)
    assert both["status"]=="completed" and both["done"]==both["total"]==2,both
    assert [r["mode"] for r in both["results"]]==["cold","warm"]
    assert all(r["ok"]==2 for r in both["results"])
    assert request("/api/v1/runs/"+both_id+"/samples")["total"]==4
    thread.join(2)
    assert not thread.is_alive()
print("Both, samples pagination, CSV and JSON smoke passed")

# Real inspector wire query, including qtype, DO and CD.
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1",0))
    port=sock.getsockname()[1]
    sock.settimeout(10)
    def respond_inspect():
        data,peer=sock.recvfrom(65535)
        q=dns.message.from_wire(data)
        assert q.question[0].rdtype==dns.rdatatype.AAAA
        assert q.ednsflags&dns.flags.DO and q.flags&dns.flags.CD
        r=dns.message.make_response(q)
        r.flags|=dns.flags.AD
        r.answer.append(dns.rrset.from_text(q.question[0].name,42,"IN","AAAA","2001:db8::1"))
        sock.sendto(r.to_wire(),peer)
    thread=threading.Thread(target=respond_inspect,daemon=True)
    thread.start()
    result=request("/api/v1/dns/inspect",{"name":"example.com","qtype":"AAAA","dnssec":True,"checking_disabled":True,"endpoints":[f"udp://127.0.0.1:{port}"]})
    row=result["results"][0]
    assert row["outcome"]=="answer" and row["answer"][0]["ttl"]==42,row
    assert row["answer"][0]["values"]==["2001:db8::1"]
    assert row["dnssec"]["ad"] and not row["dnssec"]["independently_validated"]
    thread.join(2)
    assert not thread.is_alive()
print("DNS inspector wire smoke passed")

# Network endpoints: real loopback HTTP and a scoped rejection.
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class HeadFixture(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(204)
        self.end_headers()
    def log_message(self,*args):
        pass
http_fixture=ThreadingHTTPServer(("127.0.0.1",0),HeadFixture)
thread=threading.Thread(target=http_fixture.serve_forever,daemon=True)
thread.start()
try:
    report=request("/api/v1/network/connectivity",{"host":"127.0.0.1","port":http_fixture.server_port,"kind":"http","count":1})
    row=report["results"][0]["samples"][0]
    assert row["ok"] and row["http_status"]==204 and row["peer_ip"]=="127.0.0.1",row
finally:
    http_fixture.shutdown()
    http_fixture.server_close()
    thread.join(3)
blocked=request("/api/v1/network/tls",{"host":"169.254.169.254","port":443})
assert not blocked["results"][0]["ok"] and blocked["results"][0]["stage"]=="resolve"
assert request("/api/v1/capabilities")["connectivity"]
print("Connectivity and TLS API smoke passed")

routes=request("/api/v1/network/routes",{"host":"127.0.0.1","max_hops":2})
assert routes["method"]=="udp-error-queue"
route=routes["results"][0]
if route["available"]:
    assert route["reached"],route
    assert route["hops"][0]["samples"][0]["status"]=="destination"
blocked=request("/api/v1/network/routes",{"host":"169.254.169.254","max_hops":1})
assert not blocked["results"][0]["reached"] and not blocked["results"][0]["hops"]
print("Route analyzer API smoke passed")

monitor=request("/api/v1/monitoring/monitors",{"name":"smoke","host":"127.0.0.1","kind":"tcp","enabled":False})
assert monitor["enabled"] is False
assert request("/api/v1/monitoring")["monitors"][0]["id"]==monitor["id"]
assert request("/api/v1/monitoring/monitors/"+monitor["id"]+"/history")==[]
maintenance_path="/api/v1/monitoring/monitors/"+monitor["id"]+"/maintenance"
scheduled=request(maintenance_path,{"starts_at":time.time()+120,"ends_at":time.time()+240})
assert scheduled["state"]=="scheduled"
assert request(maintenance_path)[0]["id"]==scheduled["id"]
req=urllib.request.Request(base+maintenance_path+"/"+str(scheduled["id"]),method="DELETE",headers={"X-CSRF-Token":csrf})
with opener.open(req,timeout=10) as response: assert json.load(response)["state"]=="cancelled"
import uuid
snapshot_path="/api/v1/intelligence/time-machine/snapshots"
payload={"request_id":str(uuid.uuid4()),"label":"smoke before"}
expect_error(urllib.request.Request(base+snapshot_path,data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"}),403)
snap=request(snapshot_path,payload)
assert snap["snapshot"]["monitors"][0]["observation_status"]=="paused"
assert request(snapshot_path,payload)==snap
assert request(snapshot_path+"/"+snap["id"])==snap
req=urllib.request.Request(base+"/api/v1/monitoring/monitors/"+monitor["id"],method="DELETE",headers={"X-CSRF-Token":csrf})
with opener.open(req,timeout=10) as response:
    assert response.status==204
assert request("/api/v1/monitoring")["monitors"]==[]
after=request(snapshot_path,{"request_id":str(uuid.uuid4()),"label":"smoke after"})
diff=request("/api/v1/intelligence/time-machine/compare?older="+snap["id"]+"&newer="+after["id"])
assert diff["changes"][0]["kind"]=="monitor_removed"
for snapshot in (snap,after):
    req=urllib.request.Request(base+snapshot_path+"/"+snapshot["id"],method="DELETE",headers={"X-CSRF-Token":csrf})
    with opener.open(req,timeout=10) as response: assert response.status==204
# Exercise the actual scheduler and real TCP/HTTP fixture, not only CRUD.
http_fixture=ThreadingHTTPServer(("127.0.0.1",0),HeadFixture)
thread=threading.Thread(target=http_fixture.serve_forever,daemon=True)
thread.start()
try:
    active=request("/api/v1/monitoring/monitors",{"name":"active smoke","host":"127.0.0.1","port":http_fixture.server_port,"kind":"http","interval_seconds":60})
    mid=active["id"]
    for _ in range(100):
        observations=request("/api/v1/monitoring/monitors/"+mid+"/history")
        if observations:
            break
        time.sleep(.1)
    assert len(observations)==1 and observations[0]["outcome"]=="healthy",observations
    req=urllib.request.Request(base+"/api/v1/monitoring/monitors/"+mid,method="PATCH",data=b'{"enabled":false}',headers={"Content-Type":"application/json","X-CSRF-Token":csrf})
    with opener.open(req,timeout=10) as response:
        assert json.load(response)["enabled"] is False
    req=urllib.request.Request(base+"/api/v1/monitoring/monitors/"+mid,method="DELETE",headers={"X-CSRF-Token":csrf})
    with opener.open(req,timeout=10) as response:
        assert response.status==204
finally:
    http_fixture.shutdown()
    http_fixture.server_close()
    thread.join(3)
print("Monitoring API and live scheduler smoke passed")

# Exercise a real outbound agent against the controller and local DNS fixture.
import tempfile
from pathlib import Path
from backend.ndc.agent_client import Agent
from unittest.mock import patch
expect_error(urllib.request.Request(base+"/api/v1/agents/machine/poll",data=b'{}',headers={"Content-Type":"application/json"}),403)
invite=request("/api/v1/agents/invite",{"name":"CI agent","location":"loopback"})
with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{"NDC_AGENT_TEST_HTTP":"1"}):
    root=Path(tmp)
    (root/"enrollment-token").write_text(invite["token"])
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1",0))
        sock.settimeout(10)
        endpoint=f"udp://127.0.0.1:{sock.getsockname()[1]}"
        agent=Agent(root,base,[endpoint])
        try:
            agent.enroll()
            assert not (root/"enrollment-token").exists()
            task=request("/api/v1/agents/"+invite["id"]+"/tasks",{"endpoints":[endpoint],"count":1,"mode":"cold"})["id"]
            def respond_agent():
                data,peer=sock.recvfrom(65535)
                q=dns.message.from_wire(data)
                r=dns.message.make_response(q)
                r.answer.append(dns.rrset.from_text(q.question[0].name,60,"IN","A","192.0.2.1"))
                sock.sendto(r.to_wire(),peer)
            thread=threading.Thread(target=respond_agent,daemon=True)
            thread.start()
            agent.step()
            thread.join(2)
            assert not thread.is_alive()
            detail=request("/api/v1/agents/tasks/"+task)
            assert detail["state"]=="completed",detail
            assert detail["payload"]["results"][0]["ok"]==1
            assert not agent.spool.exists()
            assert request("/api/v1/agents")["agents"][0]["online"]
            request("/api/v1/agents/"+invite["id"]+"/revoke",{})
            assert agent.post("poll",{"version":"1","engine":"python-dns02"}).status_code==401
        finally:
            agent.client.close()
print("Outbound agent and real DNS smoke passed")

# Same profile on two independent agent identities, including an offline interval.
with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{"NDC_AGENT_TEST_HTTP":"1"}):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1",0))
        sock.settimeout(15)
        endpoint=f"udp://127.0.0.1:{sock.getsockname()[1]}"
        agents=[]
        ids=[]
        try:
            for i in range(2):
                invitation=request("/api/v1/agents/invite",{"name":f"batch fixture {i}","location":f"site {i}"})
                root=Path(tmp)/str(i)
                root.mkdir()
                (root/"enrollment-token").write_text(invitation["token"])
                a=Agent(root,base,[endpoint])
                agents.append(a)
                a.enroll()
                ids.append(invitation["id"])
            body={"request_id":"b"*32,"agent_ids":ids,"config":{"endpoints":[endpoint],"mode":"both","count":1}}
            batch=request("/api/v1/agents/batches",body)
            assert not batch["duplicate"]
            assert request("/api/v1/agents/batches",body)["duplicate"]
            def respond_batch():
                for _ in range(6):
                    data,peer=sock.recvfrom(65535)
                    q=dns.message.from_wire(data)
                    r=dns.message.make_response(q)
                    r.answer.append(dns.rrset.from_text(q.question[0].name,60,"IN","A","192.0.2.1"))
                    sock.sendto(r.to_wire(),peer)
            thread=threading.Thread(target=respond_batch,daemon=True)
            thread.start()
            agents[0].step()
            detail=request("/api/v1/agents/batches/"+batch["id"])
            assert {m["state"] for m in detail["members"]}=={"completed","queued"}
            agents[1].client.close()
            agents[1]=Agent(Path(tmp)/"1",base,[endpoint])
            agents[1].enroll()
            agents[1].step()
            detail=request("/api/v1/agents/batches/"+batch["id"])
            assert len(detail["members"])==2
            for member in detail["members"]:
                assert member["state"]=="completed",member
                assert [r["mode"] for r in member["results"]]==["cold","warm"]
                assert all(r["ok"]==1 and r["p95"] is not None for r in member["results"])
            thread.join(2)
            assert not thread.is_alive()
            for id in ids:
                request("/api/v1/agents/"+id+"/revoke",{})
        finally:
            for a in agents:
                a.client.close()
print("Two-agent batch and offline resume smoke passed")

# Real diagnostic HTTP status evidence, plus scope denial.
class DiagnosticFixture(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(503)
        self.end_headers()
    def log_message(self,*args):
        pass
fixture=ThreadingHTTPServer(("127.0.0.1",0),DiagnosticFixture)
thread=threading.Thread(target=fixture.serve_forever,daemon=True)
thread.start()
try:
    diagnostic=request("/api/v1/diagnostics",{"host":"127.0.0.1","kind":"http","port":fixture.server_port})
    row=diagnostic["results"][0]
    assert row["probe"]["ok"] and row["probe"]["http_status"]==503,row
    assert any(f["code"]=="http_server_error" and f["confidence"]=="observed" for f in row["findings"])
    assert row["dns_skipped"] and not row["dns"]
finally:
    fixture.shutdown()
    fixture.server_close()
    thread.join(3)
blocked=request("/api/v1/diagnostics",{"host":"169.254.169.254","endpoints":["udp://1.1.1.1"]})
assert blocked["results"][0]["findings"][0]["code"]=="scope_denied"
assert not blocked["results"][0]["dns"]
print("Diagnostic evidence API smoke passed")

# Integrations disabled by default; no outbound network activity.
assert request("/api/v1/integrations")=={"adguard_configured":False,"throughput_configured":False}
for path in ("adguard","throughput"):
    expect_error(urllib.request.Request(base+"/api/v1/integrations/"+path,data=b'{}',headers={"Content-Type":"application/json","X-CSRF-Token":csrf}),409)
print("Opt-in integration API smoke passed")

# Explicit deletion of terminal jobs and body budget.
id=request("/api/v1/runs",{"endpoints":["udp://127.0.0.1:9"],"count":1})["id"]
request("/api/v1/runs/"+id+"/cancel",{})
for _ in range(100):
    state=request("/api/v1/runs/"+id)["status"]
    if state in ("completed","cancelled","failed","interrupted"):
        break
    time.sleep(.1)
req=urllib.request.Request(base+"/api/v1/runs/"+id,method="DELETE",headers={"X-CSRF-Token":csrf})
with opener.open(req,timeout=10) as response:
    assert response.status==204
expect_error(urllib.request.Request(base+"/api/v1/runs/"+id),404)
expect_error(urllib.request.Request(base+"/api/v1/runs",data=b"x"*131073,headers={"Content-Type":"application/json","X-CSRF-Token":csrf}),413)
print("Release deletion and request size smoke passed")

logout=urllib.request.Request(base+"/api/auth/logout",data=b"",headers={"X-CSRF-Token":csrf})
with opener.open(logout,timeout=10) as response:
    assert not json.load(response)["authenticated"]
expect_error(urllib.request.Request(base+"/api/status"),401)
for _ in range(9):
    bad=urllib.request.Request(base+"/api/auth/login",data=b'{"password":"wrong"}',headers={"Content-Type":"application/json","X-NDC-Request":"1"})
    # Browser tests have also logged in; global budget may already be exhausted.
    try:
        opener.open(bad,timeout=10)
    except urllib.error.HTTPError as exc:
        assert exc.code in (401,429)
    else:
        raise AssertionError("wrong password accepted")
expect_error(bad,429)
print("Authentication, CSRF, logout and rate limit smoke passed")
