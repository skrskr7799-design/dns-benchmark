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
