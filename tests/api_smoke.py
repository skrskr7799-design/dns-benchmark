import json, socket, threading, time, sqlite3, urllib.request
import dns.message, dns.rrset

def request(path, body=None):
    req = urllib.request.Request("http://127.0.0.1:8080" + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
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
