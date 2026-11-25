import os, time, statistics, threading, sqlite3, json, math, ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor
import dns.message, dns.query, dns.rcode, dns.quic
import socket, ssl, httpx
from contextlib import ExitStack
from collections import Counter
from typing import Literal
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

app = FastAPI()
db = Path(os.getenv("DATA_DIR", "/data")) / "history.sqlite"
db.parent.mkdir(parents=True, exist_ok=True)
with sqlite3.connect(db) as c:
    c.execute("CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, payload TEXT)")
lock = threading.Lock()
state = {"running": False, "results": [], "done": 0, "total": 0}
domains = ["example.com", "example.org", "iana.org", "wikipedia.org", "debian.org", "python.org", "kernel.org", "mozilla.org"]
class Run(BaseModel):
    endpoints: list[str] = Field(min_length=1, max_length=40)
    count: int = Field(default=10, ge=1, le=100)
    mode: Literal['cold','warm'] = 'cold'
    family: Literal['auto','ipv4','ipv6'] = 'ipv4'
    parallel: int = Field(default=1, ge=1, le=2)

def resolve(u, family):
    af = {'auto': socket.AF_UNSPEC, 'ipv4': socket.AF_INET, 'ipv6': socket.AF_INET6}[family]
    addresses = socket.getaddrinfo(u.hostname, u.port or 443, af, socket.SOCK_STREAM)
    return addresses[0][4][0]

def query(endpoint, domain, ip, stack, resources):
    u = urlsplit(endpoint)
    q = dns.message.make_query(domain, "A")
    if u.scheme in ("https", "h3"):
        if u.scheme == "https" and "http" not in resources:
            resources["http"] = stack.enter_context(httpx.Client(http2=True, trust_env=False))
        if u.scheme == "h3" and "quic" not in resources:
            resources["quic"] = stack.enter_context(dns.quic.SyncQuicManager())
        return dns.query.https(q, endpoint.replace("h3://", "https://", 1), timeout=5, bootstrap_address=ip, session=resources.get("http") or resources.get("quic"), http_version=dns.query.HTTPVersion.H3 if u.scheme == "h3" else dns.query.HTTPVersion.H2)
    if u.scheme == "tls":
        if "tls" not in resources:
            raw = stack.enter_context(socket.create_connection((ip,u.port or 853),timeout=5))
            resources["tls"] = stack.enter_context(ssl.create_default_context().wrap_socket(raw,server_hostname=u.hostname))
        return dns.query.tls(q, ip, port=u.port or 853, timeout=5, sock=resources["tls"])
    if u.scheme == "quic":
        if "quic" not in resources:
            resources["quic"] = stack.enter_context(dns.quic.SyncQuicManager())
        return dns.query.quic(q, ip, port=u.port or 853, timeout=5, server_hostname=u.hostname, connection=resources["quic"].connect(ip,u.port or 853,server_hostname=u.hostname))
    return dns.query.udp(q, ip, port=u.port or 53, timeout=5)

def measure(endpoint, count, mode, family):
    values, errors = [], []
    ip = None
    with ExitStack() as warm:
        resources = {}
        try:
            ip = resolve(urlsplit(endpoint), family)
        except Exception as e:
            errors = [str(e)[:200]] * count
        if ip:
            for i in range(count + (mode == "warm")):
                start = time.monotonic()
                try:
                    with ExitStack() as cold:
                        r = query(endpoint, domains[i % len(domains)], ip, warm if mode == "warm" else cold, resources if mode == "warm" else {})
                    if r.rcode() != dns.rcode.NOERROR or not r.answer:
                        raise ValueError("Unexpected DNS response: " + dns.rcode.to_text(r.rcode()))
                    if mode == "cold" or i > 0:
                        values.append((time.monotonic()-start)*1000)
                except Exception as e:
                    if mode == "cold" or i > 0:
                        errors.append(str(e)[:200])
                    if mode == "warm":
                        warm.close()
                        resources.clear()
    v = sorted(values)
    pct = lambda p: round(v[max(0, math.ceil(len(v)*p)-1)],2) if v else None
    return {"endpoint":endpoint,"ip":ip,"mode":mode,"family":family,"ok":len(v),"count":count,"mean":round(statistics.mean(v),2) if v else None,"p50":pct(.5),"p95":pct(.95),"p99":pct(.99),"jitter":round(statistics.pstdev(v),2) if v else None,"error":errors[-1] if errors else "", "errors":dict(Counter(errors))}

def worker(run):
    try:
        with ThreadPoolExecutor(max_workers=run.parallel) as pool:
            from concurrent.futures import as_completed
            futures = [pool.submit(measure,e,run.count,run.mode,run.family) for e in run.endpoints]
            for f in as_completed(futures):
                result = f.result()
                with lock:
                    state["results"].append(result)
                    state["done"] += 1
        with sqlite3.connect(db) as c:
            c.execute("INSERT INTO runs(payload) VALUES (?)",(json.dumps({"time":time.time(),"results":state["results"]}),))
    except Exception as e:
        with lock: state["error"] = str(e)
    finally:
        with lock: state["running"] = False

web_dist = Path(__file__).with_name("web-dist")
if (web_dist / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=web_dist / "assets"), name="assets")

@app.get("/", response_class=HTMLResponse)
def home():
    if (web_dist / "index.html").is_file():
        return FileResponse(web_dist / "index.html")
    return Path(__file__).with_name("index.html").read_text()
@app.get("/health")
def health(): return {"ok":True}
@app.get("/api/defaults")
def defaults(): return Path(__file__).with_name("resolvers.txt").read_text().splitlines()
@app.get("/api/status")
def status():
    with lock: return json.loads(json.dumps(state))
@app.get("/api/history")
def history():
    with sqlite3.connect(db) as c:
        return [json.loads(row[0]) for row in c.execute("SELECT payload FROM runs ORDER BY id DESC LIMIT 30")]
@app.post("/api/run")
def run(body:Run):
    for e in body.endpoints:
        try:
            u=urlsplit(e)
            if u.scheme not in ("https","h3","tls","quic","udp") or not u.hostname or u.username or u.password: raise ValueError()
            if u.scheme=="udp": ipaddress.ip_address(u.hostname)
            _=u.port
        except ValueError: raise HTTPException(400,"Invalid endpoint")
    with lock:
        if state["running"]: raise HTTPException(409,"Already running")
        state.clear()
        state.update(running=True,results=[],done=0,total=len(body.endpoints))
    threading.Thread(target=worker,args=(body,),daemon=True).start()
    return {"started":True}
