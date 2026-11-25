import time, statistics, math, socket, ssl, httpx
from urllib.parse import urlsplit
from contextlib import ExitStack
from collections import Counter
import dns.message, dns.query, dns.rcode, dns.quic
from ..scope import validate_ip
from .quic_transport import QuicSession
import os

domains = ["example.com", "example.org", "iana.org", "wikipedia.org", "debian.org", "python.org", "kernel.org", "mozilla.org"]
def resolve(u, family):
    af = {'auto': socket.AF_UNSPEC, 'ipv4': socket.AF_INET, 'ipv6': socket.AF_INET6}[family]
    port = u.port or (443 if u.scheme in ("https","h3") else 853 if u.scheme in ("tls","quic") else 53)
    addresses = socket.getaddrinfo(u.hostname, port, af, socket.SOCK_STREAM)
    # Reject a mixed permitted/forbidden DNS answer rather than silently bypassing scope.
    checked=[validate_ip(a[4][0]) for a in addresses]
    return checked[0]

def query(endpoint, domain, ip, stack, resources):
    u = urlsplit(endpoint)
    ip = validate_ip(ip)
    q = dns.message.make_query(domain, "A")
    if u.scheme in ("h3","quic"):
        if "session" not in resources:
            resources["session"]=stack.enter_context(QuicSession(endpoint,ip))
        session=resources["session"]
        q.id=0
        reused=session.requests>0
        response=dns.message.from_wire(session.exchange(q.to_wire()))
        if not q.is_response(response):
            raise ValueError("Mismatched DNS response")
        resources["observation"]={"protocol":session.protocol.alpn,"peer_ip":session.ip,
            "reused":reused,"handshake_ms":None if reused else session.handshake_ms}
        return response
    if u.scheme == "https":
        if "http" not in resources:
            def observe(response):
                if response.http_version!="HTTP/2":
                    raise ValueError("Expected HTTP/2")
                stream=response.extensions.get("network_stream")
                peer=stream.get_extra_info("server_addr") if stream else None
                if peer and validate_ip(peer[0])!=ip:
                    raise ValueError("Unexpected peer IP")
                previous=resources.get("last_stream")
                resources["observation"]={"protocol":"h2","peer_ip":peer[0] if peer else None,
                    "reused":(previous is stream) if stream is not None else None,"handshake_ms":None}
                resources["last_stream"]=stream
            transport = dns.query._HTTPTransport(bootstrap_address=ip,http1=False,http2=True,verify=os.getenv("NDC_CA_FILE") or True,trust_env=False)
            resources["http"] = stack.enter_context(httpx.Client(transport=transport,http1=False,http2=True,trust_env=False,follow_redirects=False,event_hooks={"response":[observe]}))
        return dns.query.https(q, endpoint, timeout=5, port=u.port or 443, bootstrap_address=ip, session=resources["http"], verify=True, http_version=dns.query.HTTPVersion.H2)
    if u.scheme == "tls":
        reused="tls" in resources
        connect_ms=handshake_ms=None
        if not reused:
            t=time.monotonic()
            raw = stack.enter_context(socket.create_connection((ip,u.port or 853),timeout=5))
            connect_ms=(time.monotonic()-t)*1000
            t=time.monotonic()
            resources["tls"] = stack.enter_context(ssl.create_default_context(cafile=os.getenv("NDC_CA_FILE")).wrap_socket(raw,server_hostname=u.hostname))
            handshake_ms=(time.monotonic()-t)*1000
            resources["tls"].setblocking(False)
        resources["observation"]={"protocol":"dot","peer_ip":resources["tls"].getpeername()[0],"reused":reused,"handshake_ms":handshake_ms,"connect_ms":connect_ms}
        return dns.query.tls(q, ip, port=u.port or 853, timeout=5, sock=resources["tls"])
    if u.scheme=="tcp":
        reused="tcp" in resources
        connect_ms=None
        if not reused:
            t=time.monotonic()
            resources["tcp"]=stack.enter_context(socket.create_connection((ip,u.port or 53),timeout=5))
            connect_ms=(time.monotonic()-t)*1000
            resources["tcp"].setblocking(False)
        resources["observation"]={"protocol":"tcp","peer_ip":resources["tcp"].getpeername()[0],"reused":reused,"handshake_ms":None,"connect_ms":connect_ms}
        return dns.query.tcp(q,ip,port=u.port or 53,timeout=5,sock=resources["tcp"])
    resources["observation"]={"protocol":"udp","peer_ip":None,"reused":None,"handshake_ms":None}
    return dns.query.udp(q, ip, port=u.port or 53, timeout=5)

def bootstrap(endpoint,family):
    start=time.monotonic()
    try:
        return resolve(urlsplit(endpoint),family),round((time.monotonic()-start)*1000,3),None
    except Exception as exc:
        return None,round((time.monotonic()-start)*1000,3),describe(exc)

def measure(endpoint,count,mode,family,cancelled,pinned=None):
    if cancelled.is_set():
        return None
    ip,bootstrap_ms,bootstrap_error=pinned if pinned is not None else bootstrap(endpoint,family)
    samples=[]
    warmup=None
    def one(index,domain,stack,resources):
        start=time.monotonic()
        resources.pop("observation",None)
        error=None
        rcode=None
        try:
            response=query(endpoint,domain,ip,stack,resources)
            elapsed=(time.monotonic()-start)*1000
            rcode=dns.rcode.to_text(response.rcode())
            if response.rcode()!=dns.rcode.NOERROR or not response.answer:
                error="DNS response: "+rcode+(" (empty answer)" if not response.answer else "")
        except Exception as exc:
            elapsed=(time.monotonic()-start)*1000
            error=describe(exc)
        o=resources.get("observation",{})
        def ms(key):
            value=o.get(key)
            return round(value,3) if value is not None else None
        return {"index":index,"domain":domain,"qtype":"A","ok":error is None,
                "duration_ms":round(elapsed,3),"error":error,"rcode":rcode,
                "protocol":o.get("protocol"),"peer_ip":o.get("peer_ip"),"reused":o.get("reused"),
                "connect_ms":ms("connect_ms"),"handshake_ms":ms("handshake_ms")}

    if ip is None:
        for i in range(count):
            if cancelled.is_set():
                break
            samples.append({"index":i,"domain":domains[i%len(domains)],"qtype":"A","ok":False,
                            "duration_ms":None,"error":bootstrap_error,"rcode":None,"protocol":None,
                            "peer_ip":None,"reused":None,"connect_ms":None,"handshake_ms":None})
    else:
        with ExitStack() as warm:
            resources={}
            if mode=="warm" and not cancelled.is_set():
                warmup=one(-1,"example.net",warm,resources)
                if not warmup["ok"]:
                    warm.close()
                    resources.clear()
            for i in range(count):
                if cancelled.is_set():
                    break
                domain=domains[i%len(domains)]
                if mode=="warm":
                    sample=one(i,domain,warm,resources)
                    if not sample["ok"]:
                        warm.close()
                        resources.clear()
                else:
                    with ExitStack() as cold:
                        sample=one(i,domain,cold,{})
                samples.append(sample)
    if not samples and warmup is None:
        return None
    successes=[s for s in samples if s["ok"]]
    values=sorted(s["duration_ms"] for s in successes)
    errors=[s["error"] for s in samples if not s["ok"]]
    def pct(p):
        return round(values[max(0,math.ceil(len(values)*p)-1)],2) if values else None
    return {"endpoint":endpoint,"ip":ip,"mode":mode,"family":family,"ok":len(values),
            "count":len(samples),"requested_count":count,"mean":round(statistics.mean(values),2) if values else None,
            "p50":pct(.5),"p95":pct(.95),"p99":pct(.99),
            "jitter":round(statistics.pstdev(values),2) if values else None,
            "error":errors[-1] if errors else "","errors":dict(Counter(errors)),
            "warmup_error":warmup["error"] if warmup else None,"warmup":warmup,
            "bootstrap_ms":bootstrap_ms,"bootstrap_error":bootstrap_error,"engine":"python-dns02",
            "protocols":sorted({s["protocol"] for s in successes if s["protocol"]}),
            "peer_ips":sorted({s["peer_ip"] for s in successes if s["peer_ip"]}),
            "reuse":{"yes":sum(s["reused"] is True for s in successes),
                     "no":sum(s["reused"] is False for s in successes),
                     "unknown":sum(s["reused"] is None for s in successes)},
            "samples":samples}

def measure_both(endpoint,count,family,cancelled):
    if cancelled.is_set():
        return
    pinned=bootstrap(endpoint,family)
    for mode in ("cold","warm"):
        if cancelled.is_set():
            break
        result=measure(endpoint,count,mode,family,cancelled,pinned=pinned)
        if result is not None:
            yield result

def describe(exc):
    return (type(exc).__name__ + ': ' + str(exc))[:250]
