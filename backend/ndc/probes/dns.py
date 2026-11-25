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
        if not reused:
            raw = stack.enter_context(socket.create_connection((ip,u.port or 853),timeout=5))
            resources["tls"] = stack.enter_context(ssl.create_default_context(cafile=os.getenv("NDC_CA_FILE")).wrap_socket(raw,server_hostname=u.hostname))
            resources["tls"].setblocking(False)
        resources["observation"]={"protocol":"dot","peer_ip":resources["tls"].getpeername()[0],"reused":reused,"handshake_ms":None}
        return dns.query.tls(q, ip, port=u.port or 853, timeout=5, sock=resources["tls"])
    if u.scheme=="tcp":
        reused="tcp" in resources
        if not reused:
            resources["tcp"]=stack.enter_context(socket.create_connection((ip,u.port or 53),timeout=5))
            resources["tcp"].setblocking(False)
        resources["observation"]={"protocol":"tcp","peer_ip":resources["tcp"].getpeername()[0],"reused":reused,"handshake_ms":None}
        return dns.query.tcp(q,ip,port=u.port or 53,timeout=5,sock=resources["tcp"])
    resources["observation"]={"protocol":"udp","peer_ip":None,"reused":None,"handshake_ms":None}
    return dns.query.udp(q, ip, port=u.port or 53, timeout=5)

def measure(endpoint, count, mode, family, cancelled):
    values, errors, observations = [], [], []
    warmup_error = None
    ip = None
    if cancelled.is_set():
        return None
    with ExitStack() as warm:
        resources = {}
        try:
            ip = resolve(urlsplit(endpoint), family)
        except Exception as e:
            errors = [describe(e)] * count
        if ip:
            for i in range(count + (mode == "warm")):
                if cancelled.is_set():
                    break
                start = time.monotonic()
                try:
                    with ExitStack() as cold:
                        active = resources if mode == "warm" else {}
                        active.pop('observation',None)
                        r = query(endpoint, domains[i % len(domains)], ip, warm if mode == "warm" else cold, active)
                        elapsed=(time.monotonic()-start)*1000
                        observation=active.get('observation',{})
                    if r.rcode() != dns.rcode.NOERROR or not r.answer:
                        raise ValueError("Unexpected DNS response: " + dns.rcode.to_text(r.rcode()))
                    if mode == "cold" or i > 0:
                        values.append(elapsed)
                        observations.append(observation)
                except Exception as e:
                    if mode == "cold" or i > 0:
                        errors.append(describe(e))
                    else:
                        warmup_error=describe(e)
                    if mode == "warm":
                        warm.close()
                        resources.clear()
    attempted = len(values) + len(errors)
    if not attempted:
        return None
    v = sorted(values)
    pct = lambda p: round(v[max(0, math.ceil(len(v)*p)-1)],2) if v else None
    return {"endpoint":endpoint,"ip":ip,"mode":mode,"family":family,"ok":len(v),"count":attempted,"requested_count":count,"mean":round(statistics.mean(v),2) if v else None,"p50":pct(.5),"p95":pct(.95),"p99":pct(.99),"jitter":round(statistics.pstdev(v),2) if v else None,"error":errors[-1] if errors else "", "errors":dict(Counter(errors)),"warmup_error":warmup_error,"engine":"python-dns01","protocols":sorted({o["protocol"] for o in observations if o.get("protocol")}),"peer_ips":sorted({o["peer_ip"] for o in observations if o.get("peer_ip")}),"reuse":{"yes":sum(o.get("reused") is True for o in observations),"no":sum(o.get("reused") is False for o in observations),"unknown":sum(o.get("reused") is None for o in observations)}}


def describe(exc):
    return (type(exc).__name__ + ': ' + str(exc))[:250]
