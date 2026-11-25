import time, statistics, math, socket, ssl, httpx
from urllib.parse import urlsplit
from contextlib import ExitStack
from collections import Counter
import dns.message, dns.query, dns.rcode, dns.quic
from ..scope import validate_ip

domains = ["example.com", "example.org", "iana.org", "wikipedia.org", "debian.org", "python.org", "kernel.org", "mozilla.org"]
def resolve(u, family):
    af = {'auto': socket.AF_UNSPEC, 'ipv4': socket.AF_INET, 'ipv6': socket.AF_INET6}[family]
    addresses = socket.getaddrinfo(u.hostname, u.port or 443, af, socket.SOCK_STREAM)
    # Reject a mixed permitted/forbidden DNS answer rather than silently bypassing scope.
    checked=[validate_ip(a[4][0]) for a in addresses]
    return checked[0]

def query(endpoint, domain, ip, stack, resources):
    u = urlsplit(endpoint)
    ip = validate_ip(ip)
    q = dns.message.make_query(domain, "A")
    if u.scheme in ("https", "h3"):
        if u.scheme == "https" and "http" not in resources:
            transport = dns.query._HTTPTransport(bootstrap_address=ip,http1=False,http2=True,verify=True,trust_env=False)
            resources["http"] = stack.enter_context(httpx.Client(transport=transport,http1=False,http2=True,trust_env=False,follow_redirects=False))
        return dns.query.https(q, endpoint.replace("h3://", "https://", 1), timeout=5, port=u.port or 443, bootstrap_address=ip, session=resources.get("http"), verify=True, http_version=dns.query.HTTPVersion.H3 if u.scheme == "h3" else dns.query.HTTPVersion.H2)
    if u.scheme == "tls":
        if "tls" not in resources:
            raw = stack.enter_context(socket.create_connection((ip,u.port or 853),timeout=5))
            resources["tls"] = stack.enter_context(ssl.create_default_context().wrap_socket(raw,server_hostname=u.hostname))
            resources["tls"].setblocking(False)
        return dns.query.tls(q, ip, port=u.port or 853, timeout=5, sock=resources["tls"])
    if u.scheme == "quic":
        if "quic" not in resources:
            resources["quic"] = stack.enter_context(dns.quic.SyncQuicManager(verify_mode=True,server_name=u.hostname))
        return dns.query.quic(q, ip, port=u.port or 853, timeout=5, server_hostname=u.hostname, verify=True, connection=resources["quic"].connect(ip,u.port or 853))
    return dns.query.udp(q, ip, port=u.port or 53, timeout=5)

def measure(endpoint, count, mode, family, cancelled):
    values, errors = [], []
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
                        r = query(endpoint, domains[i % len(domains)], ip, warm if mode == "warm" else cold, resources if mode == "warm" else {})
                    if r.rcode() != dns.rcode.NOERROR or not r.answer:
                        raise ValueError("Unexpected DNS response: " + dns.rcode.to_text(r.rcode()))
                    if mode == "cold" or i > 0:
                        values.append((time.monotonic()-start)*1000)
                except Exception as e:
                    if mode == "cold" or i > 0:
                        errors.append(describe(e))
                    if mode == "warm":
                        warm.close()
                        resources.clear()
    attempted = len(values) + len(errors)
    if not attempted:
        return None
    v = sorted(values)
    pct = lambda p: round(v[max(0, math.ceil(len(v)*p)-1)],2) if v else None
    return {"endpoint":endpoint,"ip":ip,"mode":mode,"family":family,"ok":len(v),"count":attempted,"requested_count":count,"mean":round(statistics.mean(v),2) if v else None,"p50":pct(.5),"p95":pct(.95),"p99":pct(.99),"jitter":round(statistics.pstdev(v),2) if v else None,"error":errors[-1] if errors else "", "errors":dict(Counter(errors))}


def describe(exc):
    return (type(exc).__name__ + ': ' + str(exc))[:250]
