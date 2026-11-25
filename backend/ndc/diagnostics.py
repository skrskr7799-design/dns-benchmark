"""Evidence-based local diagnostics. No automatic remediation or speculative attribution."""
import ipaddress
import time
from .models import Inspect
from .probes.connectivity import probe_once, families
from .probes.inspector import inspect

RULE_VERSION="1"

def finding(code,layer,confidence,evidence,action):
    return {"code":code,"layer":layer,"confidence":confidence,"evidence":evidence,"action":action}

def classify(probe, dns_rows, thresholds):
    stage=probe["stage"]
    err=probe.get("error") or ""
    out=[]
    def add(code,layer,confidence,fields,action):
        out.append(finding(code,layer,confidence,fields,action))
    if not probe["ok"]:
        fields={"stage":stage,"error":err,"ip":probe.get("ip")}
        if "ScopeError:" in err:
            add("scope_denied","scope","observed",fields,"Check the authorized target scope; do not bypass restrictions.")
        elif stage=="resolve":
            answers=[r for r in dns_rows if r["outcome"]=="answer"]
            add("resolution_failed","dns","observed",fields,"Check the system resolver and requested address family.")
            if answers:
                add("resolver_disagreement","dns","possible",{"answering_resolvers":[r["endpoint"] for r in answers]},"Compare system DNS configuration and explicit resolver answers; no proof of poisoning or filtering.")
        elif stage=="tcp":
            add("tcp_failed","tcp","observed",fields,"Check service listener, firewall and route; the cause is not determined by this probe.")
        elif stage=="tls":
            code="certificate_rejected" if probe.get("verified") is False else "tls_failed"
            add(code,"tls","observed",fields,"Inspect certificate trust, hostname, server TLS configuration and system clock.")
        elif stage=="http":
            add("http_exchange_failed","http","observed",fields,"Check the HTTP service or reverse proxy and its logs.")
        else:
            add("probe_failed","unknown","observed",fields,"Inspect raw probe evidence.")
    elif probe.get("http_status") is not None:
        status=probe["http_status"]
        if status>=500:
            add("http_server_error","http","observed",{"http_status":status},"Inspect origin and reverse proxy logs; a response does not identify the failing component.")
        elif status>=400:
            add("http_client_response","http","observed",{"http_status":status},"Check the URL, authorization and whether HEAD is supported.")
        elif status>=300:
            add("http_redirect","http","observed",{"http_status":status},"Inspect the intended redirect separately; it was not followed.")
    for field,limit in thresholds.items():
        value=probe.get(field)
        # Only timings of completed stages are reported by the probe.
        if value is not None and value>limit and field in ("dns_ms","connect_ms","handshake_ms","ttfb_ms"):
            add("slow_"+field,{"dns_ms":"dns","connect_ms":"tcp","handshake_ms":"tls","ttfb_ms":"http"}[field],"observed",{"field":field,"value_ms":value,"threshold_ms":limit},"Repeat measurements and compare a known-good baseline; threshold exceedance does not locate the root cause.")
    if probe.get("certificate") and probe["certificate"]["days_remaining"]<14:
        add("certificate_expiring","tls","observed",{"days_remaining":probe["certificate"]["days_remaining"]},"Review certificate renewal.")
    if not out:
        add("no_issue_observed","none","observed",{"stage":stage,"http_status":probe.get("http_status")},"No issue observed in this single test; intermittent problems remain possible.")
    return out

def diagnose(config):
    start=time.time()
    results=[]
    for family in families(config.family):
        probe=probe_once(config.host,config.port,family,config.kind,config.path)
        dns_rows=[]
        agreement=None
        dns_skipped=None
        try:
            ipaddress.ip_address(config.host)
            literal=True
        except ValueError:
            literal=False
        if literal:
            dns_skipped="IP literal; explicit DNS comparison not applicable"
        elif not config.endpoints:
            dns_skipped="No explicit resolver selected"
        elif "ScopeError:" in (probe.get("error") or ""):
            dns_skipped="Destination scope denied"
        else:
            report=inspect(Inspect(name=config.host,qtype="A" if family=="ipv4" else "AAAA",endpoints=config.endpoints,family=config.resolver_family,dnssec=True))
            dns_rows=report["results"]
            agreement=report["agreement"]
        findings=classify(probe,dns_rows,config.thresholds.model_dump())
        if agreement is False:
            findings.append(finding("dns_answers_differ","dns","observed",{"groups":[{"endpoint":r["endpoint"],"group":r["comparison_group"],"rcode":r["rcode"]} for r in dns_rows]},"Compare resolver policy, CDN behavior and cache. Different answers alone do not establish blocking."))
        if any(f["code"]!="no_issue_observed" for f in findings):
            findings=[f for f in findings if f["code"]!="no_issue_observed"]
        results.append({"family":family,"probe":probe,"dns":dns_rows,"dns_skipped":dns_skipped,"dns_agreement":agreement,"findings":findings})
    if len(results)==2:
        a,b=results
        if a["probe"]["ok"]!=b["probe"]["ok"]:
            for row in results:
                row["findings"]=[f for f in row["findings"] if f["code"]!="no_issue_observed"]
                row["findings"].append(finding("family_asymmetry","network","observed",{"ipv4_ok":a["probe"]["ok"],"ipv6_ok":b["probe"]["ok"]},"Compare address records, routing and service support for each family; no conclusion about the ISP."))
    return {"rule_version":RULE_VERSION,"host":config.host,"port":config.port,"kind":config.kind,"vantage":"container","started_at":start,"finished_at":time.time(),"thresholds":config.thresholds.model_dump(),"results":results,"limitations":["Single observation per family, not continuous monitoring.","HTTP HEAD is not a full browser or application health check.","Explicit resolver queries do not replace the system resolver or change the connection IP.","No automatic remediation or attribution of censorship, packet loss or upstream faults."]}
