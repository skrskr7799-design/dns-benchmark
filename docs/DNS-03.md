# DNS-03 — DNS Inspector candidate

DNS-02 CI passed at e1570c0 (run 45589699366).
New authenticated POST /api/v1/dns/inspect shares the scoped DNS engine.
Supports A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, PTR, SRV, HTTPS, SVCB,
DS, DNSKEY and RRSIG. Domain canonicalization uses dnspython; PTR accepts
an IP literal and converts to reverse DNS. Up to four endpoints, serial
queries, one inspection at a time; rejects overlap with other inspections.
Existing global authenticated write rate limit applies. Benchmark can run
concurrently; results are immediate and not added to benchmark history.

Returns answer/authority/additional RRsets, TTL, RCODE, response flags,
EDNS, requested DO, response DO, AD/CD, observed protocol and IP when
available, bootstrap and exchange time, CNAME links present in response.
DNSSEC flags are observations, not independent chain verification.
NXDOMAIN, NODATA, referral, alias-only, DNS errors, truncation and transport
errors remain distinct. Explicit optional UDP-to-TCP fallback uses same
validated IP/port; never automatically downgrades encrypted transports.
Answer groups ignore TTL, record order and RRSIG; compare canonical RDATA
and RCODE. Differences can be legitimate CDN, cache, location or policy
effects. No automatic claim of blocking/poisoning. No recursive CNAME chasing.
A response with no requested record and no alias/referral is labelled no_data,
not independently proven authoritative NODATA.

React module provides domain, record type, endpoints, IPv4/IPv6, DO/CD,
optional UDP fallback, comparison groups, sections, flags and JSON export.
No external service or network modification. Tests use deterministic DNS
fixtures. CI and real-network preview pending. No DB migration.
Preview port 8105 and isolated data directory, owner-password required.
Existing live install/main unchanged. Outstanding gates inherited from DNS-02:
live H3/DoQ, independent client/Go comparison, lockfile/dependency audit,
retention, full security and CasaOS acceptance. 
