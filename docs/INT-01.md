# INT-01 — optional integrations candidate

DIAG-01 run 45596168766 failed in browser strict locator (two evidence
blocks matched TimeoutError); all backend unit/integration stages passed.
Fix faeecf2 scopes to the finding card. Full rerun still required.

AdGuard Home: official OpenAPI https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml
GET /control/status, /control/stats, /control/dns_info only. Authenticated
owner explicitly requests snapshot; no queries to querylog, no writes to
AdGuard. Note upstream AdGuard credentials may themselves have admin rights;
this adapter is read-only, not an AdGuard-side least-privilege account.
Prefer an independently restricted reverse proxy allowing those three GETs.
No raw payload, domains, client IP lists, full upstream paths, query tokens
or auth secrets returned. Aggregates may be absent/partial; time values
converted from seconds to ms. Upstream host/port only, conditional entries
omitted. Distinct URLs may collapse to same host label.

Opt in by creating /data/adguard.json with mode 0600, owner uid 10001.
Example (placeholders, not deployed):
    {"origin":"https://adguard.example.test:443","ip":"192.168.0.108","username":"YOUR_USER","password":"YOUR_PASSWORD"}
Set NDC_ALLOWED_CIDRS=192.168.0.108/32 (or exact authorized IP). The
origin hostname must match its TLS cert. NDC_CA_FILE may point to a trusted
private CA. HTTP only with explicit "allow_http":true and non-global IP;
it transmits Basic credentials in plaintext, so prefer verified HTTPS.
Both integrations use fixed pinned IP, validated scope, no redirects/proxy.
No browser-controlled target or credential input. Files read at request time;
missing file disables integration. AdGuard 15-second cooldown.

Optional /data/throughput.json mode 0600:
    {"origin":"https://speed.example.test","ip":"192.168.0.108","path":"/test.bin"}
Use only an authorized static file endpoint; no credentials, upload,
redirect or automatic scheduled tests. GET with identity encoding; cap
8 MiB consumed bytes, 3-second socket inactivity timeout, soft 10-second
elapsed budget checked between chunks. Header/slow-drip read can exceed
soft budget; not a hard wall-clock deadline. Quota one attempt per minute
per process; resets on restart. Throughput is application payload over
entire measured interval, includes connection/setup; not link capacity.
Partial errors explicitly labelled. No third-party speed service by default.
AdGuard JSON cap 2 MiB per response, soft 8-second body deadline; three
sequential GETs. Shared interactive slot; no persistence of reports.
Preview 8112 isolated data; no live changes. CI fixtures pending.
Remaining production gates: hard request deadlines, dependency lock/audit,
live transports, independent client comparison, CasaOS and VPS tests,
security/rollback/retention review. Main unchanged.
