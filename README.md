# DNS Benchmark / Network Intelligence Platform

Self-hosted network diagnostics for an authorized private network. Single
controller (FastAPI, React, SQLite) with optional outbound-only agents.
This branch is a release candidate, not a stable release. Do not expose
the service directly to the Internet.

## Modules

DNS Benchmark (UDP/TCP, DoH2/H3, DoT, DoQ; Cold/Warm/Both), Providers,
DNS Inspector, Connectivity, TLS Inspector, Route Analyzer, Monitoring, Agents,
Smart Diagnostics, AdGuard Home read-only integration and bounded HTTP download.
Network Intelligence: DNS Intelligence, Observatory, Time Machine, Global
Intelligence (remote and explicitly authorized peer measurements), DNS Integrity,
Protocol Laboratory, Internet Atlas, Website X-Ray, Network Twin, Scenario
Builder and Chaos Lab. Optional functionality is gated and subject to documented
measurement limitations. See [integration candidate](docs/INTEGRATION-CANDIDATE.md).

## Isolated CasaOS preview

Use [deploy/compose.acceptance.yaml](deploy/compose.acceptance.yaml) and the exact
source/image instructions in [the acceptance record](docs/INTEGRATION-CANDIDATE.md).
Port 8113 binds loopback by default; use an explicitly restricted trusted LAN
address for mobile testing. Separate data directory; never replace the existing
installation on 8099. No published preview image is assumed. Create the first
owner in the browser on the isolated instance; use verified HTTPS for normal
operation. The preview HTTP cookie override is not a production setting.

Explicit NDC_ALLOWED_CIDRS permits non-global targets; e.g. an authorized
single AdGuard IP /32. This is application validation, not a firewall.
Metadata/link-local destinations stay denied. Agents require local endpoint
allowlists and verified HTTPS; see docs/DIST-01.md and docs/DIST-02.md.
Optional Telegram and AdGuard are disabled until configured. See
docs/MON-01.md and docs/INT-01.md. Full certificates chain and ICMP/route
availability depend on runtime. DNSSEC positive-chain verification requires an
independently supplied trusted root DNSKEY and explicit delegation chain; negative
proofs and client leak testing are not implemented. Chaos packet tests are local
loopback fixtures, not external network impairment.

## Data and operational safety

See docs/REL-01.md for backup/restore, migration and rollback. New histories
are capped at NDC_MAX_JOBS (default 500), existing runs are never silently
removed, and terminal runs can be exported/deleted from History. Limit is
a record count, not a filesystem quota. Monitor disk use.
Never copy a live SQLite database using plain cp without its WAL.
Never run two controllers on one data directory.
Never replace a working data directory to try a preview.

## Status

See docs/REL-01.md for release gates, and individual phase documents for
limitations. Local CI is necessary but not sufficient for production
acceptance. No live deployment or main merge is implied.

First-run setup also accepts direct `.local` hostnames (e.g. `http://casaos.local:8099`) from private source addresses. The suffix does not authenticate the client; forwarded requests remain rejected. Name resolution must already work in the user's network. Password minimum remains 16 characters; the form displays validation checks and a message on invalid submission.
