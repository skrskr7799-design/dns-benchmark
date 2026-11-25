# Network Diagnostics Center

Self-hosted network diagnostics for an authorized private network. Single
controller (FastAPI, React, SQLite) with optional outbound-only agents.
This branch is a release candidate, not a stable release. Do not expose
the service directly to the Internet.

## Modules

DNS Benchmark (UDP/TCP, DoH2/H3, DoT, DoQ; Cold/Warm/Both), DNS Inspector,
Connectivity, TLS Inspector, Route Analyzer, Monitoring, Agents,
Smart Diagnostics, AdGuard Home read-only integration and bounded HTTP download.

## Isolated CasaOS preview

Use deploy/compose.preview-rel01.yaml on port 8113, **not** the old live
installation on 8099. Create the separate writable directory:
```sh
sudo install -d -m 700 -o 10001 -g 10001 /DATA/AppData/dns-benchmark-preview-rel01
```
Open the direct local IP and port to create the first owner in the browser. Existing owner-password files or NDC_OWNER_PASSWORD remain supported. The new account stores a salted scrypt verifier in /data/owner-account.json (0600). First-run setup is limited to direct private-network requests; do not expose an unconfigured instance to the Internet, even through Docker NAT. By default direct local HTTP uses a non-Secure cookie, other requests use Secure cookies; explicit NDC_SECURE_COOKIE=0 or 1 overrides this. Use verified HTTPS for normal operation. A writable /data mount is required.
Import the preview compose only after its CI publishes the image. HTTP
preview requires explicit NDC_SECURE_COOKIE=0 and a trusted LAN, firewall
or private overlay. For normal operation use a verified HTTPS reverse proxy,
set NDC_ORIGIN to the exact HTTPS origin, and keep secure cookies enabled.
Restrict network exposure and outbound target scope. No root or NET_RAW needed.

Explicit NDC_ALLOWED_CIDRS permits non-global targets; e.g. an authorized
single AdGuard IP /32. This is application validation, not a firewall.
Metadata/link-local destinations stay denied. Agents require local endpoint
allowlists and verified HTTPS; see docs/DIST-01.md and docs/DIST-02.md.
Optional Telegram and AdGuard are disabled until configured. See
docs/MON-01.md and docs/INT-01.md. Full certificates chain and ICMP/route
availability depend on runtime. No independent DNSSEC validation.

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
