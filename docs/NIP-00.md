# NIP-00 baseline inventory — partial

Baseline main 920bffc, CI 45613443277; owner reports working live login and UI on CasaOS, mobile menu displaced page. Mobile fix 4a5121d / 45615833349 green, not merged in this branch. Verified CI of mobile head includes local DNS transports, scope, job persistence, connectivity/TLS, route fixtures, monitor/agent/batch/diagnostics, integration, backup, concurrency, browser, first-run and dependency gate. It is a fixture run, not a live production acceptance certificate.

| Gate | Evidence / remaining work |
|---|---|
| Application package lock/audit | Existing CI passes npm/pip zero-known findings gate and runtime lock comparison. OS packages/base image scan not verified. |
| Transport | Local UDP/TCP/H2/H3/DoT/DoQ fixtures; actual internet H3/DoQ, independent client comparison, real IPv6 outstanding. |
| Persistence | SQLite WAL and controller flock, three authoritative DBs, offline backup. New owner-account restore and intelligence DB fixture added in NIP-01A. Real restore drill outstanding. |
| Runtime | Existing bounded queue and integration subprocess deadlines, 768MiB/128 PIDs test limits; general DNS/OS lookup deadlines remain soft. Peak/load/long-term disk measurement on CasaOS outstanding. |
| Distribution | Two loopback fixture agents; no real authorized VPS rollout/verified overlay test yet. |
| Integrations | Read-only AdGuard and Telegram fixtures; live credentials and permission-dependent checks pending. |
| UI | Owner initial live acceptance; mobile drawer fix CI verified but actual mobile Safari retest pending. |
| Auth/scope | Existing owner/CSRF and scope tests, local setup including .local. Private LAN restriction is deployment boundary, not proof of reachability through arbitrary NAT. |

No new live probes, credentials, server modifications or merges authorized in this pass. NIP-00 inventory is complete for this slice; hardening and real acceptance remain partial and track REL-01. NIP-01 contract spike can proceed without pretending these gates passed; no stable release before acceptance.
