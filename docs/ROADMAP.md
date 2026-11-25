# Delivery roadmap (historical foundation plan)

For the next generation, see [Network Intelligence Platform](NETWORK-INTELLIGENCE-ROADMAP.md). The original plan below is preserved as historical context; its status statements are not a current implementation inventory.

All stages are planned, not implemented. Deliver small accepted slices;
no main merge without owner approval. Each stage includes tests and notes.

| Phase | Deliverable | Acceptance gate |
|---|---|---|
| FND-01 | React/Vite/TS shell, design tokens, routing, typed API, multi-stage image | Existing benchmark works through new UI; mobile and desktop; legacy data preserved; preview on port 8100 separate data |
| FND-02 | FastAPI modules, persistent job coordinator, SQLite migration, SSE, profiles, cancel | Deterministic tests for restart/cancel/error and old DB import; export compatibility; no duplicate jobs |
| FND-03 | Auth, target scope, limits, capabilities, operational docs | Unauthorized actions rejected; rebinding/redirect/metadata tests; non-root image; no privileged access |
| DNS-01 | Transport correctness spike and canonical engine decision | Local H2/H3/DoT/DoQ tests; actual protocol/peer/reuse verified; independent client comparison; documented limitations |
| DNS-02 | Benchmark v2: both modes, raw samples, phases, metrics, profiles, comparison charts | Same IP/corpus; successful warmup explicit; strict protocol; 100-sample local deterministic case; error class; AdGuard copy/export |
| DNS-03 | DNS Inspector | Correct record types, NXDOMAIN/SERVFAIL/TC/AD semantics; answer diff; deterministic fixtures |
| NET-01 | Connectivity + TLS | TCP/HTTP phases, chain and name validation, expiry; capability-aware ICMP; no fake metrics |
| NET-02 | Route Analyzer | Optional limited runner; hop timeout/IPv6 tests; no privileged container |
| MON-01 | Scheduled jobs + history + alert lifecycle | Restart-safe scheduling, no overlapping tasks, retention, deduplication, recovery and rate limit |
| DIST-01 | Agent contract and engine reuse | Local and remote same methodology; auth/enrollment/revocation/leases/spool; no shell tasks |
| DIST-02 | Multi-site dashboard | Two test nodes, offline/resume, idempotent results, comparison with same profile |
| DIAG-01 | Evidence-based diagnostics | Fixture for DNS/TCP/TLS/HTTP failures, explicit uncertainty, no auto remediation |
| INT-01 | Optional read-only AdGuard integration and throughput | Secrets protected, user-approved target, quotas, opt-in only |
| REL-01 | Production polish and release | Migration/rollback rehearsal, browser smoke, security audit, docs, resource measurement on target hardware |

Suggested release slices: v0.3 foundation + DNS benchmark correctness (FND-01..03,
DNS-01..02); v0.4 inspector/connectivity/TLS; v0.5 route and monitoring;
v0.6 distributed; v0.7 diagnostics/integrations; v1.0 acceptance. Version numbers
are proposals, not promised deadlines. Auth/scope required before remote or
scheduled execution. Deterministic tests are required for every supported
transport; public live probes are opt-in and do not define CI reliability.

## First implementation pass
1. Create work branch from approved docs/main; broaden CI trigger for work/**,
   publish preview only if explicitly configured, keep main edge separate.
2. Establish React build, route shell, benchmark feature with current API adapter
   and reusable table/chart primitives. Keep original backend functional.
3. Multi-stage Docker build, same /data and port 8099, SPA served same origin.
   Verify old history and export; no breaking DB migration in first UI pass.
4. Then extract backend modules and implement durable jobs and migrations.
5. Correct benchmark transport with local protocol fixtures before expanding tools.

## Current known defects
H3 reuse unproven; many H3 failures and blank exception text. Some Cold/Warm
runs select different IPs; actual connected IP/protocol not independently verified.
Warmup failure silently excluded. Legacy history lacks raw samples; global
state not restart safe; no cancellation, saved profiles, auth, target restrictions
or retention. CI checks health/defaults/import only. No need to change live
AdGuard Home or NetBird. Keep working v0.2.0 installed until a preview passes.
