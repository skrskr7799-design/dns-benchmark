# NIP-13 — integrated acceptance register

Release gate, not a declaration of completion. No main merge, release tag, image promotion or owner-server changes.

## A — consolidation
Baseline 1d09699, main 920bffc (51 ahead, 0 behind), separate mobile drawer 4a5121d (one divergent commit). Ported drawer Shell, CSS, responsive assertions; new routes retained. Backups cover six known controller databases (history, monitoring, agents, intelligence, twin, scenarios) plus existing managed auth/integration files. Format v1 compatible with legacy subsets. Added restore tests for exact Twin revision and Scenario definition/run replay, legacy manifest, malformed hashes and symlink manifest. External env/TLS/agent configuration separate. CI pending.

## Outstanding scope and evidence
| Gate | Remaining acceptance / functionality |
|---|---|
| NIP-00..04 | physical resource/legacy migration and restore, cross-module scheduler deadlines, owner server and live observations |
| NIP-05 | active machine request saturation, fairness, RTT cancellation/restart quarantine, actual private mTLS two-VPS measurement |
| NIP-06 | controlled authoritative signed/bogus fixture, full trust chain, split DNS and consented client leak design |
| NIP-07 | encrypted end-to-end lab fixtures, actual child timeout/reap, populated browser and durable experiment history |
| NIP-08 | real fixed provider compatibility, resource binding and provider DNS/egress, multi-address and cache/error acceptance |
| NIP-09 | real HTTPS/redirect fixture, optional isolated browser waterfall, durable evidence |
| NIP-10 | graphical topology, populated editor/revision/evidence integration, retention/export and restore |
| NIP-11 | scheduled/incident triggers, durable bounded actions/notifications, cancellation/resume; currently manual read-only DAG |
| NIP-12 | disposable actual packet impairment fixture with isolation and cleanup proof; currently synthetic only |
| NIP-13 | exact candidate full CI, real screenshots vs approved references, mobile Safari, accessibility, dependency/image scan, realistic soak, migration/backup/rollback, documented scope and explicit owner approval |

## Order
B: security/lifecycle correctness, shared budgets and scope. C: complete required gaps or explicitly agree deferred scope. D: populated cross-module workflows and visual review against original references. E: integration candidate and deployment/rollback docs; owner approval before main merge, physical acceptance afterwards. No readiness percentage based on page count or prior CI.

## B1 — peer lifecycle hardening (candidate)
RTT terminal sessions with a receiver lease retain shared agent reservation until controller deadline + 10s, including cancellation, credential invalidation, expiry, restart and matching receipts. Queued requests without a lease release immediately. Goodput matching receipts no longer release existing quarantine early. Existing persisted deadline/lease fields avoid schema changes. Shared goodput clock high-water also guards RTT claim refresh, admission and freshness; rollback cannot advance a new handoff, and expiration does not prune histories during rollback. Tests cover cancellation through restart, blocked DNS dispatch until quarantine boundary, rollback handoff and completed goodput reservation. These are controller-time safeguards, not proof of remote process termination; forward clock jumps, clock-domain reconciliation, active rate limiter saturation and physical load acceptance remain open. CI pending.

## B2a — bounded worker IO and provider destination validation (candidate)
Atlas, X-Ray, Protocol Lab and synthetic Chaos use a shared monotonic worker deadline, bounded input/output and diagnostic pipes, nonblocking IO and kill/reap on failure. Linux controller only; this is not a sandbox or a full RSS/CPU limit. Tests exercise real child timeout and reaping, nonreading stdin, exact output limit, stderr overflow and failure. Atlas resolves only fixed provider hostnames, rejects mixed private/public DNS candidates regardless of configured LAN allowlist, connects to the chosen literal IP with peer check and TLS hostname verification, no proxy/redirect/compression. RDAP response object class and range must match requested IP/ASN before projection. Provider live compatibility, RPKI resource validation and active machine rate budgets remain open; no main merge. CI pending.

## B2b — verified machine rate lanes (candidate)
Consolidation job 139798939390 completed all steps successfully; B1 and B2a still running when checked. Machine enrollment remains 30/min. Other machine requests have a 1200/min shared pre-auth ingress cap, strict generated bearer format, verified agent identity preflight off the event loop, and a separate authorization check inside each route. Idle requests use 480/min global and 80/min per agent; heartbeat/status/finish/results use reserved 240/min global and 100/min per agent. Non-borrowing rolling monotonic windows bounded to 64 verified agent/lane keys; no bearer retained; expired entries removed. This changes previous shared 600/min ceiling to at most 720/min authenticated requests, plus enrollment. Invalid credentials cannot spend authenticated budgets but can exhaust ingress; reverse proxy and actual load acceptance still required. Preparation/start remain in idle lane, and malicious enrolled agents can still consume shared capacity. Additional SQLite authentication read per request is a deliberate cost. Tests cover idle saturation, active status, invalid credentials, rotation, expiration. No scheduler changes in this pass; benchmark/inspection contention, scheduler deadlines, forward clock jumps and physical performance remain open. CI pending.

## B — scheduler consolidation (candidate)
Peer lifecycle CI 45788074879 passed. Resource and API candidates still running at inspection. Shared interactive/monitor/snapshot lane now has a bounded 3-second background reservation on contention; HTTP stays nonblocking, no unbounded queue. Scheduler retries on its existing tick, reservation expires if no retry. Existing monitor-first ordering and minute snapshot cadence preserved. Benchmark remains a separate single job lane (up to two endpoint workers) deliberately, rather than holding the inspection slot for a long benchmark. Coordinator admission and claim serialized with stop signal, duplicate start rejected. Tests cover reservation/expiry, concurrent single admission and stopping admission. Not a measured hard scheduler deadline; notification IO, forward clock jumps, real resource soak, ingress saturation and external provider acceptance still require acceptance evidence. No new roadmap stages. CI pending. Next existing gates C, D, E only; do not expand scope. 
