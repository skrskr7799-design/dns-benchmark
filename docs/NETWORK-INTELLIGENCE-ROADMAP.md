# Network Intelligence Platform — expansion roadmap

Status: proposed implementation programme, owner endorsed the eleven concepts in discussion. No module in this document is claimed implemented. Main baseline 920bffc6bd7a44da2fb84e881b0da363c2e64b4f; mobile drawer fix 4a5121d32f929c9523103f7da1d0805255325390 passed CI 45615833349, independently awaiting owner merge approval. Owner reported successful live CasaOS UI/login except mobile drawer. Existing REL-01 production gates are not waived. The tested version remains an integration candidate. Obsidian Signature remains the UI contract.

## Product direction

An entirely self-hosted network intelligence platform: measure, observe, explain, correlate, model and automate. Existing tools remain useful individually. New modules share typed observations and events instead of duplicating probes, history, notification systems or credential handling. Core stays Python/FastAPI, React/TypeScript, SQLite and the current outbound-only agent model. No mandatory external cloud, Redis, PostgreSQL or Kubernetes. Optional browser and fault laboratory workers are isolated opt-in components, never in the default CasaOS image. Keep 8099 and existing writable /data mount, owner account and legacy histories; additive migration with backup and restore validation.

## Delivery order

| Phase | Module / output | Depends on | Acceptance |
|---|---|---|---|
| NIP-00 | Baseline hardening and real acceptance | existing REL-01 | Record actual transports and capabilities; backup/restore owner-account and DBs; independent measurement comparison; live tests only with owner authorization; OS image audit; baseline CPU/RAM/disk and bounded cancellation; do not represent unresolved gates as passed |
| NIP-01 | Shared evidence, jobs and event foundation | NIP-00 baseline inventory | Versioned observations with provenance, typed units, status and correlation IDs; SQLite additive schema, retention, pagination, atomic idempotency, bounded scheduler; restart/recovery and legacy tests; backfill only supported fields |
| NIP-02 | DNS Intelligence | NIP-01 | Comparable cohorts, configurable transparent scoring, confidence/sample coverage, reliability and p50/p95/p99, explain recommendation and fallback; no rank for incompatible/incomplete data; deterministic scoring fixture; local AdGuard export never auto-applied |
| NIP-03 | Network Observatory | NIP-01 | Scheduled profiles, time windows, baseline/anomaly detection, maintenance/unknown periods, incident dedup and recovery, observed availability, chart gaps; monitor scheduler fairness and bounded retention |
| NIP-04 | Network Time Machine | NIP-03 | Immutable bounded snapshots of authorized endpoints, DNS RRsets/route observations/cert fingerprints/address changes; semantic diff with unknown/not collected distinguished from removal; timeline and links to source evidence; no false causal inference |
| NIP-05 | Global Network Intelligence | NIP-01 | Versioned remote TCP/TLS/HTTP/route jobs, capabilities, local/remote comparability, leases, cancel, offline behavior, opt-in controlled two-agent RTT/throughput, directional matrix, explicit timestamp/coverage; real two-node acceptance before broad rollout |
| NIP-06 | DNS Integrity & Privacy | NIP-02, NIP-05 | Resolver agreement with CDN/geo/TTL caveats, controlled positive/negative DNSSEC tests and actual independent validation where supported, split DNS by vantage; optional client-side DNS leak test via consented authoritative test zone; distinguish container/agent/browser vantage |
| NIP-07 | Protocol Laboratory | NIP-01 | Reproducible profiles for cold/warm, IPv4/v6, concurrency, actual negotiated transports and reuse; fixed authorized test endpoints, workload and wall-clock budgets; compare matched corpus/time/IP/protocol, independent transport cross-checks |
| NIP-08 | Internet Atlas | NIP-01 | IP/domain/ASN search; RDAP allocation, origin ASN/prefix, BGP observations, RPKI status from named sources with retrieval time; cached bounded fixed-provider clients, provenance and offline/error state; no invented geolocation or universal path |
| NIP-09 | Website X-Ray | NIP-01, NIP-08 optional enrichment | DNS/TCP/TLS/HTTP phases, bounded redirect chain with per-hop scope validation, cache/security headers and observed protocol; optional isolated browser worker waterfall with subresource policy, no arbitrary user scripts, downloads or retained cookies |
| NIP-10 | Network Twin | NIP-03, NIP-04, NIP-05 | Owner-defined device/service/site graph, directed typed dependencies, binding real monitor IDs and source evidence; cycle-safe impact analysis, unknown/stale propagation, root-cause hypotheses not facts, graph scalability and mobile list |
| NIP-11 | Network Scenario Builder | NIP-01, NIP-03, NIP-10 | Versioned typed DAG editor and runner; manual/scheduled/incident triggers, conditions, bounded actions, notifications and audit; dry-run, revision pinning, idempotent resume, cancellation, loop/recursion rejection; no arbitrary shell/code/webhooks or automatic config changes |
| NIP-12 | Network Chaos Lab | NIP-07, NIP-11 optional orchestration | Separate disposable test environment, controlled delay/loss/limits/DNS failure, known target allowlist, kill/cleanup and rollback proof, no live network privileges in core, no host or production interface mutation |
| NIP-13 | Integrated acceptance and release | NIP-02..12 | Full cross-module workflows, migrations/restore, dependency and image scans, live authorized fixtures, resource soak and UI accessibility at 320/390/768/1536 widths, operator docs, approved immutable release and rollback |

Order within the above dependency graph may be adjusted by owner approval. Each phase is split into A (contract/backend), B (UI/interaction), C (tests, security, performance and evidence). These are proposed milestones, not promised dates. No bulk rewrite or placeholder pages masquerading as implemented features.

## Architecture decisions for NIP-01

- Keep existing history.sqlite, monitoring.sqlite and agents.sqlite authoritative. Proposed new intelligence.sqlite is a derived evidence/event store, not a replacement. Include it in offline backup/restore before persisting data; explicit migration version and compatibility gate. No cross-database atomicity claim: use per-source committed outbox or durable cursor/idempotent replay with unique source identity and revision; prove crash windows and gaps. Avoid unbounded duplicate raw payloads; link to source IDs, retain compact immutable evidence summaries with documented expiration.
- Observation envelope proposal: schema_version, observation_id, source_kind/source_id/source_revision, run_id, optional correlation_id, vantage_id, observed_at UTC, received_at UTC, target_id, probe_kind, profile_revision, outcome (success/failure/unknown/skipped), typed measurements (name/value/unit), protocol/IP/family where observed, error_code, limitations and provenance. Missing values are null, not zero. Remote timestamps are agent claims with skew checks; controller receipt time is separate. Do not persist secrets, private auth headers or full response bodies by default.
- Event envelope: event_id, event_type, source identity/revision, observed_at, recorded_at, affected targets/vantages, severity, confidence, evidence links, rule_version, deduplication key. Event transition and notification outbox are atomic within their database. At-least-once processing, idempotent materialization, explicit partial/unknown status. No exactly-once external delivery promise.
- Scheduler: reuse existing bounded execution lanes and shared probe scope; no second uncoordinated scheduler. Define admission, per-user/site/target concurrency, queue/time/byte budgets and fairness between interactive/periodic tasks. No catch-up storm; cancel and restart preserve terminal state. Hard deadlines for new potentially blocking workers, including resolver and browser subprocess trees.
- Before implementation measure target hardware and choose explicit defaults. Candidate budget: existing controller 768 MiB/128 PIDs, 20 monitors baseline, retention 30 days with configurable row and byte ceilings, bounded read pages and export, no always-on high-frequency probes. These are starting constraints, not measured guarantees. Browser worker and Chaos Lab disabled unless separately installed. Independent disk alerts, checkpoint/vacuum maintenance tested; no silent deletion of user-pinned evidence.
- Shared target/profile identity should include exact endpoint, probe parameters, family, intended versus negotiated protocol, network vantage and version. Comparability rules are versioned, not inferred from display names. Anycast IP equality does not imply same physical resolver.
- Capability and security: preserve owner auth/CSRF, verified HTTPS agents, destination allowlist and metadata deny, no arbitrary remote commands, no implicit broadening to LAN scans. Revalidate each resolved address and redirect, pin connections, reject ambiguous/mixed targets as applicable. Scope checks must run on each agent, not just controller. Rate-limit public data providers, honor policy/terms, no private targets submitted to external enrichment APIs by default. Internet Atlas sources must be selected and verified during implementation, not assumed.
- Design: keep graphite/cyan #80D6DF and existing typography; group nav into Diagnostics, Intelligence, Infrastructure, Automation and System only after usability review. Reuse charts, tables and responsive components. No fake scores, maps, country metadata or live activity. All module screenshots clearly distinguish test fixture from real data. Mobile off-canvas drawer is a separate pending merge.

## Module specifics and limits

DNS Intelligence: version weights, show contributing metrics, eligibility and sample count. Start with reliability and p95/p50, then jitter/reuse, protocol availability and cohort coverage. No subjective privacy/security score unless grounded by separately verified criteria. Fallback recommendations distinguish client resolver behavior from AdGuard upstream policy.

Observatory: rolling median/MAD or quantile baseline after sufficient comparable samples; sparse or changed profile means insufficient baseline. Display threshold rules, maintenance and missing windows; observed success proportion is not continuous uptime. Correlation is temporal evidence, not proof of causation.

Time Machine: user chooses target set and snapshot cadence. Normalize RRsets excluding ordering, track TTL separately, distinguish observed ICMP route change from actual path certainty, certificate renewal versus trust failure. Bound snapshot size and keep diffs traceable.

Global: keep agents outbound-only, signed/authenticated lease protocol with explicit feature negotiation; version rollback compatibility. Use only owner-controlled endpoints for throughput and pairwise test listeners with authentication/quotas. Start with two authorized nodes, expand to six only after real acceptance. No remote arbitrary scripts, public load tests or VPN deployment changes.

Integrity: use controlled domains with known answers for meaningful DNSSEC/filter tests. AD flag is not independent verification. Different valid CDN answers are not evidence of hijack; mark suspicion with uncertainty. Client DNS leak requires separate opt-in client workflow and authoritative instrumentation; server probe cannot infer phone DNS.

Lab: test only owned or authorized infrastructure. Separate cold/warm, matched samples, explicit actual HTTP version/QUIC and failure reasons, stop budgets. Report missing protocol as unsupported or untested, not zero latency.

Atlas: use registry RDAP and routing datasets/providers subject to availability. Registry holder, route origin, geolocation and hosting provider are distinct. RPKI valid/invalid/not-found is specific to prefix/origin and time. Avoid forwarding private IP or internal DNS names externally.

X-Ray: bounded HTTP methods and response bodies, header redaction, no credentials by default. Browser worker separate egress enforcement for every request, strict timeout, no service worker/persistence or arbitrary scripts. Technology detection is heuristic, not authoritative.

Twin: manually declared graph first; read-only integrations may suggest nodes later, never silently modify topology. Dependencies do not prove root cause. Site grouping, filter and zoom for large graphs; accessible mobile list.

Scenario: first release manual DAG with typed registered actions, then schedule/event triggers. Validate DAG and permissions on save and run. Pin immutable scenario version, limit steps/fan-out/depth/retries/duration, quotas, notification dedup, no self-trigger loops. No destructive operations or generic arbitrary URL callbacks.

Chaos: isolated disposable Docker network or separate VM only. Core keeps cap-drop ALL; optional fault runner may use narrowly scoped NET_ADMIN in isolated namespace, not host networking or Docker socket. Explicit start/stop, watchdog, cleanup even on crash, no modification of real router/VPN/AdGuard. Simulator first if platform lacks isolation.

## Proposed release trains

- v0.4: NIP-00/01 foundation, DNS Intelligence, Observatory and Time Machine.
- v0.5: Global Intelligence, Integrity & Privacy, Protocol Lab.
- v0.6: Internet Atlas, Website X-Ray, Network Twin.
- v0.7: Scenario Builder and isolated Chaos Lab.
- v1.0: only after acceptance gates and explicit owner approval.

Version numbers are planning labels. The current edge and prerelease tag are not changed by this roadmap.

## Quality / working agreement

Work branches, one coherent pass per commit, green exact-head CI before moving on. Record implemented/partial/blocked with SHA, CI run and evidence in a progress ledger; no claims of live success from deterministic fixtures. Main merge only on explicit owner approval. No deployments or credentials requested without a clear owner-authorized test. Each phase includes security threat cases, migration/backup tests, API contract and browser tests, actual resource measurements, and documented limits. Keep existing install usable throughout; test previews in separate data directories. First practical work: resolve NIP-00 baseline gap inventory, then NIP-01A evidence contract and crash-safe ingestion spike; no new feature UI until shared contract and retention tests pass.

## Progress ledger

| Stage | Status | Evidence |
|---|---|---|
| Existing platform | owner initial acceptance, partial | UI/login reported working on CasaOS; remaining live transport/agent/integration gates in REL-01 |
| Mobile drawer | implemented / CI passed / merge pending | 4a5121d, 45615833349; actual iOS retest after main publication |
| NIP-00 | partial | [baseline inventory](NIP-00.md); real acceptance pending |
| NIP-01A | implemented / CI passed (45631588249) | [contract and derived store](NIP-01.md); source ingestion not enabled |
| NIP-01B1 | implemented / CI passed (45636343788) | benchmark transactional outbox and drain; [NIP-01](NIP-01.md) |
| NIP-01B2 | implemented / CI passed (45647219921) | monitor observation/incident outbox, fair drain and coverage counters |
| NIP-01B3 | implemented / CI passed (45649570754) | agent result outbox, sample-derived metrics and three-stream drain |
| NIP-01C1 | implemented / CI passed (45650114432) | source allocations, pressure retention and authenticated read API |
| NIP-01C2 | implemented / CI passed (45650846494) | comparable DNS cohorts and bounded coverage-aware read API |
| NIP-02A | implemented / CI passed (45652543280) | [DNS Intelligence scoring](NIP-02.md), matched local runs and recommendation gates |
| NIP-02B | implemented / repaired and verified (45658906221) | DNS Intelligence UI, real ranking API, responsive fixture tests |
| NIP-02C1 | implemented / CI passed (45658906221) | accessible filter fix, controlled UDP-to-ranking acceptance, backup replay |
| NIP-02C2 | implemented / CI passed (45660254579) | reviewed ten DNS Intelligence screenshots; compact mobile layout repair and regression |
| NIP-03A1 | implemented / CI passed (45662383202) | [Observatory baseline and anomaly read model](NIP-03.md) |
| NIP-03A2 | implemented / CI passed (45664227760) | transactional Observatory state, journal, pause/resume boundaries and event replay |
| NIP-03B | implemented / CI passed (45737341394) | Observatory UI, pause-aware window reconstruction, real API and responsive tests |
| NIP-03C1 | implemented / CI passed (45743862564) | real controlled HTTP probe, active-anomaly backup replay, mobile plot polish |
| NIP-03C2 | implemented / CI passed (45744665875) | scheduled maintenance, claim recovery, Observatory controls |
| NIP-04A1 | implemented / CI passed (45745414003) | [immutable monitor snapshots and semantic diff](NIP-04.md) |
| NIP-04A2 | implemented / CI passed (45745857257) | scoped DNS/TLS/route snapshots and semantic diff |
| NIP-04A3 | implemented / CI passed (45746425204) | bounded snapshot schedules, shared lane, restart reconciliation |
| NIP-04B | implemented / CI passed (45746786204) | Time Machine UI, compatible comparison, capture and schedules |
| NIP-04C1 | implemented / CI failed (45752914452) | real scheduled TLS rotation, restore, loopback route and structured details |
| NIP-04C2 | CI failed (45753346652) | complete backup fixture, real TLS acceptance and maintenance browser regression |
| NIP-04C3 | implemented / CI passed (45753872223) | shared test CA and two distinct server leaves, strict validation unchanged |
| NIP-05A1a | implemented / CI passed (45754380166) | [v2 capability negotiation and legacy DNS lease compatibility](NIP-05.md) |
| NIP-05A1b | implemented / CI passed (45754782749) | typed TCP admission, shared lease, validated result and outbox; dispatch disabled |
| NIP-05A2a | implemented / CI passed (45755238285) | scoped remote TCP subprocess, deadline, cancellation, v2 spool and real API acceptance |
| NIP-05A2b1 | implemented / CI passed (45755567135) | TLS and HTTP/HTTPS scoped worker and typed evidence |
| NIP-05A2b2 | implemented / CI passed (45755942196) | bounded route worker and coverage-aware hop results |
| NIP-05A3a | targeted tests passed / full CI failed (45756523742) | matched remote batches, bounded dispatch and compatible cohorts |
| NIP-05A3b | CI failed (45756928443) | pairwise observations, matched phase deltas and smoke rate-budget fix |
| NIP-05A3c/A4a | targeted tests passed / full CI failed (45757284651) | strict fixture repair, peer authorization and RTT report contract only |
| NIP-05A4b1 | bidirectional mTLS passed / CI failed (45757582898) | explicit one-shot mTLS RTT transport and local real tests |
| NIP-05A4b1r | implemented / CI passed (45759770696) | deterministic login budget and successive listener bind, exclusivity regression |
| NIP-05A4b2a | implemented / CI passed (45760382194) | internal durable peer coordination, shared reservation and evidence reconciliation |
| NIP-05A4b2b1 | implemented / CI passed (45768493456) | gated peer API and one-shot volatile grant relay |
| NIP-05A4b2b2 | implemented candidate / CI pending | opt-in local RTT runtime and durable execution journal |
| NIP-05A4c1 | implemented / CI passed (45769505682) | bounded directional mTLS goodput transport, separately approved |
| NIP-05A4c2a | targeted tests passed / full CI failed (45770928897) | explicit local throughput runtime boundary and durable per-agent traffic budget |
| NIP-05A4c2a-r | browser 10/10 passed / full CI failed (45771253284) | deterministic DNS initial editing and late defaults regression |
| NIP-05A4c2b1 | CI failed (45771661675) | independent internal goodput claims, shared reservations, controller admission budget, CI isolation |
| NIP-05A4c2b1r | implemented / CI passed (45771859956) | old schema fixture repair, expiry clock high-water and shared queue regression |
| NIP-05A4c2b2 | implemented / CI passed (45772037144) | internal session leases, quarantine, exact receipt reconciliation and evidence |
| NIP-05A4c2b3 | implemented / CI passed (45772249210) | opt-in owner/machine API, sequential agent execution and end-to-end fixture |
| NIP-05B | implemented / CI passed (45772553347) | Global Intelligence workspace, bounded directional matrix and remote comparison |
| NIP-05C1 | backend/API passed / visual CI failed (45775704394) | owner launch and cancellation forms, bounded matrix, retry fixture |
| NIP-05C2a | implemented / CI passed (45783493054) | accessible launch labels, bounded claim refresh, rotated peer priority |
| NIP-05C2b | planned | active-session load, RTT cancellation/restart hardening and physical acceptance |
| NIP-06A/B | implemented / CI passed (45783888520) | resolver agreement, controlled DNSSEC behavior, pinned-key signature check and UI; no root-chain or client leak claim |
| NIP-07A/B | implemented / CI passed (45784324206) | configured endpoint laboratory, fixed workload, child deadline, matched transport/reuse comparison and UI |
| NIP-08A/B, NIP-09A/B | implemented / CI passed (45785449505) | opt-in fixed-provider Atlas, bounded HEAD X-Ray, both workspaces |
| NIP-10A/B | implemented / CI passed (45785884186) | owner topology revisions, monitor/evidence binding, cycle-safe impact and responsive editor |
| NIP-11A/B, NIP-12A/B | implemented / CI passed (45787223492) | manual read-only scenario DAG, revision-pinned reports, synthetic fault model and workspaces |
| NIP-13A | implemented / CI job passed (45787805056) | mobile drawer reconciliation, known controller database backup/restore, acceptance gap register |
| NIP-13B1 | implemented / CI passed (45788074879) | RTT terminal quarantine, goodput receipt quarantine, shared clock guard and regression tests |
| NIP-13B2a | implemented / CI passed (45788416348) | bounded worker pipes and actual timeout tests, provider TLS/IP binding and RDAP validation |
| NIP-13B2b | implemented / CI passed (45788749071) | verified machine request budgets and reserved active continuation lane |
| NIP-13B scheduler consolidation | implemented / CI passed (45789396818) | bounded background reservation, shutdown admission guard |
| NIP-13C/D/E | planned | close remaining documented functional gaps or agree deferred scope; design and final acceptance | remaining modules; final visual acceptance, physical budget and shared scheduler hardening remain open; [server acceptance gate](SERVER-ACCEPTANCE.md) |

Functional completion candidate: graphical Twin and opt-in durable Lab/X-Ray history. See NIP-13.md for explicit remaining scope; no added stages.

Scenario automation candidate adds periodic and observed incident trigger, revision pinning, atomic reports/cadence and capacity pause. Remaining scope unchanged (NIP-13.md).

Functional candidate adds positive DNSSEC chain under explicitly supplied root key and real bounded loopback UDP DNS fault experiments; remaining acceptance in NIP-13.md. CI pending.
