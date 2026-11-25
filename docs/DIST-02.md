# DIST-02 — distributed dashboard candidate

DIST-01 verified green at 39bc3c0, run 45594461280. Owner UI adds Agents
page: create one-time invitation, manual location, heartbeat, online/offline,
enrolled/revoked/expired states, confirm credential rotation/revocation,
task details/raw JSON export and cancellation. Token held in component state,
not browser storage. No agents deployed on user's servers.

POST /api/v1/agents/batches accepts 2–8 distinct enrolled agent IDs and one
immutable AgentRun config (one endpoint, 1–10 queries per mode). Creates all
tasks atomically; queue limit on any member rejects entire batch. Request ID
deduplicates exact replay, conflict on changed config/agent set. UI retries
same request ID while component remains mounted and config unchanged; browser
reload loses pending ID. GET /batches (last 50), GET /batches/{id}, POST
/batches/{id}/cancel. Additive tables in agents.sqlite. Retain whole batch
until all tasks terminal and last completion older than 30 days. No new
agent protocol needed. Offline nodes queue until reconnect or 24h expiry;
lease 300s, no automatic replay. Batch cancellation cooperative, completed
results retained. No strict simultaneous start barrier.

Dashboard computes mean, p50, p95 and population standard deviation from
accepted individual samples on controller, not agent summary. Tables include
failed/queued/interrupted/offline members; unavailable values not zero.
Chart groups by mode, IP and observed protocol, successful complete series
only, successful warmup required for warm. Same IP is not same physical
anycast server; different times and networks confound comparisons. Reported
samples are authenticated agent claims, not independently attested. Warm
reconnects shown in reuse count. Location manually supplied, no geolocation.
JSON exports summary or full individual task. No local node comparison,
remote TLS/route/monitoring yet. No automatic configuration or deployment.

CI adds batch lifecycle/atomicity/idempotency/offline/restart/retention tests,
two real outbound loopback agents and browser flow. New CI pending.
Preview 8110, separate data/password; HTTPS private controller required for
real agents, HTTP preview UI only. Compose agent uses preview-dist-02.
Previous acceptance gaps remain: independent Go/client comparison, live H3,
lockfile/audit, full production security and CasaOS tests. Main unchanged.
