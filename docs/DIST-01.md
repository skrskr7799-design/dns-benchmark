# DIST-01 — Agent contract candidate

MON-01 4974be5 verified green (45593307552). This slice adds the controller
API and Python outbound agent; UI and multi-site comparison are DIST-02.
Canonical engine remains provisionally Python, shared imports from
backend.ndc.probes.dns. No independent Go/client performance comparison yet.

## Contract
Owner API (session/CSRF): GET /api/v1/agents, POST /invite (name/location),
POST /{id}/rotate, /{id}/revoke, /{id}/tasks, GET /tasks/{id},
POST /tasks/{id}/cancel (all under /api/v1/agents).
Invite expires after 10 minutes and is single use; resulting random 256-bit
credential stored hashed at controller, stored in mode 0600 agent state.
Rotation invalidates credential and current work. Machine POST /machine/enroll,
 /machine/poll, /machine/heartbeat, /machine/results/{id} use separate
bounded request/rate limits, bearer identity (except one-use enrollment),
no cookie access. Owner and machine routes do not share auth privileges.
Protocol v1, engine python-dns02, container vantage; location is owner label,
not geolocation. Agent claims are not attestation; trust enrolled machines.

Maximum 32 agent records (including revoked/expired invitations), four active
tasks per agent; 10k task history cap, completed tasks expire after 30 days,
audit 180 days, queued expiry 24h. Cleanup occurs during API/agent activity.
Only one endpoint, 1–10 requests per mode, one worker, DNS benchmark only.
Local exact endpoint allowlist plus existing resolved IP scope; no shell tasks,
arbitrary payloads or privileged containers. Owner must authorize targets.
Leases 300s, no automatic reassignment, expired becomes interrupted; one
active lease per agent. Poll every 5s, heartbeat during task every 10s,
last seen stale after 45s. Revocation/cancellation detected cooperatively,
cannot interrupt an in-flight socket/system resolver instantly. Agent local
deadline 240s cooperative. No lease extension; late result refused.
Results matched to agent/lease/task, sample count, query corpus, mode and
success count; exact replay idempotent, conflicting replay rejected. Remote
data trusted for reported timing, no independent attestation or full server
recalculation of summary statistics. Max 128 KiB request body. SQLite separate
agents.sqlite; history and monitoring databases unchanged. Persistent one-item
spool written before execution and before upload; retries with backoff, crash
during execution reports failure, never re-runs a started lease. Expired or
rejected results discarded with status log. Enrollment response loss requires
owner rotation. No automatic enrollment or remote configuration.

## Private deployment
Controller must be reachable over verified HTTPS (e.g. reverse proxy with a
certificate valid for its NetBird DNS name). Restrict listener/firewall to
private network; no public exposure. The preview HTTP port 8109 is owner UI
only, not suitable for agent credentials. HTTP loopback is CI-only explicit opt-in.
Create owner-password as before. Generate invite through authenticated owner
API, save token to ./agent-data/enrollment-token, and create
./agent-data/allowed-endpoints.json (JSON array of exact authorized endpoints).
Directory owned by uid 10001 mode 0700; files mode 0600. Set
NDC_CONTROLLER_URL to HTTPS origin. For private CA mount a trusted CA file
and set NDC_AGENT_CA_FILE to its container path. Optional NDC_ALLOWED_CIDRS
must be explicitly configured on each agent. Use deploy/compose.agent.yaml,
no published agent port, cap_drop ALL, read-only root. For rotation stop
agent, rotate on controller, remove identity.json and old spool.json, write
new enrollment-token and restart. Revoke through owner API.
No real VPS deployment or credentials created here. Main unchanged.
CI includes lifecycle, isolation, expiry, spool and real loopback API/agent
tests. Final CI pending. DIST-02 adds UI, two-node comparison and offline
scenario acceptance. Existing lockfile/audit, independent measurement and
production security/CasaOS acceptance remain open.

## Current installation (supersedes historical preview)
See [AGENT-DEPLOYMENT.md](AGENT-DEPLOYMENT.md) and the Agents wizard. Current Compose uses edge / protocol 2, with explicit overrides for legacy compatibility or pinned images. Controller HTTP healthcheck is disabled for agent containers. Online heartbeat is the operational indicator. Historical preview tags above are not current deployment instructions.
