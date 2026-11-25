# REL-01 — release candidate, pass 1

INT-01 75bdd8f, run 45596952664, verified successful (9 browser tests,
all preceding backend suites). Not a production acceptance.

## Findings and changes

- README described unauthenticated v0.2; rewritten for current architecture.
- Unbounded job/profile records: new jobs capped at 500 (configurable 10–5000),
  profiles at 100. Explicit terminal-run deletion removes its modern linked
  history entry and cascades samples. No automatic data deletion; old v0.2
  rows preserved. UI paginates modern run index and confirms deletion.
  Existing databases above cap reject new jobs until owner exports/deletes.
  SQLite does not automatically shrink files; no byte/disk quota yet.
- Owner password file rejects symlinks, nonregular files and group/world
  access; mode 0600 required. CSRF comparison uses bytes. Request body limit
  retained, now 10-second receive deadline, static response security headers.
  SSE capped to eight streams. Global rate limits are not per-client quotas.
- Docker healthcheck, read-only root and resource caps in RC compose.
  768 MiB / 128 PIDs are provisional, not load-tested. No privileged sockets.
- Offline backup/restore command with SQLite backup API, integrity and
  foreign key checks, SHA-256 manifest and refusal to overwrite an existing
  target. Same ownership lock prevents running-controller backups. Backups
  contain secrets and must be stored privately/encrypted; checksums detect
  accidental corruption, not malicious manifest changes. No automatic
  upload or deletion. Includes three controller DBs and known secret files,
  not environment, CA files, reverse proxy configs or agent local data.
- CI records npm and pip audit output for review, not yet a release-blocking
  automatic dependency gate. Last green log reported 2 high npm advisories;
  causes/fixes pending audit output. Frontend lockfile artifact downloaded
  from that successful run, not yet committed. Python transitive lock and
  base image digests pending. No force audit fix.
- Additional release tests: cap, explicit deletion, backup lock and restore,
  checksum rejection, secret permissions, CSRF, API size limit.

## Offline backup / restore

Stop the controller in CasaOS. Keep original data intact; create a separate
backup destination parent owned by uid 10001. Example using exact tested
image (replace IMAGE with immutable sha tag or verified digest):
```sh
docker run --rm --network none --cap-drop ALL \
  -v /DATA/AppData/dns-benchmark:/data \
  -v /DATA/AppData/ndc-backups:/backups \
  IMAGE python -m backend.ndc.backup backup /data /backups/pre-upgrade
```
Use a fresh destination name each time. Test restore to new directory:
```sh
docker run --rm --network none --cap-drop ALL \
  -v /DATA/AppData/ndc-backups:/backups:ro \
  -v /DATA/AppData/ndc-restore:/restore \
  IMAGE python -m backend.ndc.backup restore /backups/pre-upgrade /restore/data
```
Backup destination and restore parent must already be writable by uid
10001; restore child must not exist. Keep backups off the host as well.
For rollback stop new controller; start prior known-good image against
original untouched data or a verified pre-upgrade restore, never blindly
downgrade a newer database. Do not copy agent identities/spools between
hosts. Revoke/rotate restored agent credentials if backup predates changes.

## Release gates (all required before stable tag)

1. RC CI green; inspect actual npm/pip reports, fix or explicitly document
   applicable advisories and commit reproducible locks; base image pinning.
2. Security review: scope/egress firewall, reverse proxy, secrets, machine
   authentication, memory/disk/CPU limits, slow-drip request deadlines,
   revocation and queue bounds; no claim of full independent audit.
3. Restore drill including legacy v0.2 history, monitor and agent DBs.
4. CasaOS isolated preview, real H2/H3/DoT/DoQ, IPv4/v6, independent client
   and Go comparison; measure resource use, validate cancellation/timeouts.
5. Two real VPS through verified HTTPS private overlay; offline/revoke tests.
6. Live AdGuard/Telegram only with owner authorization and credentials.
7. UI implementation must follow the owner-approved [Obsidian Signature](OBSIDIAN-SIGNATURE.md) reference contract; real responsive screenshots and accessibility review.
8. Explicit owner approval of main merge, immutable release tag and rollback.

This pass does not satisfy these gates yet. No deployment, public exposure,
stable tag or main merge. Preview port 8113, isolated directory.

## REL-01B — dependency remediation candidate

Baseline run 45598045033 at 925276a passed functional CI but audit reports were informational. npm: two high entries (direct @playwright/test and transitive playwright; one root advisory GHSA-7mvr-c777-76hp). Python: dnspython 2.7.0 (2 distinct IDs), pip 25.0.1 (6), Starlette 0.46.2 (7, deduplicated by ID). Some findings require specific features/platforms; DNS wire parser and static response issues are particularly relevant. Upgrade Playwright to audit-recommended 1.65.1, dnspython to 2.9.2, FastAPI to 0.165.0 (upstream requires Starlette >=1.6.0), pip to 26.2.0. DNS and integrations migrate to httpx2 as required by dnspython; agent retains explicit httpx 0.28.1. Existing wire fixtures are mandatory. Pin previously tested base image digests; OS-level image CVE scanning still pending. Guard reads ASGI path, validates Host and method, rejects static Range (not needed for web assets). Audit actual runtime path from isolated auditor venv; record resolved versions and lock JSON; zero known package advisories required before publishing preview. Lock generation remains temporary until new lock can be retrieved and committed; Python version snapshot not a hash lock. CI pending; do not declare resolved until reports and transport/API/browser checks succeed. Full design-map retrieval incomplete; see OBSIDIAN-SIGNATURE.md. No UI redesign in this pass.

## REL-01C — bounded execution and reproducible dependency candidate

REL-01B b109e15 run 45600428806 confirmed green, package security gate zero known findings. Exact npm lock JSON and 33-package Python inventory recovered from its log, committed. npm ci requires lock; pip constraints plus CI diff against actual freeze; no hash-locked Python wheels yet. Base image digests already fixed. SQLite claim now atomically refuses concurrent running/cancelling jobs; writes to terminal jobs refused; worker failure signals other workers cooperatively. SSE revision-only read on unchanged snapshots, shared AnyIO thread pool; full snapshot still decoded on change. Fixed-purpose subprocess isolates optional integrations: 30s AdGuard, 12s download wall-clock subprocess budget (process launch overhead excluded), kills/reaps child on timeout, HTTP 504, no arbitrary commands or credentials in argv. Existing soft budgets preserved, no partial result on forced termination. Other DNS/system resolver deadlines still cooperative or socket-level; no claim of globally hard deadline. CI now runs read-only container, 768 MiB, 128 PIDs, no caps, bounded test tmpfs; exercises concurrent 24 submissions/12 claims, stale revision, terminal writes and real slow HTTP worker. Resource snapshot is diagnostic, not peak-load proof. Preview constraints unchanged; no deployment. OS image audit, independent DNS transport comparison, real CasaOS/VPS load and restoration remain release gates. Design unchanged. New CI pending.
