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
7. UI visual polish and real responsive screenshots; accessibility review.
8. Explicit owner approval of main merge, immutable release tag and rollback.

This pass does not satisfy these gates yet. No deployment, public exposure,
stable tag or main merge. Preview port 8113, isolated directory.
