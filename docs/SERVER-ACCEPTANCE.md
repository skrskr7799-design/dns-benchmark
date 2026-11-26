# Server acceptance and integration gate

Owner intent: finish development, integrate into main, then test on the owner's server. Current working branch remains separate; no merge now. Release version and exact scope to be agreed at final acceptance; planned trains in NETWORK-INTELLIGENCE-ROADMAP.md are not published releases.

## Before merge
- Review remaining roadmap modules and explicit blockers; do not mark partial stages complete on fixture success.
- Audit exact integration HEAD, including the separately tested mobile drawer branch; reconcile any divergent changes without silently dropping work.
- Full CI: unit, real controlled transports, scheduler/replay, all DB migrations, browser matrices, dependency gates; inspect artifacts at desktop/mobile widths. Run image OS security scan and record exceptions.
- Check shared scheduler contention, deadlines, shutdown, bounded storage, and physical CPU/RAM/disk budgets under realistic load. Distinguish sample/end-of-run numbers from peaks.
- Validate migrations from the owner's installed version on a copied data directory; verify login, prior history, agents, monitors and snapshots. Never downgrade an upgraded SQLite schema in place.
- Prepare versioned image pinned by digest, compose/settings compatibility notes, changelog, and documented backup/restore. No automatic release on an unfinished branch.
- Explicit owner approval of merge candidate and its exact scope; main CI and image publication must be verified again.

## On owner server
1. Record existing container image digest, config/mounts, data owner/permissions and current version. Keep existing deployment unchanged.
2. Stop existing controller for consistent backup using its supported offline backup command. Verify manifest and checksums; include history.sqlite, monitoring.sqlite, agents.sqlite, intelligence.sqlite, twin.sqlite, scenarios.sqlite and experiments.sqlite if present, plus app-managed auth/integration files. Keep credentials private. Save external env files, TLS/CA assets and configuration separately; backup CLI does not include them.
3. Restore into a NEW data directory for preview with separate port and isolated agent/test configuration. Do not point two controllers at the same data or allow duplicate notification/probe activity from copied active schedules; use isolated test data or disable outbound access until reviewed.
4. Owner checks initial login and iOS drawer, DNS benchmark and real transports, monitoring/maintenance, Observatory, Time Machine, agent enrollment and distributed tests, and remaining implemented modules. Check actual CPU/RAM/storage/network behavior. Record exact image digest and test outcomes. CI alone does not establish server readiness.
5. Promote only after explicit acceptance. Keep the prior image/config and pre-upgrade backup. Rollback: stop upgraded controller, restore original compatible data into a separate directory, use old image/config, then verify health/login/history. Data written after backup will not automatically survive rollback; export/reconcile as appropriate. Do not attach a newer migrated DB to old code.

No server access or deployment performed in this pass. This is an acceptance policy, not a claim that all checks are completed.

## Consolidation baseline
The NIP-11/12 candidate 1d09699 is 51 commits ahead of main 920bffc with no main-only commits at verification. Mobile drawer 4a5121d diverged by one commit; its Shell, CSS and responsive assertions have been ported without replacing newer routes. Candidate CI and actual iOS Safari remain to be verified. Backup format v1 remains additive and compatible with older manifests; new database files are included when present. For a new deployment require all seven controller DBs in the verified backup manifest; older versions may legitimately lack some. Never use an old backup executable to back up newer data. See NIP-13.md for outstanding acceptance gates.

## Integration candidate record
See [INTEGRATION-CANDIDATE.md](INTEGRATION-CANDIDATE.md) for the exact successful application baseline, measured CI snapshot, screenshot review, current scope and isolated preview commands. New compose uses local SHA-tagged build or explicitly supplied image, loopback port 8113 by default and separate data. No merge or publication implied. Exact original archive, OS image scan and physical acceptance remain open.
