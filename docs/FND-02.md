# FND-02 — persistent jobs (implementation candidate)

Adds a separated probe adapter, validated models, storage, coordinator and
versioned API. SQLite user_version=1 adds jobs/results/profiles and retains
legacy runs unchanged. Backup is created via SQLite backup API before first
migration of an existing history database. Completed jobs are mirrored into
legacy history atomically. Cancelled/interrupted/failed jobs remain available
through v1 with partial results; legacy history remains completed-only.
Queued jobs survive restart; in-flight jobs become interrupted. One process
and one database owner enforced by OS lock. Queue max 8 including active jobs,
one active run and up to two probes concurrently. Cancellation is cooperative
between requests, not guaranteed immediate (including DNS bootstrap).
SSE sends full snapshots with revision IDs, reconnect refreshes current state;
no historical event replay. React uses polling plus cancellation, and profiles
API is available; profile editor and SSE integration are pending. No raw samples,
CSV, scheduler, Alembic or transport correctness changes yet. Additive
migration uses PRAGMA user_version rather than Alembic at this stage.
Existing API remains compatible. Endpoint validation is not an authorization
or SSRF boundary; trusted LAN only pending FND-03.
CI includes deterministic job lifecycle, cancellation, old history and local UDP
tests. FND-01 lockfile and npm audit follow-up remain open; CI generates lockfile
artifact if absent. Preview uses separate 8101 port and data mount. Not merged.
