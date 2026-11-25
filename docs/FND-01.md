# FND-01 — React foundation

Implemented UI draft: React/TypeScript, TanStack Query/Router, overview,
benchmark and history screens, responsive navigation, sortable results,
real summary metrics, simple CSS bars, browser-local saved endpoint list,
legacy JSON export, same-origin API. Planned modules are labelled as such.
No changes to DNS measurement semantics or SQLite format.

This first slice uses plain CSS and polling deliberately; Tailwind/ECharts,
localization, SSE, durable profiles and cancellation are subsequent work.
The legacy engine is explicitly labelled. Dependency lockfile must be generated
and committed before acceptance: npm registry unavailable in authoring runtime.
CI generates a lockfile artifact for review; Docker consumes it when available.
Browser test covers real API reads and mocked start/results/export; it does not
prove actual protocol correctness. Migration and live preview acceptance pending.

Preview only: create /DATA/AppData/dns-benchmark-preview owned by uid 10001,
import deploy/compose.preview.yaml after CI publishes preview-fnd-01,
then open port 8100 on trusted LAN. The old 8099 installation and data are untouched.
Preview remains unauthenticated; do not expose to internet. Do not copy live
SQLite while writes are occurring; use a consistent backup for history testing.
Main must not merge until CI, lockfile and preview verification are accepted.
