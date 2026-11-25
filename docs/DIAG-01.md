# DIAG-01 — evidence-based diagnostics candidate

DIST-02 CI verified green at af130b0, run 45595461018.
Authenticated POST /api/v1/diagnostics shares the interactive semaphore.
Uses existing scoped TCP/TLS/HTTP probe, optionally explicit DNS inspection
with up to two user-selected resolvers (name disclosed only when chosen).
One observation per selected family, IPv4/IPv6/both, TCP/TLS/HTTP/HTTPS,
HEAD only, no redirects, no automatic repair. Resolver transport family
separate from target address family. IP literals skip DNS comparison.
Scope rejection skips extra queries. No new privileges or external AI.
Thresholds are configurable illustrative defaults, not universal norms.
Rule version 1, observed vs possible findings, machine-readable evidence,
recommended manual checks, original probes, explicit limitations and JSON
export. A failed stage is not proof of root cause. DNS difference is not
proof of tampering. HTTP status is separate from successful exchange.
IPv4/IPv6 asymmetry is observed connectivity only. No automatic traceroute,
monitor correlation, remote-agent diagnoses, or persisted reports yet.
System resolver timeout remains OS dependent. UI route Smart Diagnostics.
CI includes deterministic rules, real local HTTP API and browser smoke.
Preview 8111 separate data/password. No main merge or live deployment.
Inherited open gates: Go/independent transport comparison, live H3,
dependency audit/lockfile, security review and CasaOS acceptance.
