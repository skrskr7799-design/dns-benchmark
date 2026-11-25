# FND-03 — security foundation (implementation candidate)

Single owner, password supplied through /data/owner-password (chmod 600,
uid 10001), or NDC_OWNER_PASSWORD for controlled deployments. No default
password and no unauthenticated first-visitor setup. Startup refuses missing
or weak-length password (minimum 16 characters; use a randomly generated
secret). Password verifier derived with scrypt at startup, session IDs random
and stored hashed in memory, 12-hour expiry, maximum 32 sessions, revoked
on restart/logout. Login globally limited to 10 attempts/minute, writes
60/minute. No username required. Cookie Secure by default; only set
NDC_SECURE_COOKIE=0 for explicitly trusted HTTP LAN preview. For HTTPS reverse
proxy configure NDC_ORIGIN to the exact external origin. No CORS. API reads
and writes including legacy and SSE authenticated; mutation CSRF token and
origin checks. Public health and static UI only. Single-process deployment.
Owner password rotation: replace file, restart, all sessions invalidated.

Destination validation at resolution, public unicast by default; local
private/loopback/CGNAT only with explicit NDC_ALLOWED_CIDRS. Hard deny
metadata, link-local, multicast and transition ranges listed in scope.py.
DoH2 uses the pinned dnspython 2.7 transport (private API; version pinned)
with TLS verification, no redirects/proxy; DoH3 uses explicit IP and verified
hostname, legacy H3 reuse remains unsupported. DoQ and DoT explicit IP and
certificate verification. No automatic remediation, raw sockets, shell,
or privilege escalation. This is application-level control, not a firewall:
use container/host egress rules for high-assurance isolation. Legacy DNS
bootstrap uses system resolver, and DNS/TLS/QUIC transport validation has
further fixture work planned in DNS-01. No public deployment until full audit.
Sensitive query parameters forbidden for resolver endpoints at model validation.
Existing historical data not modified. Authentication applies to new UI and API;
old standalone HTML fallback is disabled to avoid unprotected legacy behavior.
CI tests auth, CSRF, login rate limit, scope, rebinding pinning and legacy history.
Production data and main unchanged. Preview port 8102, separate mount, HTTP
only explicitly opted in. Lockfile and dependency audit remain open.
