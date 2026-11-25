# NET-01 — Connectivity and TLS Inspector

DNS-03 CI passed at 88483eb (run 45590426530). Adds authenticated
POST /api/v1/network/connectivity and /api/v1/network/tls. Interactive DNS,
connectivity and TLS share one nonblocking semaphore; benchmark may run
independently. Global write rate limit and target scope apply. Only authorized
targets should be probed. No shell commands, scanning, raw sockets or redirects.

Connectivity: TCP connect, HTTP/HTTPS HEAD, Linux unprivileged ICMP echo.
One chosen scoped IP per family per series, explicit IPv4, IPv6 or both,
up to five attempts, source/peer metadata from the container. Separate
system resolution, TCP, TLS, first byte and HTTP headers timing where
observed; TTFB and headers are cumulative from HTTP request start, not
additive. Total for repeated attempts excludes the shared resolution.
HTTP status is a received response, not an application health guarantee.
No body download, credentials, queries or redirects, 32 KiB header cap,
absolute header-read deadline. Only HTTP/1.1 for HTTP timing; TLS inspector
offers h2 and http/1.1 ALPN. Three-second socket timeout per stage; OS
resolution is not guaranteed bounded. ICMP uses kernel datagram ping
sockets and checks reply type/sequence/random payload; requires kernel
ping_group_range and network support. Capability means socket creation
only, not reachability. Unavailable is not zero loss. No NET_RAW added.
ICMP loss percentage is the share of sent probes without matching replies;
not proof of link loss. TCP variation is population standard deviation
of successful connect timings; failures are separate, not ICMP loss.

TLS: trusted context verifies certificate chain and hostname; no insecure
retry. Leaf subject/issuer/SAN, validity, remaining days, serial, SHA-256,
negotiated TLS/cipher/ALPN. Certificate details only after successful
verification. Full verified chain is returned only on runtimes with
public get_verified_chain API (Python 3.12 base currently lacks it).
No OCSP/CRL revocation, protocol enumeration or untrusted certificate
extraction. Explicit CA bundle supported via NDC_CA_FILE.

React adds two routes, tables, timings, per-family results, JSON exports.
Immediate interactive results only; no persistence until monitoring.
CI adds deterministic loopback fixtures and UI coverage. Preview port
8106 with separate data and owner-password. Main unchanged.
Inherited open gates: lockfile/audit, live H3/DoQ, independent client/Go,
retention, security review, CasaOS acceptance.
