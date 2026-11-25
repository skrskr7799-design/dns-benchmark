# DNS-01 — transport correctness candidate

FND-03 CI confirmed green at a4edaf5 (run 45586442403).
Python remains the provisional canonical engine, because it can preserve
existing deployment and provide a reusable QUIC session with aioquic.
This is not a measured performance comparison against Go. The planned
independent-client / Go comparison and real-network validation remain open;
do not mark DNS-01 accepted on build success alone.

## Implementation
- aioquic pinned to 1.3.0. One explicitly managed connection per warm H3/DoQ
  session, new connection per cold sample, fresh bidirectional stream per query.
- QUIC certificate and hostname verification; pinned IP/port, no accepting
  packets from alternate peer addresses, explicit ALPN h3/doq, no fallback.
- DoQ framing and zero DNS message ID; DNS response checked against question.
- H2 retains pinned transport and verifies negotiated HTTP/2; observes actual
  peer when httpcore exposes it and tracks stream object identity for reuse.
- DoT/TCP retain socket for warm tests, peer observed via getpeername.
  DNS TCP added as tcp://IP:port. UDP has no connection reuse metric.
- Timer excludes resource teardown; warmup error recorded separately, reuse
  counts identify measured samples that actually reused sessions or reconnected.
  Results retain old fields and add engine/protocols/peer_ips/reuse/warmup_error.
  Handshake duration is collected internally for QUIC but not yet exported.
- Target scope remains enforced. NDC_CA_FILE can explicitly specify trusted CA
  bundle; certificate verification is not disabled.
- Cold/warm both-mode, raw samples, independent bootstrap timing and full
  latency breakdown are DNS-02 work. Warmup failure is visible but later
  reconnects can still be included and marked non-reused. No claim that warm
  DNS transport implies cached DNS answers.

## Validation
Local fixture tests exercise actual H2/H3/DoQ/DoT/TCP exchanges and count
connections on the server side, test hostname rejection, and warmup errors.
Existing CI includes UDP, job lifecycle, security and browser tests.
CI results for this branch pending at authoring. No public-network measurement
was performed here. IPv6 live and failure/timeout edge cases need further
coverage; H3 performance over user's network not established. Go comparison
and independent client verification remain acceptance blockers.
Preview image preview-dns-01 uses port 8103 and separate data directory.
Owner password file required; trusted LAN HTTP preview only. Do not deploy
publicly. Main and installed version unchanged. Dependency lockfile/audit
remain open from FND-01.
