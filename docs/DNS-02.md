# DNS-02 — benchmark 2.0 candidate

DNS-01 CI passed at 573af10 (run 45587943871), including local transport
fixtures. Independent client / Go comparison and real-network acceptance
are still open; this phase does not claim to close those gates.

## Measurement contract
- Both resolves once per endpoint, then runs Cold and Warm sequentially on
  the same IP, hostname, port and A-query corpus. The warmup uses example.net
  outside the measured corpus and is saved separately. Cold precedes Warm:
  recursive DNS cache state and network conditions can differ, so the delta
  is observational, not a pure measure of handshake savings.
- Each measured slot records sequence, name/type, success, elapsed monotonic
  time, DNS RCODE when available, error, observed protocol and peer, reuse,
  TCP connect and handshake timing where observable. Bootstrap is timed
  separately, shared for Both; failed resolution slots have null elapsed
  time. Current success criterion remains NOERROR with a nonempty answer.
- Failed warmup is explicit; subsequent successful requests can include
  reconnects, shown by reuse counters. Failed and incomplete runs must not
  be interpreted as fully warm measurements. DNS exchange-only phase is
  not separately observable for all adapters, so no synthetic estimate.
- TCP connection and DoT TLS handshake are timed; QUIC handshake recorded
  when new, H2 phase timing currently unknown. Percentiles use nearest rank,
  successes only; jitter legacy field means population standard deviation.
- Samples persisted in existing job_results JSON per completed/cancelled
  series, not incrementally per packet. Abrupt process loss can lose the
  in-flight series; no schema migration. Summary status and SSE omit samples;
  completed legacy history retains summary and run_id for new entries.
- Authenticated v1 samples endpoint supports offset/limit; complete JSON and
  CSV exports (CSV formula-prefix protection). CSV covers measured samples,
  JSON also contains warmup and run metadata. Old records without samples
  display no samples rather than fabricating them. Retention still pending.

## UI
Both selector, series progress, per-query chart and paginated table,
matched Cold/Warm P95 comparison, history baseline comparison with
comparability flags, bootstrap and reuse in summary, selection of successful
endpoints for AdGuard upstream text (UDP URI converted to bare address),
clipboard fallback text and deduplication. Does not modify AdGuard settings.
Selection reflects successful series, not verified filtering policy or
compatibility with every AdGuard version. UI uses CSS charts at this stage;
full chart library and localization still deferred.

## CI / acceptance
Adds local TCP 100 Cold + 100 Warm plus one warmup test: checks one resolution,
same corpus, 101 connections and 201 requests, reuse and phase data. Adds
authenticated Both UDP API test, pagination, summary/raw separation, CSV/JSON.
All prior CI suites retained. New CI pending. Preview port 8104 uses a separate
data directory and owner-password file; never overwrite the active installation.
Known remaining gates: live H3/DoQ validation, comparison against independent
client/Go, frontend lockfile and dependency audit, full security review,
resource/retention policy and real CasaOS preview. Main unchanged.
