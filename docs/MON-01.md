# MON-01 — Monitoring candidate

NET-01 fix 6cf55f6 and NET-02 245597e both confirmed green.
Separate monitoring.sqlite keeps benchmark schema unchanged. Single scheduler
under existing process ownership lock; shared interactive slot, separate from
benchmark. One check at a time; fixed delay from completion, no catch-up storm,
interrupted claim retried on startup, no fabricated observations. Maximum 20
monitors, 60–86400 second interval. DNS A, TCP, HTTP/HTTPS HEAD, TLS, one
family per monitor. Same target scope and verified transports; no extra
container capabilities. HTTP 2xx/3xx healthy, others failed; DNS requires A
answer, no inference about blocking. Thresholds: end-to-end TCP/HTTP/TLS time
including DNS; DNS request time excludes bootstrap; TLS/HTTPS expiry days.
Unknown internal failures break consecutive streaks without declaring outage.
N consecutive failed/degraded opens one incident; N healthy closes it.
Pause preserves open incident and history, discards in-flight result; cannot
resume while previous check still active. Delete explicitly removes all data.
No monitor edit yet; create/pause/resume/delete. Observations retained up to
30 days and 10k per monitor; closed incidents 180 days; hourly prune also
covers paused monitors. History API capped to 1000, UI last 200, percentage
describes observed successful probes, not continuous uptime. No raw ICMP
monitor, arbitrary webhook or external dashboard yet.

Optional Telegram: put bot token in /data/telegram-token (0600, uid 10001)
and NDC_TELEGRAM_CHAT_ID in environment; restart and opt in per monitor.
Fixed HTTPS endpoint, no redirects, no credentials in API/DB. Incident and
recovery outbox writes atomic with transition, 5 attempts with backoff,
pending expires after 7 days; restart retries sending rows. At-least-once
delivery (duplicates possible if response lost/crash), no exactly-once promise.
No real Telegram message sent in development. In-app incidents always work.
Notifications already queued may send while paused. Delivery status counts
visible. Tests use fake notifier/clock. OS DNS resolution can exceed socket
timeouts; scheduler graceful stop bounded, existing process exits if worker
still alive. No production deployment. Preview 8108 separate data/password.
Outstanding inherited acceptance: lockfile/audit, live H3/DoQ, Go comparison,
full security review and CasaOS verification. Benchmark retention remains open.
