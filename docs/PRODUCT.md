# Network Diagnostics Center — product specification

Proposed scope. The existing dark graphite/violet design remains recognizable,
with a responsive sidebar, restrained accents, no decorative animation,
compact data tables, keyboard navigation and accessible contrast. Desktop-first
with functional mobile views. Russian/English localization via message keys.

## Modules and useful features
| ID | Module | Features | Priority |
|---|---|---|---|
| UI | Overview | Health cards, last runs, recent failures, active jobs, quick actions, capability notices | P0 |
| DNS-B | DNS Benchmark | UDP/TCP, DoH2/3, DoT/DoQ; strict protocol; cold/warm/both; same IP; IPv4/IPv6; raw samples, charts, filters, comparison, cancellation, saved profiles, JSON/CSV, copy selected AdGuard upstreams | P0 |
| DNS-I | DNS Inspector | Record lookup, multiple resolvers, TTL, RCODE, flags, response comparison, reverse lookup, DNSSEC signal, policy/block detection with caveats, CNAME chain | P1 |
| NET | Connectivity | TCP port checks, ICMP when supported, HTTP reachability/timing, loss/latency variation, IPv4 vs IPv6, local route/egress metadata | P1 |
| TLS | TLS Inspector | Certificate chain, issuer, expiry, SAN, trust/hostname, negotiated TLS/ALPN, handshake timing; safe HTTPS checks | P1 |
| ROUTE | Route Analyzer | Traceroute where supported, hop RTT, missing hop handling, comparison by source; optional ASN/geography later | P2 |
| MON | Monitoring | Scheduled bounded probes, uptime, latency trends, threshold/debounce, incident timeline, notification deduplication, Telegram/webhook optional | P2 |
| AGENT | Distributed testing | Nodes, last seen, health, capability matrix, same profile across sites, side-by-side comparisons, per-node failures | P3 |
| DIAG | Smart Diagnostics | Guided tests, evidence and probable causes (DNS vs TCP vs TLS vs routing), confidence and next actions; no automatic system changes | P3 |
| AGH | AdGuard integration | Optional read-only local API connector, query/latency overview, upstream comparison, copy config only by default | P4 |
| SPEED | Throughput | Explicit opt-in tests to authorized endpoints, size/time limits, no continuous load by default | P4 |

## Primary workflows
1. Launch saved benchmark, watch per-target progress, cancel if needed; sort by
   reliability then P95, compare Cold/Warm and copy a selected upstream set.
2. Enter domain, select resolvers and record type, compare answers and flags
   without treating every legitimate CDN variation as poisoning.
3. Run guided internet diagnosis: gateway (when meaningful), DNS, TCP, TLS, HTTP,
   optional route. Show which layers pass and which were not tested.
4. Schedule a lightweight probe, see latency degradation and alerts with recovery.
5. Compare the same profile at home and on selected private VPS agents;
   label agent source and actual destination IP.
6. Import legacy result JSON and compare historical runs with explicit methodology
   differences; export machine-readable data.

## UI navigation
Overview / DNS Benchmark / DNS Inspector / Connectivity / TLS Inspector /
Routes / Monitoring / Agents / History / Settings. Smart Diagnostics as an
Overview action and dedicated report view. Disabled or unavailable modules are
clearly marked; do not show fabricated live statistics. Mobile: collapsed
sidebar, horizontal tables, essential controls above fold.
DNS result details include IP, protocol, success, mean, median, P95/P99,
variability, phase timings where available, error class, connection status and
sample distribution. Histories include timestamp, profile, source and engine version.
Charts show real samples, no invented data. Do not equate resolver filtering
policy with reliability or DNSSEC with privacy.
