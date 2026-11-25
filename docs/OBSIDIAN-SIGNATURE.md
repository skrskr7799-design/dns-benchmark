# Obsidian Signature — approved visual contract

Owner approved eight reference images on 2026-11-25. This supersedes the
previous graphite/violet alpha design direction. REL-01D must reproduce
these references, not invent an alternative theme. Reference layouts are
design intent; their displayed values, status and features are not evidence
of actual functionality. The application remains a responsive web app, not
a native Windows desktop app; omit artificial window chrome.

## Reference manifest (original JPEG bytes, SHA-256)

| File in reference archive | Dimensions | SHA-256 |
|---|---|---|
| 01-dashboard.jpeg | 1536×961 | 4ac7f2cfd3d58680bbaf7a295e4245814bc667c6468b6d0df4217f89f4b1a003 |
| 02-route-analyzer.jpeg | 1536×864 | c8e1a3e9f910082e75114093b34934a24a4401d0dc8973f1fe57a429d4cd88ab |
| 03-providers.jpeg | 1536×1024 | 6c2b52b6b00cde0ac365ee496cf72d0c0753a903efae53907fc7e3fcc6e30f59 |
| 04-dns-inspector.jpeg | 1536×983 | 88a9bc4531a26be94a892af5674a04001605485c78d92be620485eddcd9331b1 |
| 05-dns-benchmark.jpeg | 1536×1024 | 865c8c9e9015806bae6474b8da6deb89e6ce30a8a4ec6a9512419f23475bd6af |
| 06-diagnostics.jpeg | 1536×1024 | 6c6eb37fe46e70566421bb1291091ef526883cb288c58644f03923827410992c |
| 07-history.jpeg | 1536×1024 | 2dd3326b39963e61864b2ec07534828630065a37873253375d87a5ac5288b1b8 |
| 08-design-system.jpeg | 1536×1024 | 1c457c8f434d775ca668fa79888dc89fe1c689d4bcb740819a5311ae4f6bf365 |

Original images are packaged separately as obsidian-signature-references.zip;
manifest is committed here. Do not use generated substitutes.

## Identity

DNS Benchmark / NETWORK INTELLIGENCE. Geometric cyan wireframe cube with
an internal cube/connected paths (references 02–08 are the primary mark).
Reference 01 has a layered alternate mark; use the cube consistently.
Deep blue-black graphite, restrained cool surfaces, cyan/turquoise primary
accent, muted near-white text; green success, amber warning, red failure.
Violet and blue only as secondary chart series or record categories.
No purple-dominant theme, rainbow gradients, frosted glass excess, or
large rounded floating cards. Fine circuit/network paths as restrained
header/sidebar decoration, never behind dense text. SVG line icons with
consistent stroke, not emoji. Compact technical typography, tabular numbers,
monospace where useful for IPs and fingerprints. Preserve Cyrillic support.

Proposed implementation tokens (approximate visual matches, not sampled
authoring values): background #0B1319, sidebar #0D171E, surface #111E26,
raised #172630, border #293A44, text #DCE7ED, muted #9AADB8, accent #69DDE2,
accent dark #1D6570, success #4ED5A1, warning #E6BB67, danger #E37883.
Cards 8–10px radius, 1px border, compact 14–18px padding, 12–16px gaps;
desktop sidebar ~250–280px at 1536, header/title ~30–34px.
Primary buttons cyan with dark text. Active nav dark teal, fine cyan left
edge. All interactive focus, hover, disabled states must be discernible.

## Screen contracts

- Overview (01): KPI strip, ranked DNS results left, latency and compact
  route right, record inspector/history/analytics below. Only real measured
  values; absent telemetry clearly marked. No invented network health score,
  packet loss, ISP, geolocation or continuous chart.
- Benchmark (05): profile/actions, progress, KPI cards, response chart and
  distribution, compact sortable results with protocol/percentiles/reliability.
  Keep existing run/cancel, profiles, samples, exports and warm/cold semantics.
  No fake pause or ETA. Use available timestamps/samples, not invented trends.
- Providers (03): catalog, protocol filtering, selection and comparison.
  Catalog must originate in real resolver data; no fictional country/privacy
  rankings or unsupported capabilities. Dedicated feature is a gap, not
  completed by styling.
- Inspector (04): query bar, result metrics, grouped record panels, resolver
  details, raw response. Current API selects one record type per request;
  multi-type lookup/tree/trace require separate implementation. AD flag is
  not independent DNSSEC validation.
- Routes (02): observed hop topology, per-hop table, RTT plot, selected node
  details. Preserve timeouts/gaps and ECMP uncertainty; no fabricated ASN,
  geography, multi-target branches, packet loss or summed hop RTT.
- Diagnostics (06): stepwise evidence, summary, recommendations, phase
  timings. No fake live progress, composite score, packet loss or routing
  evidence if not measured. Keep observed versus possible.
- History (07): session selection, trends and comparison, exports, percentile
  data with clear aggregation/period semantics. Keep explicit deletion and
  legacy history. No synthetic 30-day history.
- Design system (08): unified shell, grouped navigation Workspace / Monitoring
  / System, settings concept and visual signature. Connectivity, TLS,
  Monitoring, Agents, Integrations, authentication share the same components.
  Settings controls must reflect actually implemented configuration; no inert
  switches or fictitious versions.

## Implementation and acceptance

REL-01D: shared tokens, logo/icon set, app shell and auth; then rebuild each
screen composition against references; then responsive adaptation and real
data verification. No API/security regression. Do not replace working
features with mockups or hide unsupported metrics behind sample data.
Desktop visual comparison at 1536×1024 and 1536×864, tablet 768×1024,
mobile 390×844 and 320px width. Test empty/loading/error/partial/full/running
states, keyboard focus, contrast, table overflow within its own container,
long IPs, domains and certificate data. Capture actual Playwright screenshots
with deterministic fixtures for visual review; clearly distinguish fixture
screenshots from live data. Keep screenshots/reference comparisons with
release acceptance evidence. Obtain owner approval for significant deviations.

This commit freezes the design only, does not claim implementation or visual
acceptance. Existing technical audit remains in progress. No main merge.
