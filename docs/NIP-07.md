# NIP-07 — Protocol Laboratory

Candidate from 5e3a872, whose CI is running. NIP-05C2a passed 45783493054. Previous open acceptance gates remain.

## Profile and execution
Operator configures NDC_LAB_ENDPOINTS as JSON array of up to eight exact DNS endpoints, default empty (disabled). No arbitrary endpoints from browser, no automatic network traffic. Existing destination scope rules and verified encrypted transport remain mandatory. One or two endpoints, IPv4/IPv6, Cold/Warm, one to six samples per mode, one or two independent endpoint/family lanes, max 24 planned DNS transactions including warmups. Fixed A corpus from benchmark and example.net warmup. One bootstrap IP per lane; transport observations, reuse and individual samples retained. No fallback or retries. Cold means new connection, not a cleared upstream cache. Parallelism is across lanes only.

Owner POST uses existing shared inspection semaphore; worker subprocess with fixed executable/module, no shell, 45s communicate timeout; timeout kills and reaps child and returns no partial data. Process creation/cleanup overhead is outside timeout; exact number attempted on timeout unknown. Child has same network scope and privileges as controller. No persistent history or cancellation endpoint yet. Browser exports result JSON. Comparison only within matched endpoint/family/peer/protocol/corpus with observed cold nonreuse and warm reuse, otherwise null; no ranking between resolvers or link-capacity inference.

Tests: contract/allowlist/limits, timeout handling and real UDP child with exact observed corpus; existing engine has separate TLS/H2/H3/DoQ fixtures. UI initial-state responsive capture. Need integrated encrypted transport experiments with deterministic fixture, browser populated launch test, real timeout kill test, physical resource acceptance and eventual evidence storage. No main merge.
