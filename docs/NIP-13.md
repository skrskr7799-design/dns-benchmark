# NIP-13 — integrated acceptance register

Release gate, not a declaration of completion. No main merge, release tag, image promotion or owner-server changes.

## A — consolidation
Baseline 1d09699, main 920bffc (51 ahead, 0 behind), separate mobile drawer 4a5121d (one divergent commit). Ported drawer Shell, CSS, responsive assertions; new routes retained. Backups cover six known controller databases (history, monitoring, agents, intelligence, twin, scenarios) plus existing managed auth/integration files. Format v1 compatible with legacy subsets. Added restore tests for exact Twin revision and Scenario definition/run replay, legacy manifest, malformed hashes and symlink manifest. External env/TLS/agent configuration separate. CI pending.

## Outstanding scope and evidence
| Gate | Remaining acceptance / functionality |
|---|---|
| NIP-00..04 | physical resource/legacy migration and restore, cross-module scheduler deadlines, owner server and live observations |
| NIP-05 | active machine request saturation, fairness, RTT cancellation/restart quarantine, actual private mTLS two-VPS measurement |
| NIP-06 | controlled authoritative signed/bogus fixture, full trust chain, split DNS and consented client leak design |
| NIP-07 | encrypted end-to-end lab fixtures, actual child timeout/reap, populated browser and durable experiment history |
| NIP-08 | real fixed provider compatibility, resource binding and provider DNS/egress, multi-address and cache/error acceptance |
| NIP-09 | real HTTPS/redirect fixture, optional isolated browser waterfall, durable evidence |
| NIP-10 | graphical topology, populated editor/revision/evidence integration, retention/export and restore |
| NIP-11 | scheduled/incident triggers, durable bounded actions/notifications, cancellation/resume; currently manual read-only DAG |
| NIP-12 | disposable actual packet impairment fixture with isolation and cleanup proof; currently synthetic only |
| NIP-13 | exact candidate full CI, real screenshots vs approved references, mobile Safari, accessibility, dependency/image scan, realistic soak, migration/backup/rollback, documented scope and explicit owner approval |

## Order
B: security/lifecycle correctness, shared budgets and scope. C: complete required gaps or explicitly agree deferred scope. D: populated cross-module workflows and visual review against original references. E: integration candidate and deployment/rollback docs; owner approval before main merge, physical acceptance afterwards. No readiness percentage based on page count or prior CI.
