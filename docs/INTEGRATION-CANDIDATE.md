# Integration candidate — acceptance record

## Tested application baseline

9563b7fbdd6a68bdd869facaa7189d2cf1347502, branch work/nip-13-obsidian.
[Build 45792952030](https://github.com/skrskr7799-design/dns-benchmark/actions/runs/45792952030), job 139816306682: success. At inspection main 920bffc6bd7a44da2fb84e881b0da363c2e64b4f, 60 commits ahead, zero behind, 135 changed files. No main merge, tag, or image promotion performed.

- Docker build and locked dependency inventory verified. npm and Python package gates reported zero known findings; not an OS image CVE scan or independent audit.
- Backend tests passed: DNS transports, scope, DNSSEC positive chain, UDP fixture, worker reaping, history, Twin, Scenario, agent mTLS, scheduler, storage, backup/restore and evidence. Browser: 10 smoke, 4 responsive/functional, 1 initial setup; persisted owner after restart passed.
- End-of-run docker stats: CPU 0.40%, memory 121.3 MiB / 768 MiB, 6 PIDs. Single sample, not a peak or soak result.
- Screenshot artifact 15104530258: 198 PNGs. Reviewed top-viewport contact sheets of 19 populated desktop 1536x1024, 18 at 390x844, 18 at 320x800. Cyan/graphite visual consistency, bounded local table/graph scrolling, readable hierarchy. Mobile forms and explanatory text push results below the fold; some full-page captures taken after interaction show sticky desktop navigation lower in the document. No claim of complete per-pixel/full-page review or actual iOS Safari testing. Original hash-verified JPEG archive unavailable in this pass; related reference images are not a substitute for exact archive comparison.

## Scope requiring owner decision before integration

Implemented read-only revision-pinned scenario reports (manual, interval, observed monitor transition), positive A DNSSEC validation from supplied root DNSKEY, opt-in Lab/X-Ray history, loopback UDP fixture and synthetic fault model. Explicitly not completed: independent client DNS leak / authoritative zone, authenticated negative/wildcard DNSSEC proof and anchor rollover, full browser/subresource waterfall, arbitrary scenario actions/notifications, actual namespace/netem packet impairment, full live provider compatibility and encrypted laboratory integration acceptance. Do not claim these features shipped. Proposed integration scope is current implemented features; defer the above only if owner explicitly approves. No new roadmap stages.

## Safe isolated preview

Existing main image on 8099 and /DATA/AppData/dns-benchmark remain untouched.
The green application baseline was built in CI but its publish step was skipped on the work branch. Do not assume a GHCR preview exists. Build from exact commit locally or later use verified published digest. Commands on the owner's Docker host (checkout in separate directory; authenticated clone may be required):

```sh
git clone https://github.com/skrskr7799-design/dns-benchmark.git ndc-acceptance-src
cd ndc-acceptance-src
git checkout --detach 9563b7fbdd6a68bdd869facaa7189d2cf1347502
test "$(git rev-parse HEAD)" = 9563b7fbdd6a68bdd869facaa7189d2cf1347502
docker build -t ndc-acceptance:9563b7f .
docker image inspect ndc-acceptance:9563b7f --format '{{.Id}}'
```

Use the acceptance compose from this documentation commit (not the historical baseline checkout). Save it as compose.acceptance.yaml in a separate directory. Verify /DATA/AppData/dns-benchmark-acceptance does not exist or contains ONLY intended preview data. Create an empty data directory for first-run testing:

```sh
sudo install -d -m 700 -o 10001 -g 10001 /DATA/AppData/dns-benchmark-acceptance
export NDC_PREVIEW_IMAGE=ndc-acceptance:9563b7f
docker compose -f compose.acceptance.yaml config
docker compose -f compose.acceptance.yaml up -d
docker compose -f compose.acceptance.yaml ps
curl -fsS http://127.0.0.1:8113/health
```

Default port binding is loopback, optional Atlas/peer/goodput/lab disabled. For direct phone testing choose the host's trusted LAN address explicitly via NDC_PREVIEW_BIND, restrict ingress at host/network firewall, no WAN exposure. HTTP cookie override is for isolated LAN testing only; normal deployment needs verified HTTPS, exact origin, secure cookies. No copying production data or credentials for first-run. Optional private destinations must be explicitly authorized; default empty CIDRs. After setup, test DNS benchmark, inspector, connectivity, route/TLS, monitors, Twin, scenario/chaos/history. Verify mobile drawer on actual iOS. Record memory/CPU peaks, restarts and sustained load, not merely idle stats. Then test approved real agents on verified HTTPS private overlay; never clone active credentials. Enable opt-in providers only after authorization. Stop preview with docker compose down (do not delete data).

For migration/restore, use a stopped controller and current supported backup CLI; review copied schedules and integrations before starting a restored controller, preferably with outbound traffic blocked. Validate all seven DBs, external configs separately. Do not downgrade migrated databases. Record old image ID/digest and configuration and use pre-upgrade data for rollback. See SERVER-ACCEPTANCE.md.

## Gate status

Automated application baseline green; this documentation/compose commit requires exact CI again. Reference approval, OS image scan, owner-specific migration rehearsal, actual CasaOS/iOS/VPS resource/transport checks and immutable published digest remain open. Owner must explicitly accept limited scope and authorize integration. Main CI and image digest must be verified after merge; no stable version before physical acceptance.
