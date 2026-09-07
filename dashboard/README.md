# Visualization Dashboard (Priority Addition B)

Two halves:

1. **Per-build shareable report** — implemented in
   `autosbom/dashboard/html_report.py` and rendered by `autosbom report`:
   a single self-contained HTML file with the attack-surface heatmap
   (components grouped by exposure category: Bluetooth / network-facing /
   CAN / OTA / diagnostics / crypto / base-system), the raw-vs-post-VEX
   noise-reduction chart, the drift timeline, and the baseline
   signature-verification indicator. Only *human-approved* VEX statements
   count as suppression in these charts.

2. **Live backend — OWASP Dependency-Track** (run it yourself; config below).
   It natively ingests CycloneDX and VEX, renders dependency graphs, and
   tracks risk over time. The CI pipeline uploads each build's SBOM when
   `DTRACK_URL` / `DTRACK_API_KEY` are configured.

## Running Dependency-Track locally

```sh
./dashboard/verify.sh
```

This validates `dashboard/docker-compose.yml`, brings Dependency-Track up,
and polls until the API reports healthy and the frontend actually serves
the UI — not just "docker compose exited 0". On success: UI at
http://localhost:8080 (initial login admin/admin — change it immediately),
API at http://localhost:8081.

Upload a build manually:

```sh
curl -X POST "http://localhost:8081/api/v1/bom" \
  -H "X-Api-Key: $DT_API_KEY" \
  -F "autoCreate=true" \
  -F "projectName=pi5-ivi-demo" -F "projectVersion=dev" \
  -F "bom=@autosbom-out/sbom.cdx.json"
```

Then upload the exported OpenVEX (`autosbom vex export ...`) against the same
project so suppressions carry into the live view.

## Status / honesty note

The HTML report generator is implemented and unit-tested, and rendered
output was visually verified in light mode.

The Dependency-Track deployment (`docker-compose.yml` + `verify.sh`) was
validated as far as this development environment's network policy allows:
the compose file's syntax/schema was confirmed valid (`docker compose
config`), and `docker compose up` was run for real — it correctly resolved
and began pulling both official images before the container image layer
download was blocked by this sandbox's organizational egress policy
(`production.cloudfront.docker.com` — Docker Hub's CDN — is not on this
session's allowed-hosts list; confirmed via the proxy's own status
endpoint, which explicitly says to report such a block rather than route
around it). **The actual running service has not been verified end-to-end**
— run `./dashboard/verify.sh` on a machine with normal internet access to
do that; it will report clearly if anything about the setup itself is
wrong. The 60-90 second demo video is not yet recorded.
