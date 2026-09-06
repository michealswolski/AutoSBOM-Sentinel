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
curl -LO https://dependencytrack.org/docker-compose.yml
docker compose up -d
# UI on http://localhost:8080 (initial login admin/admin, change it)
```

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
output was visually verified in light mode. The Dependency-Track wiring
above is standard, documented usage but has **not** been stood up and
verified from inside this repository's development environment — do that
once locally before demoing it. The 60-90 second demo video is not yet
recorded.
