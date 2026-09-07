#!/usr/bin/env bash
# Bring up Dependency-Track and confirm it's actually healthy -- not just
# "docker compose up exited 0", but "the API answers and the UI loads".
# Run from the repo root: ./dashboard/verify.sh
set -euo pipefail

COMPOSE_FILE="$(dirname "$0")/docker-compose.yml"
API_URL="http://localhost:8081"
UI_URL="http://localhost:8080"

echo "== Validating compose file syntax (no network needed) =="
docker compose -f "$COMPOSE_FILE" config >/dev/null
echo "OK: $COMPOSE_FILE is valid"

echo "== Starting Dependency-Track (this pulls ~1-2GB of images on first run) =="
docker compose -f "$COMPOSE_FILE" up -d

echo "== Waiting for the API server to report healthy (can take 2-3 minutes on first boot) =="
for i in $(seq 1 60); do
  if curl -sf "$API_URL/health" >/dev/null 2>&1; then
    echo "OK: API server is healthy at $API_URL"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "FAILED: API server did not become healthy within 5 minutes." >&2
    echo "Check logs: docker compose -f $COMPOSE_FILE logs dtrack-apiserver" >&2
    exit 1
  fi
  sleep 5
done

echo "== Confirming the frontend actually serves the UI =="
if curl -sf "$UI_URL" | grep -qi "dependency-track"; then
  echo "OK: frontend is serving the UI at $UI_URL"
else
  echo "FAILED: frontend did not return the expected page." >&2
  exit 1
fi

cat <<EOF

Dependency-Track is up and verified:
  UI:  $UI_URL   (default login admin/admin -- change it immediately)
  API: $API_URL

Next: upload a build's CycloneDX SBOM (see dashboard/README.md), e.g.:
  curl -X POST "$API_URL/api/v1/bom" \\
    -H "X-Api-Key: <your API key from the UI>" \\
    -F "autoCreate=true" -F "projectName=my-project" -F "projectVersion=dev" \\
    -F "bom=@autosbom-out/sbom.cdx.json"
EOF
