#!/usr/bin/env bash
# Verify a cosign signature on an SBOM or drift baseline.
#
# Keyless verification (matches sign_artifact.sh keyless from GitHub Actions):
#   ./verify_artifact.sh keyless sbom.cdx.json \
#     "https://github.com/OWNER/REPO/.github/workflows/sbom-pipeline.yml@refs/heads/main"
#
# Key verification:
#   ./verify_artifact.sh key baseline.json
set -euo pipefail

MODE="${1:?usage: verify_artifact.sh keyless|key <file> [identity]}"
FILE="${2:?usage: verify_artifact.sh keyless|key <file> [identity]}"

command -v cosign >/dev/null || { echo "error: cosign not installed" >&2; exit 1; }

case "$MODE" in
  keyless)
    IDENTITY="${3:?keyless mode needs the expected certificate identity}"
    cosign verify-blob \
      --signature "${FILE}.sig" \
      --certificate "${FILE}.pem" \
      --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "$FILE"
    ;;
  key)
    cosign verify-blob --key cosign.pub --signature "${FILE}.sig" "$FILE"
    ;;
  *)
    echo "error: mode must be 'keyless' or 'key'" >&2
    exit 2
    ;;
esac
echo "VERIFIED: $FILE"
