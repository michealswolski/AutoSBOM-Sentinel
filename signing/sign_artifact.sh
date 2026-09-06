#!/usr/bin/env bash
# Sign an SBOM or drift baseline with Sigstore cosign.
#
# Keyless mode (preferred, run from CI with OIDC — e.g. GitHub Actions):
#   ./sign_artifact.sh keyless path/to/sbom.cdx.json
#   -> writes sbom.cdx.json.sig and sbom.cdx.json.pem, logs to Rekor
#
# Key mode (local development / air-gapped Pi):
#   cosign generate-key-pair            # once; keep cosign.key OFF the device
#   ./sign_artifact.sh key path/to/baseline.json
#   -> writes baseline.json.sig
set -euo pipefail

MODE="${1:?usage: sign_artifact.sh keyless|key <file>}"
FILE="${2:?usage: sign_artifact.sh keyless|key <file>}"

command -v cosign >/dev/null || {
  echo "error: cosign not installed (https://docs.sigstore.dev/cosign/installation/)" >&2
  exit 1
}

case "$MODE" in
  keyless)
    # In GitHub Actions, set `permissions: id-token: write` on the job; the
    # signature is transparency-logged in Rekor and the short-lived Fulcio
    # certificate is written alongside for offline verification.
    COSIGN_YES=true cosign sign-blob \
      --output-signature "${FILE}.sig" \
      --output-certificate "${FILE}.pem" \
      "$FILE"
    echo "signed (keyless): ${FILE}.sig + ${FILE}.pem (Rekor-logged)"
    ;;
  key)
    cosign sign-blob --key cosign.key \
      --output-signature "${FILE}.sig" \
      "$FILE"
    echo "signed (key): ${FILE}.sig"
    ;;
  *)
    echo "error: mode must be 'keyless' or 'key'" >&2
    exit 2
    ;;
esac
