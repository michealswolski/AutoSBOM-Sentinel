# Signing / Attestation (Priority Addition A)

Cryptographically sign the Stage 1 SBOM and the Stage 3 drift baseline so the
whole trust chain is verifiable, not just asserted. Without this, the drift
detector's own trust anchor (the baseline) is just a file that could itself be
tampered with.

## What's here

| File | Purpose |
|---|---|
| `sign_artifact.sh` | cosign signing — keyless (CI/OIDC → Fulcio → Rekor) or key-based |
| `verify_artifact.sh` | matching verification |

The drift daemon (`autosbom drift`) **requires a verifiable baseline by
default** and refuses to run otherwise; `--allow-unverified-baseline` exists
for development only and stamps every logged event with
`baseline_verified: false`. See `autosbom/stage3_drift/verify.py`.

The CI workflow (`.github/workflows/sbom-pipeline.yml`) performs keyless
signing of the generated SBOM on every build, and GitHub's own artifact
attestation step records in-toto/SLSA-style provenance for it.

## Typical flows

**CI (keyless — no long-lived keys):** handled automatically by the
`sbom-pipeline.yml` workflow (`id-token: write` + `cosign sign-blob` +
`actions/attest-build-provenance`).

**On the Pi (key-based, for the drift baseline):**

```sh
cosign generate-key-pair            # do this on your workstation, not the Pi
autosbom baseline --output baseline.json
./signing/sign_artifact.sh key baseline.json
# copy baseline.json + baseline.json.sig + cosign.pub to the Pi, then:
autosbom drift --baseline baseline.json --signature baseline.json.sig \
    --public-key cosign.pub --event-log /var/log/autosbom/drift.jsonl
```

Keep `cosign.key` off the device — the device only ever needs `cosign.pub`.

## Status / honesty note

The scripts and the daemon-side verification policy are implemented and the
policy behavior is unit-tested (a missing/failed verification is rejected).
End-to-end keyless signing needs a real OIDC session (CI or interactive
browser login) and has **not** been exercised inside this repository's
development environment — run the CI workflow or the scripts locally to
confirm before claiming the signing loop works end-to-end.
