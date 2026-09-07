# AutoSBOM Sentinel

An automotive-aware pipeline that generates SBOMs from embedded Linux
firmware, cuts CVE false positives with an automotive-context VEX layer, and
continuously watches a running device for unauthorized drift from its signed
baseline — a personal portfolio project built around the supply-chain
visibility gap exposed by the 2025 **PerfektBlue** disclosure.

## Why

PerfektBlue (CVE-2024-45431 … CVE-2024-45434, in OpenSynergy's BlueSDK
Bluetooth stack) was patched by the vendor in September 2024, yet some OEMs
had not shipped fixes to vehicles by June 2025 — largely because many OEMs
did not know they were even using the vulnerable component. There was no
usable SBOM. (The frequently-quoted "~350 million vehicles" install base is
OpenSynergy's own vendor claim, not an independently verified figure.)

This project builds, end to end and on legally-accessible targets only
(public Automotive Grade Linux images and self-built Yocto/Buildroot
images — never proprietary OEM/Tier-1 firmware), the tooling that closes
that gap:

| Stage | What it does | Where |
|---|---|---|
| **0 — Benchmark harness** | Scores generic tools (Syft, Trivy, EMBA) against ground-truth SBOMs: precision/recall, version mismatches, unknown-version reports, CVE accuracy vs. a manually-verified sample | `autosbom/stage0_benchmark/` |
| **1 — Automotive-tuned generator** | binwalk + Syft + a native ELF walk; **flags (never drops)** stripped/unknown-version binaries; parses Yocto `CVE_STATUS`/`CVE_CHECK_IGNORE` backport annotations; emits CycloneDX 1.6 (+ SPDX 2.3) | `autosbom/stage1_generator/` |
| **2 — Automotive-context VEX** | Rules engine over a declared device context (disabled Bluetooth profiles, network isolation, execute-path) proposing OpenVEX statements — **every suppression requires named human approval; auto-suppression is deliberately not implemented** | `autosbom/stage2_vex/` |
| **3 — Runtime drift detector** | Daemon re-inventories shared libraries (SHA-256), packages, and kernel modules, diffing against a **cosign-signed baseline it verifies before trusting** (unsigned baselines are rejected by default) | `autosbom/stage3_drift/` |
| **Signing** | cosign keyless (CI) / key-based (device) signing of SBOM + baseline; CI provenance attestation | `signing/`, `.github/workflows/sbom-pipeline.yml` |
| **Dashboard** | Self-contained HTML report: attack-surface heatmap by exposure category, raw-vs-post-VEX chart, drift timeline; Dependency-Track wiring for the live view | `autosbom/dashboard/`, `dashboard/` |
| **CI/CD** | "Continuous compliance" pipeline: Syft → Grype → approved-VEX filter → cosign → report artifact → optional Dependency-Track upload | `.github/workflows/` |
| **Demo firmware** | vcan/ICSim setup, a UDS (ISO 14229) simulator over ISO-TP, the PerfektBlue AVRCP VEX scenario, an OTA stub driving the drift demo | `demo-firmware/` |

## The 60-second story

1. `autosbom generate` turns a firmware image/rootfs into a CycloneDX 1.6
   SBOM — with stripped binaries *flagged for review* instead of silently
   guessed at or dropped.
2. A scanner reports CVE-2024-45434 (the critical PerfektBlue AVRCP
   use-after-free) against BlueZ. The device context says AVRCP is disabled.
   `autosbom vex propose` drafts a `not_affected /
   vulnerable_code_not_in_execute_path` statement — and a **human approves it
   by name** before any report treats it as suppressed.
3. `autosbom baseline` + `signing/sign_artifact.sh` create a signed runtime
   baseline. The drift daemon verifies the signature, then catches an
   unauthorized library swap as a critical `library-hash-mismatch` within
   one polling sweep.
4. `autosbom report` renders it all into one shareable HTML file.

## Install & quick start

```sh
pip install -e ".[dev]"        # zero runtime deps; PyYAML optional, pytest for dev
pytest -q                      # 50 tests

# Stage 0 (with saved tool outputs):
autosbom benchmark --ground-truth image.spdx.json \
    --tool-output syft=syft.json --tool-output trivy=trivy.json \
    --output stage0-results.md

# Stage 1:
autosbom generate ./extracted-rootfs --output-dir ./out \
    --yocto-metadata ./meta-layers        # optional backport annotations

# Stage 2:
autosbom vex propose --findings grype.json --context examples/device-context.json \
    --annotations out/backport-annotations.json
autosbom vex list
autosbom vex approve --cve CVE-2024-45434 --component bluez5 \
    --reviewer "Your Name" --note "AVRCP verified disabled on device"
autosbom vex export --output vex.openvex.json --author "Your Name" \
    --product-purl pkg:generic/pi5-ivi-demo

# Stage 3:
autosbom baseline --output baseline.json
./signing/sign_artifact.sh key baseline.json
autosbom drift --baseline baseline.json --signature baseline.json.sig \
    --public-key cosign.pub --event-log drift.jsonl --once

# Report:
autosbom report --sbom out/sbom.cdx.json --findings grype.json \
    --review-store vex-review.json --drift-log drift.jsonl \
    --output build-report.html
```

External tools (syft, trivy, binwalk, cosign, grype) are invoked when
installed and reported as missing when not — the Python code itself has no
runtime dependencies and runs on a stock Raspberry Pi Python 3.9+.

## Honest status ledger

This is a personal portfolio project, not a production or certified system.
Per-piece status, precisely:

| Piece | Status |
|---|---|
| All Python modules (Stages 0-3, VEX gate, dashboard, CLI) | Implemented; **50 unit/integration tests pass** (synthetic fixtures + live filesystem sweeps in a Linux container) |
| Drift detection end-to-end | Exercised live in a Linux container: baseline of 987 real libraries + 686 packages, clean sweep = 0 events, tamper demo caught as critical within one sweep. **Not yet run on the target Raspberry Pi 5**, and the 24-hour zero-false-alarm run is still to be performed |
| Stage 0 real benchmark numbers (AGL images, Syft/Trivy/EMBA) | **Not yet produced** — the harness is ready; follow `docs/06_STAGE0_RUNBOOK.md`. No numbers are claimed until measured |
| cosign keyless signing | **Exercised end-to-end in CI**: the pipeline's `cosign sign-blob` step succeeded on a real run (Rekor-logged, Fulcio cert emitted). GitHub provenance attestation is unavailable on user-owned private repos and auto-activates when the repo is public. Key-based device flow **not yet run on the Pi** |
| Dependency-Track live dashboard | Wiring documented + CI upload step written; **not yet stood up and verified** |
| Demo firmware (vcan/ICSim, UDS sim, BlueZ scenario) | Scripts implemented; **not yet run on the target Pi** (need kernel modules / hardware) |
| Demo video | Not recorded |

## Regulatory framing (prose mapping, not a compliance claim)

- **UNECE R155 (CSMS)** expects continuous vulnerability monitoring across
  the supply chain — Stages 1-2 plus the CI pipeline demonstrate that loop
  in miniature.
- **ISO/SAE 21434** vulnerability-management work products (clauses around
  13/15) are what the VEX review store's human-approved, evidence-carrying
  records model.
- **EU Cyber Resilience Act** Article 10.6 is a de-facto SBOM mandate and
  Article 14 reporting begins September 2026; ENISA's reporting platform is
  a web-portal process at launch, so this pipeline prepares
  machine-readable evidence for human submission — it does not file
  reports automatically, and doesn't claim to.

## Future work (aware of, deliberately not built)

- LLM-assisted VEX drafting (would ship only behind the same mandatory human
  gate; hallucinated justifications are a real safety risk in this domain)
- eBPF-based runtime monitoring (a stronger Stage 3; the polling daemon was
  chosen for v1 simplicity)
- CycloneDX 1.6 CBOM / post-quantum readiness inventory
- Formal ISO/SAE 21434 clause-mapped report generator

## Repository map

```
autosbom/            the Python package (stages 0-3, dashboard, CLI)
tests/               50 tests + synthetic fixtures
docs/                project brief, architecture, research (with corrections),
                     build plan, hardware/software BOM, Stage 0 runbook
signing/             cosign sign/verify scripts
dashboard/           Dependency-Track wiring notes
demo-firmware/       vcan/ICSim, UDS simulator, OTA stub, PerfektBlue scenario
demo-target/         deliberately-vulnerable fixture -- gives the CI pipeline
                     real CVEs to find; not a real dependency, never installed
examples/            sample device-context
.github/workflows/   CI (tests) + SBOM "continuous compliance" pipeline
```

## Scope statement

No proprietary OEM/Tier-1 firmware is used or needed anywhere in this
project — public AGL images and self-built images are the only targets.
That is a design feature (anyone can reproduce this), not a limitation to
hide. Nothing here constitutes professional/production experience with any
enterprise system, and nothing is claimed as working that hasn't been —
see the status ledger above.

## License

**All Rights Reserved** — see [LICENSE](LICENSE). This is not an open-source
project: any use beyond evaluating the code (running, deploying, modifying,
or redistributing it, or incorporating it into another project) requires
prior written permission from the author. To request permission, contact
via LinkedIn: https://www.linkedin.com/in/michealwolski
