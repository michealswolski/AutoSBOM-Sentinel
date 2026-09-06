# AutoSBOM Sentinel — Project Brief

## One-line pitch
An open-source pipeline that generates automotive-aware Software Bills of Materials
(SBOMs) from embedded Linux firmware, maps them to CVEs with a VEX layer tuned to cut
automotive-specific false positives, and continuously watches a running device for
unauthorized drift from its signed baseline — built to demonstrate, hands-on, the exact
supply-chain-visibility gap that delayed patching of the 2025 PerfektBlue Bluetooth
vulnerability across an estimated ~350 million vehicles.

## Why this project (the story)
PerfektBlue (CVE-2024-45431 through CVE-2024-45434, in OpenSynergy's BlueSDK Bluetooth
stack) was patched by the vendor in September 2024, but some OEMs hadn't shipped fixes
to vehicles until June 2025 — nearly a year later — largely because many OEMs did not
know they were even using the vulnerable component. There was no usable SBOM. This
project builds the tooling that closes that exact gap, and benchmarks — with real
numbers, not just claims — how badly generic SBOM/vulnerability tools actually perform
against automotive-style embedded firmware.

## What it is
A four-stage pipeline (see `01_ARCHITECTURE.md` for full detail):
- **Stage 0 — Benchmark harness:** measure how badly generic tools (Syft, Trivy, EMBA)
  perform against ground-truth SBOMs from Automotive Grade Linux (AGL) images.
- **Stage 1 — Automotive-tuned SBOM generator:** wraps binwalk + Syft + EMBA, fixes
  known failure modes (Yocto/Buildroot backport false positives, stripped-binary
  handling), emits CycloneDX 1.6.
- **Stage 2 — Automotive-context VEX layer:** suppresses false-positive CVEs using
  automotive usage context (disabled features, network isolation, reachability),
  measured against a real benchmark.
- **Stage 3 — Runtime drift detector:** a Raspberry Pi 5 daemon that re-inventories a
  running system and flags divergence from its signed baseline SBOM — a proxy for
  unauthorized OTA updates or tampering.

Plus two additions that materially raise the ceiling on how impressive/credible it is:
- **Cryptographic signing/attestation** (Sigstore cosign + in-toto) on both the SBOM and
  the drift baseline, so the whole trust chain is verifiable, not just asserted.
- **A visualization dashboard** (Dependency-Track + a custom automotive attack-surface
  heatmap) so the project is demoable in 60 seconds on LinkedIn, not just a CLI tool.

## What it is NOT (be careful about this in any public writeup)
- It is **not** an audit of any real OEM's shipping vehicle firmware — proprietary Tier-1
  firmware isn't legally accessible to a hobbyist, so the target is Automotive Grade
  Linux (AGL) public images and the candidate's own Raspberry Pi builds, used as
  realistic stand-ins.
- It is **not** a claim of professional/production SBOM tooling experience — it is a
  personal portfolio project demonstrating the concepts, methodology, and toolchain.
- It does **not** reproduce or exploit the actual PerfektBlue vulnerability — PerfektBlue
  is the motivating incident/narrative hook, not something this project recreates.
- LLM-assisted triage, eBPF runtime monitoring, and a full compliance-report generator
  are **optional stretch goals** flagged as experimental/future-work — do not claim these
  as built unless they actually are.

## Target audience for the finished project
Entry-level automotive cybersecurity / product cybersecurity / supply-chain-security /
vulnerability-management roles at OEMs and Tier 1 suppliers, and threat-intelligence
roles (e.g., Auto-ISAC-style CTIA positions). It is a weaker fit as evidence for
pure penetration-testing/red-team roles — for those, lean on the existing CAN IDS,
SecOC demo, and key-lifecycle-manager projects instead. This project is meant to be the
**complement** to that existing pipeline, not a replacement for it: together they cover
both the "can hack/defend a vehicle network" half and the "understands supply-chain and
compliance process" half that most entry-level candidates can't show at all.

## Budget / hardware reality
Total hardware need is well under $400, and likely closer to $150-250 if a Raspberry Pi
5 and basic accessories are already on hand. See `04_HARDWARE_SOFTWARE_BOM.md` for the
exact list. Almost everything else is free/open-source software.

## Realistic timeline
Core pipeline (Stages 0-3): ~8-10 weeks part-time.
Add signing + dashboard: +2 weeks.
Add CI/CD pipeline + deliberately-vulnerable demo firmware: +2-3 weeks.
**Total realistic: 10-13 weeks** for a complete, differentiated project. It is fine to
stop after Stages 0-3 plus signing + dashboard and still have something strong — see
`03_BUILD_PLAN.md` for the priority tiers if time runs short (e.g., a job offer lands
mid-project).
