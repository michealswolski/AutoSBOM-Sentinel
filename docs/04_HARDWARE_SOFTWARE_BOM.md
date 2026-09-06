# AutoSBOM Sentinel — Hardware & Software Bill of Materials

## Hardware already on hand (per candidate's existing setup)
- Raspberry Pi 5
- A breadboard
- A personal computer (used for the heavier lifting: Ghidra/EMBA/local NVD mirror,
  Yocto/Buildroot builds, Dependency-Track hosting)
- An ELM327 OBD-II dongle (not required for this specific project, but already owned
  from the CAN Bus IDS project)

## Hardware to buy (only if pursuing Tier 3 demo firmware with CAN)
| Item | Rough cost | Needed for |
|---|---|---|
| MCP2515-based CAN HAT for Raspberry Pi | ~$15-30 | Tier 3 demo firmware (SocketCAN + ICSim) |
| Active cooler + adequate PSU for Pi 5 (if not already owned) | ~$15-25 | General reliability running the drift daemon continuously |
| NVMe HAT + small NVMe SSD (optional) | ~$40-70 | Faster local builds/storage if the SD card becomes a bottleneck |

**Total additional spend if pursuing everything: roughly $70-125 — well under the
$400 ceiling.** Tiers 1 and 2 (the actually non-negotiable parts of the project)
require **no new hardware purchases at all** beyond what's already owned.

## Software (all free/open-source)
| Tool | Role |
|---|---|
| binwalk | Firmware extraction/unpacking |
| Syft | Component/SBOM generation |
| Trivy | Vulnerability scanning, benchmark comparison |
| EMBA | Firmware-specific analysis, SBOM + VEX support |
| cve-bin-tool | Signature-based embedded library/CVE detection |
| Ghidra | Reverse engineering (as needed for stripped/unknown binaries) |
| Yocto Project / Buildroot | Building custom ground-truth embedded Linux images |
| Automotive Grade Linux (AGL) pre-built images | Ground-truth ARM64 image + official SPDX SBOM |
| CycloneDX CLI tooling | SBOM format generation/validation (CycloneDX 1.6) |
| OpenVEX / vexctl | VEX statement generation |
| Sigstore cosign | Signing (keyless, via OIDC/Fulcio/Rekor) |
| in-toto / SLSA generator tooling | Build provenance attestations |
| OWASP Dependency-Track | SBOM/VEX ingestion, dependency graph, live dashboard |
| CycloneDX Sunshine | Single-file shareable HTML report per build |
| GitHub Actions | CI/CD pipeline (Tier 3) |
| SocketCAN / can-utils / ICSim | Tier 3 demo firmware CAN simulation |
| BlueZ | Tier 3 demo firmware Bluetooth stack |

## Notes on legal/access constraints
- **No proprietary Tier-1 or OEM firmware is used or needed anywhere in this project.**
  AGL public images and self-built Yocto/Buildroot images are the only firmware targets.
  This should be stated explicitly and proudly in the README — it's a feature of the
  design (reproducible by anyone), not a limitation to hide.
- Do not attempt to obtain, download, or analyze proprietary BlueSDK, AUTOSAR, or any
  vendor's actual shipping ECU firmware for this project — that's both a legal risk and
  unnecessary for demonstrating the methodology.
