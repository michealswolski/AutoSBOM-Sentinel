# AutoSBOM Sentinel — Consolidated Research Findings & Citations

This distills two research passes (initial project design + feature-enhancement pass)
into the load-bearing facts, with a corrections section flagged up front since it
matters for credibility.

## ⚠️ Corrections — read this first
An earlier draft cited a "~61.9% false-positive reduction via reachability analysis"
figure and attributed it to "Zhou et al., ICSE '26" as if it were an **automotive
firmware** benchmark. On closer check:
- The paper is real: Zhou, Dacier & Konstantinou, "A Reality Check on SBOM-based
  Vulnerability Management" (arXiv 2511.20313).
- The 61.9% figure is verbatim-correct from that paper.
- **BUT** the correct venue is **CODASPY '26**, not ICSE, and the study measured
  **2,414 open-source repositories (Python/Rust/Ruby/PHP web-ecosystem software)** —
  it is NOT a firmware/embedded/automotive study.
- **If you want to cite a false-positive-reduction number for embedded/firmware work
  specifically, use these instead:**
  - **VPChecker** (Patel, Snit & Polychronakis, ACSAC 2025) — measured on C/C++ ELF
    binaries: a 28% reduction in "binaries reported per CVE" and a 30% reduction in
    "CVEs per binary," which the authors themselves describe as a conservative lower
    bound.
  - A Linux-kernel firmware CVE-attribution study (arXiv 2209.05217) found that
    roughly **68% of baseline CVE matches were high-confidence false positives.**
- **Best option of all: cite your own Stage 0 benchmark result once you have it.** It
  will be more credible than any borrowed number because it's measured on your own
  target images with your own methodology.

Also note: the "~350 million vehicles" figure for BlueSDK's install base is
**OpenSynergy's own vendor marketing claim** (relayed by Dark Reading and others), not
an independently verified figure printed on the primary PCA Cyber Security advisory or
in the NVD entries. Attribute it explicitly as a vendor claim if you use it.

---

## The PerfektBlue incident (the project's motivating story — well-established, high confidence)
- Four CVEs in OpenSynergy's BlueSDK Bluetooth stack, publicly disclosed 7 July 2025 by
  PCA Cyber Security's Security Assessment Team.
  - **CVE-2024-45434** — Use-After-Free in the AVRCP service — **CVSS 8.0 (Critical)**
  - **CVE-2024-45433** — incorrect function termination in RFCOMM — 5.7 (Medium)
  - **CVE-2024-45432** — function call with incorrect parameter in RFCOMM — 5.7 (Medium)
  - **CVE-2024-45431** — improper validation of an L2CAP channel's remote CID — 3.5 (Low)
- PCA's researchers had **no source code access** — they analyzed a compiled BlueSDK
  binary, which is itself a nice parallel to this project's binary-SBOM-analysis focus.
- Timeline: reported 17 May 2024 → CVEs reserved 30 Aug 2024 → patched by OpenSynergy
  September 2024 → **some OEMs had still not shipped the patch to vehicles by June
  2025.**
- Verified exploited on real production head units: Mercedes-Benz NTG6, Volkswagen MEB
  ICAS3 (ID.4), Škoda MIB3 (Superb); a BMW info-leak proof-of-concept was also shown.
- **The core lesson for this project:** "Many OEMs were unaware that they even used
  BlueSDK, largely due to the lack of a clear software bill of materials" — this is the
  single sentence that justifies the entire project's existence.

---

## Current SBOM tooling landscape (high confidence)
- Generic tools (Syft, Trivy, CycloneDX/SPDX tooling, OWASP Dependency-Track) were built
  assuming package managers and ecosystem registries — automotive ECUs frequently run
  bare-metal, RTOS (AUTOSAR Classic, FreeRTOS, QNX), or heavily customized embedded
  Linux with none of that, so binary analysis is often the only option.
- Teams evaluating generic tools (Black Duck, Syft, Trivy, FOSSA) on real embedded
  projects "routinely find outputs are incomplete, inconsistent, or so noisy" that many
  fall back to manually-maintained spreadsheets — this is the process-inefficiency gap
  the project targets.
- **Best-of-breed open/academic tools worth using or citing:**
  - **EMBA** — explicitly repositioned itself from "firmware analyzer" to "SBOM tool,"
    integrates cve-bin-tool and VEX support, emits CycloneDX.
  - **BANG (Binary Analysis Next Generation)** — recursive unpacking/provenance.
  - **binwalk** — the near-universal firmware-extraction primitive.
  - **cve-bin-tool** — signature-based embedded-library detection.
  - **capa** — YARA-based capability identification.
  - **UniBOM** (arXiv 2511.22359, 2025) — academic CLI combining binwalk+Syft+Grype for
    IoT firmware SBOM — closely related prior art worth reading and citing/differentiating
    from.
  - Niche embedded-Linux-specific tools that exist *precisely because* generic tools
    mislead on Yocto/Buildroot: `sbom-embedded`, `yocto-sbom`, `bd-scan-yocto-via-sbom`,
    Bootlin's `sbom-cve-check`.
- **Documented technical difficulties generating SBOMs from compiled firmware:**
  stripped binaries with no version strings ("unknown version" problem, flagged as
  unsolved in arXiv 2601.01308); AUTOSAR-style dead-code stripping defeating whole-module
  signature matching; proprietary/undocumented firmware formats; diverse toolchains and
  architectures (ARM/PowerPC/etc.); static linking hiding embedded libraries inside
  opaque Tier-1 supplier blobs; and 15-year vehicle-platform lifecycles multiplying the
  number of variants that each need an accurate, monitored SBOM.

---

## Regulatory landscape (high confidence on requirements; medium confidence on exact dates — verify against primary legal text before quoting precisely)
- **UNECE R155 (Cybersecurity Management System) / R156 (Software Update Management
  System):** mandatory for new EU vehicle types since July 2022, all new vehicles since
  July 2024. R155 explicitly covers the *full supply chain*, with obligations cascading
  from OEM to Tier 1 to Tier 2. SBOM is a de-facto requirement even though the word
  "SBOM" doesn't appear verbatim in the regulation text — auditors expect it in practice.
- **ISO/SAE 21434:** the engineering framework auditors expect for R155 compliance;
  defines 42 work products across clauses 5-15; vulnerability management sits around
  clauses 13/15.
- **EU Cyber Resilience Act (CRA):** Article 10.6 requires identifying/documenting
  components including open source — a de facto SBOM mandate. Reporting obligations
  (early-warning/notification/final-report cadence under Article 14) begin **11
  September 2026**; full conformity/CE-marking obligations land later (~end of 2027).
  Note that ENISA's reporting platform is expected to launch as a **web-portal-only,
  mandatory-reporting-only system with no public API at first** — a real operational
  constraint worth reflecting honestly in any compliance-reporting feature.
- **NHTSA Cybersecurity Best Practices (Sept 2022):** recommends (does not mandate)
  suppliers/manufacturers maintain a component database per ECU.
- **Auto-ISAC SBOM Informational Report (Feb 2025):** industry's own guidance, stating
  plainly that SBOM adoption "is still in its early stages in the automotive industry."

## Documented gap between requirement and real practice (medium-high confidence; sourced from industry whitepapers, not independently audited data)
- Multiple industry sources (NTT DATA, Global Market Insights, Uraeus) describe most
  suppliers and OEMs as lacking automated SBOM generation, often falling back to
  spreadsheet-based manual tracking, with a "shortage of automotive cybersecurity
  professionals with SBOM program expertise" repeatedly named as a bottleneck — directly
  relevant to positioning yourself for these roles.
- The plainest statement of the process-inefficiency problem: without an SBOM,
  "answering a simple question like 'are we affected by this new CVE?' requires days or
  weeks of manual investigation across multiple supplier contacts" — this is exactly
  the PerfektBlue failure mode in miniature.

---

## Not-yet-solved problems (identify these explicitly in your writeup as "gaps I'm addressing," each sourced)
- **Automotive-tuned SBOM→CVE mapping with acceptable false-positive rates —
  substantially unsolved.** A large empirical study (Zhou, Dacier & Konstantinou,
  CODASPY '26 — see Corrections above) measured a **92.0% false-positive rate** in
  downstream vulnerability scanning on general open-source software, driven largely by
  flagging vulnerabilities in unreachable code; the same paper states that "the absence
  of function-level metadata in mainstream vulnerability advisories... is a known,
  critical bottleneck" that "remains an unsolved industry challenge." The embedded-
  specific compounding factor (Yocto/Buildroot backports without version bumps) is
  separately documented in the `sbom-embedded` project's own writeup and by ONEKEY for
  the Linux kernel.
- **VEX adoption in automotive specifically — nascent, essentially undocumented in the
  literature as of 2026.** VEX demonstrably cuts noise in general software contexts, but
  the OpenSSF's own January 2026 report on the subject concludes adoption "remains
  inconsistent and uncertain" industry-wide, and no automotive-specific VEX-adoption
  study was found — automotive SBOM vendors describe VEX only as a forward-looking
  capability, not a deployed one.
- **AIBOM (AI/ML component bill-of-materials) for ADAS — early-stage.** The OWASP AIBOM
  Project only launched in 2025; there is essentially no automotive-specific ADAS
  model-provenance/training-data-lineage BOM practice yet.
- **Cryptographic BOM (CBOM) / post-quantum readiness for automotive — emerging.**
  CycloneDX 1.6 added native CBOM support, purpose-built for PQC discovery, but
  automotive-specific application is barely addressed in current tooling, despite the
  obvious relevance of 15-year vehicle lifecycles crossing NIST's PQC transition
  timeline (NIST IR 8547 draft: broadly, weaker classical algorithms deprecated after
  2030, disallowed after 2035).
- **Runtime/continuous SBOM drift detection for vehicles — genuinely greenfield.** One
  industry source states plainly: "what is actually running on a deployed ECU may
  diverge from the build-time SBOM due to OTA updates, field modifications, partial
  update failures, or even unauthorized software changes" and that today this is mostly
  reduced to secure-boot signature checks rather than true runtime SBOM verification.
  Academic runtime-integrity work (e.g., an eBPF-based concept called "Bomfather," arXiv
  2503.02097) exists but largely outside the automotive context specifically — **this is
  the single most novel piece of the whole project.**

---

## Enhancement-pass findings (feature additions researched in the second pass)

### Visualization (established practice)
- **CycloneDX Sunshine** — official CycloneDX project; turns a CycloneDX JSON into a
  single self-contained HTML report enriched with EPSS and CISA KEV exploit-probability
  data. Good per-build shareable artifact.
- **OWASP Dependency-Track** — the de facto open-source SBOM analysis platform;
  dependency-graph visualization, continuous risk-over-time dashboard, native VEX
  ingestion/production. Good as the live backend.
- Other reference points if you want to go further: GUAC (graph-database-driven supply
  chain visualization), Rancher's client-side SBOM Viewer, `cyclonedx-ui`.

### CI/CD ("continuous compliance" pattern — established practice)
Standard 2025-2026 open-source pattern: generate (Syft/`sbom-action`) → scan (Grype) →
filter/annotate (VEX, reviewed like code in source control) → sign (cosign) → gate the
build → push to Dependency-Track. Commercial vendors (Finite State, C2A Security's
EVSec, PlaxidityX, VxLabs ThreatZ) now market almost exactly this as "continuous
compliance" for automotive — referencing this by name shows domain awareness.

### Signing / supply-chain provenance (established practice)
- **Sigstore cosign**, ideally **keyless** (OIDC → Fulcio short-lived cert → Rekor
  transparency log) — no long-lived private keys.
- **in-toto attestations / SLSA provenance** — proves not just what's inside an
  artifact (SBOM) but where/how it was built (provenance). GitHub Artifact Attestations
  and `gh attestation verify` interoperate with cosign.
- The project-specific novel twist: **sign the Stage 3 drift baseline too**, and have
  the drift daemon verify the signature + Rekor inclusion before trusting the baseline
  it diffs against — this closes the full trust loop end-to-end.

### Demo firmware / attack-surface prior art (established targets)
- **ICSim** (Craig Smith / OpenGarages) — the standard open-source instrument-cluster
  CAN simulator; a 2026 academic successor **ICSim++** adds multi-bus topologies, a
  virtual gateway, and CAN FD support (published in SoftwareX).
- **CH-Workshop**-style forks already simulate a basic UDS diagnostic service over CAN.
- **BlueZ** for a real, CVE-bearing Bluetooth stack that directly echoes the PerfektBlue
  narrative.
- **Pwn2Own Automotive 2026** (Tokyo, Jan 21-23, 2026): 76 unique zero-days disclosed
  across 73 entries, $1,047,000 awarded; Fuzzware.io (Tobias Scharnowski, Felix
  Buchmann, Kristian Covic) named Master of Pwn with $215,500 — good, current, citable
  evidence that the automotive attack surface (including new EV-charger/OCPP
  categories) keeps expanding, supporting the "why this matters" framing.

### LLM-assisted triage (emerging/experimental — flag clearly if built)
Real research directions exist (CASEY, CVE-LLM, ProveRAG, VLAI — various 2025 papers),
and commercial vendor Pixee claims a 95% false-positive reduction via VEX-status
mapping (a vendor claim, not independently verified). Risks to flag explicitly if you
build this at all: hallucinated justifications creating false "not affected"
suppressions (a real safety risk in an automotive context), and the documented need for
a human-in-the-loop approval gate before any VEX statement is trusted.

### CISA SBOM Minimum Elements update (emerging)
CISA's draft update (public comment closed Oct 2025) adds component hash, license, tool
name, and generation context as new recommended fields beyond the original 2021 NTIA
baseline — worth aligning your Stage 1 generator's output to these fields.

---

## General confidence-level guidance for any writeup
- **Regulatory requirements and CVE facts:** high confidence, drawn from primary
  advisories/standards — safe to state directly, but double-check exact dates against
  primary sources before publishing (regulatory implementation timelines shift).
- **Industry-practice-gap statistics** (adoption percentages, "most suppliers lack X"):
  medium confidence — these come from vendor/industry whitepapers and analyst reports,
  not independently audited data. Attribute them to their source rather than stating as
  flat fact.
- **Academic benchmark numbers** (false-positive-reduction percentages, etc.): cite
  precisely, including which corpus they were measured on (see Corrections above) — do
  not transplant a general-software number onto an automotive/firmware claim.
- **Anything tagged [Experimental] in the architecture doc:** present as "aware of /
  considered / future work," not as built capability, unless it's actually working
  end-to-end.
