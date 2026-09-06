# AutoSBOM Sentinel — Architecture

This consolidates the full technical design from two research passes into one reference.
Priority tiers (what's core vs. optional) are in `03_BUILD_PLAN.md` — this doc is the
"what it is," not "what order to build it in."

---

## Stage 0 — Benchmark Harness (build this first; it's the proof and the headline artifact)

**Goal:** quantify, with real numbers, how badly generic SBOM/vulnerability tools perform
against automotive-style embedded firmware — this is the evidence for the whole
project's premise, and it doubles as the first shareable result.

**Method:**
1. Obtain ground truth: Automotive Grade Linux (AGL) publishes official pre-built images
   (e.g., an ARM64 `agl-ivi-demo-flutter`-class image) **with official SPDX SBOMs** —
   this is real, vendor-published ground truth, not something to fabricate.
2. Also build your own small embedded Linux image via Yocto or Buildroot on/for the
   Raspberry Pi 5, so you have a second, fully-known-composition target.
3. Run generic tools — Syft, Trivy, and EMBA — against both images.
4. Compare each tool's reported components + CVEs against the ground-truth SBOM and
   against manually-verified actual vulnerability status.
5. Report: false-positive rate, false-negative rate, and the *specific failure
   mechanisms* causing each (see "Known failure modes" below).

**Known failure modes to specifically look for and document:**
- **Stripped binaries / unknown-version problem:** tools can't match a CVE to a version
  they can't identify; a 2026 arXiv paper (2601.01308) flags this as an open research
  problem, not something solved by existing tools.
- **AUTOSAR-style module pruning:** build tooling strips unused functions from a module,
  so only a fraction of a component's source ships in the final binary — defeats
  whole-component signature matching.
- **Yocto/Buildroot backport false positives:** distros patch a CVE without bumping the
  version string, so version-range matchers keep flagging an already-fixed component as
  vulnerable (a **false positive**).
- **Wildcarded-CPE false-positive storms:** overly broad CPE matching (e.g., a generic
  `pkg:generic/` purl) causes tools to either miss real vulnerabilities entirely (false
  **negative**) or flood the report with irrelevant CVEs (false **positive**) — both
  failure directions have been separately documented (see citations in
  `02_RESEARCH_FINDINGS.md`).

**Deliverable:** a written/blogged benchmark report with a table of precision/recall
numbers per tool, and 2-3 concrete worked examples of each failure mode. This is the
single most citable, defensible artifact in the whole project — it's *your own
measured result*, not a borrowed statistic.

---

## Stage 1 — Automotive-Tuned SBOM Generator

**Goal:** a generator that avoids the specific failure modes found in Stage 0.

**Design:**
- Wraps `binwalk` (extraction/unpacking) + `Syft` (component identification) + `EMBA`
  (firmware-specific analysis, has its own SBOM/CVE-bin-tool/VEX integration already).
- Output format: **CycloneDX 1.6** (current de facto standard; also supports the
  Cryptography Bill of Materials extension used in the optional CBOM feature below).
  Keep an SPDX 2.3 export option since some consumers will request it specifically.
- **Explicitly handle Yocto/Buildroot backport annotations** — read `CVE_STATUS` /
  `CVE_CHECK_IGNORE`-style metadata so a backported fix doesn't get flagged.
- **Flag (don't silently drop) stripped/unknown-version binaries** for manual review,
  rather than either guessing a version or ignoring the binary.
- Emit both CPE and package-url (purl) identifiers with a confidence score where
  possible, since single-identifier matching is a big part of the false-positive problem.

---

## Stage 2 — Automotive-Context VEX Layer

**Goal:** suppress false-positive CVEs using automotive-specific usage context, and
measure the reduction against a real, domain-appropriate benchmark.

**Design:**
- Generate machine-readable **OpenVEX** statements (or CycloneDX-embedded VEX) with one
  of the standard justification codes (e.g., `vulnerable_code_not_in_execute_path`,
  `component_not_present`).
- Encode automotive-specific context rules, e.g.:
  - A CVE in a Bluetooth profile that's compiled in but disabled (directly mirrors the
    PerfektBlue story — AVRCP was the vulnerable profile in the most severe PerfektBlue
    CVE, CVE-2024-45434).
  - A CVE in a component that's network-isolated (no path to a reachable interface).
  - A CVE requiring local access not achievable given the device's actual configuration.
- **Benchmark the false-positive reduction against your own Stage 0 numbers first.**
  If you want an external benchmark to compare against, use the *correct, embedded-
  specific* studies (see `02_RESEARCH_FINDINGS.md` → Corrections) — do NOT use the
  ~61.9%/general-open-source-software figure as if it were an automotive/firmware
  result; that citation was wrong in an earlier draft and the corrected substitutes are
  documented there.

**IMPORTANT — human-in-the-loop requirement:** every VEX statement your tool proposes
should be reviewable/approvable by a human before being treated as "suppressed" in any
report or dashboard. Never let the tool auto-suppress silently — that's the exact
failure mode that makes VEX abuse dangerous, and it's a good thing to explicitly design
around and mention in your writeup (shows maturity).

---

## Stage 3 — Runtime SBOM Drift Detector

**Goal:** detect when a running system's actual component inventory diverges from its
recorded/signed baseline SBOM — a proxy for unauthorized OTA updates or tampering.

**Design:**
- Runs as a lightweight daemon on the Raspberry Pi 5 (standing in for an ECU).
- Periodically re-inventories: loaded shared libraries, installed package hashes
  (SHA-256), and loaded kernel modules.
- Diffs against a **signed baseline SBOM** (see Signing/Attestation below — the baseline
  must be cryptographically verified before being trusted as the diff target).
- Flags: additions, removals, and hash mismatches as "drift" events.
- **Demo scenario:** manually swap a shared library on the running Pi (simulating an
  unauthorized update) and show the daemon catching it within one polling interval, with
  zero false alarms over a clean 24-hour baseline run.

---

## Priority Addition A — Signed / Verifiable Supply Chain (build this — high value, not optional)

**Why it matters:** without this, the drift detector's own trust anchor (the baseline
SBOM) is just a file that could itself be tampered with — signing closes that loop and
is genuinely standard industry practice, not a nice-to-have.

**Design:**
- Sign the Stage 1 SBOM and the Stage 3 baseline with **Sigstore cosign**, ideally in
  **keyless mode** (CI authenticates via OIDC → Fulcio issues a short-lived cert → the
  signature is logged in the public **Rekor** transparency log — no long-lived private
  keys to manage).
- Wrap the build process as an **in-toto attestation** (who/what/how the artifact was
  built), following the general shape of **SLSA** provenance.
- The drift daemon (Stage 3) should **verify the cosign signature + Rekor inclusion**
  of the baseline before trusting it to diff against.
- Optional: a policy gate (e.g., cosign `verify-attestation` against a simple policy)
  that demonstrates "no valid signed provenance → reject this baseline."

---

## Priority Addition B — Visualization Dashboard (build this — makes the project demoable)

**Why it matters:** a CLI tool that only you can evaluate isn't a LinkedIn-shareable
project. This is what actually gets watched.

**Design:**
- Run **OWASP Dependency-Track** as the backing service — it natively ingests
  CycloneDX, renders dependency graphs, tracks risk over time, and natively consumes VEX
  (so your Stage 2 output plugs straight in).
- Generate a **CycloneDX Sunshine** single-file HTML report per build (self-contained,
  enriched with EPSS/KEV data) as a shareable artifact separate from the live dashboard.
- Build one **custom, automotive-specific visualization** that no generic tool provides:
  an **attack-surface heatmap** grouping components by exposure category (Bluetooth/
  network-facing/CAN/OTA) rather than by package name — this is the visual that signals
  automotive-domain thinking, not just "I ran a tool."
- Build a **drift timeline** view (Stage 3 events over time) and a **before/after VEX
  bar chart** (raw CVE count vs. post-VEX actionable count).
- **The demo asset:** a 60-90 second screen recording walking through: (1) the heatmap,
  (2) the before/after VEX chart, (3) the drift timeline with a flagged tamper event,
  (4) a green "signature verified" indicator on the trusted baseline.

---

## Secondary Additions (build if time allows — real value, moderate effort)

### C. CI/CD Pipeline ("continuous compliance")
A GitHub Actions workflow: generate SBOM (Syft) → scan (Grype) → filter (your VEX layer)
→ sign (cosign) → gate the build/upload to Dependency-Track. Frame this explicitly as
"continuous compliance" mapped to R155 CSMS vulnerability monitoring and the EU Cyber
Resilience Act's Article 14 reporting expectations. Note for the writeup: the EU's
ENISA reporting platform is a web-portal submission process at launch (no public API),
so position this pipeline as *preparing machine-readable evidence for human submission*,
not as an automated regulatory filer — that's a realistic, defensible scope.

### D. Deliberately-Vulnerable Demo Firmware
Build a small demo image on the Pi that bundles multiple realistic automotive stacks so
the pipeline has authentic targets to find, rather than generic Linux packages:
- **CAN**: Linux SocketCAN + the MCP2515 CAN HAT + **ICSim** (the standard open-source
  instrument-cluster simulator on a virtual CAN bus) — there's also a 2026 academic
  successor called ICSim++ worth knowing about (multi-bus, CAN FD).
- **UDS**: a basic UDS diagnostic service simulator (workshop-style forks exist as prior
  art to reference/adapt).
- **Bluetooth**: BlueZ — this directly echoes the PerfektBlue narrative; a good VEX demo
  is suppressing a CVE for a Bluetooth profile (e.g., AVRCP) that your demo config has
  disabled.
- **OTA client**: even a stubbed/simple OTA updater, so the Stage 3 drift-detection demo
  has a coherent "this is what unauthorized-update detection is for" story.

---

## Optional / Experimental — Cite as Future Work, Don't Over-Build

- **LLM-assisted VEX drafting / CVE summarization.** Real 2025-2026 research direction
  (see `02_RESEARCH_FINDINGS.md`), but ship it (if at all) only as a clearly-labeled
  draft-assistance feature with a mandatory human approval gate — never as an
  autonomous suppressor. Flag hallucination risk explicitly in any writeup.
- **eBPF-based runtime monitoring** (Falco/Tetragon/Tracee-style, or referencing the
  academic "Bomfather" concept) as a stronger version of Stage 3. Interesting to mention
  as "aware of this approach, chose the simpler polling-daemon design for v1" rather
  than actually building it, unless there's real spare time.
- **Cryptography Bill of Materials (CBOM) / post-quantum readiness inventory.**
  CycloneDX 1.6 natively supports this. A nice "forward-looking" mention; not core.
- **Full ISO/SAE 21434 clause-mapped compliance report generator / CRA-style disclosure
  report.** Good narrative color for the README (map your artifacts to specific clauses
  in prose), not worth building as actual generator software for a portfolio project.

---

## Scope discipline (important)
This is a personal, unpaid, portfolio-scale project on a Raspberry Pi, not a certified
CSMS or a production tool. Do not, anywhere in code comments, README, resume, or
LinkedIn copy, imply this is production/type-approval-ready, or that it constitutes
professional experience with any specific enterprise system. It demonstrates concepts,
methodology, and a working toolchain — that framing is both accurate and, per the
research, still genuinely differentiated at the entry level.
