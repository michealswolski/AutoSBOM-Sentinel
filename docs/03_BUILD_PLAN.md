# AutoSBOM Sentinel — Build Plan & Priority Tiers

## Priority tiers (use this if time runs short — e.g., a job offer lands mid-project)

**Tier 1 — Non-negotiable core (the project isn't "done" without these):**
- Stage 0: Benchmark harness
- Stage 1: Automotive-tuned SBOM generator
- Stage 2: Automotive-context VEX layer
- Stage 3: Runtime drift detector

**Tier 2 — Build these too; the ROI is too high to skip if you have any runway left:**
- Signing/attestation (cosign + in-toto) on the SBOM and the drift baseline
- Visualization dashboard (Dependency-Track + custom attack-surface heatmap + drift
  timeline) and the 60-90 second demo video

**Tier 3 — Build if time allows, in this order:**
- CI/CD pipeline (GitHub Actions, "continuous compliance" framing)
- Deliberately-vulnerable demo firmware (SocketCAN/ICSim + UDS + BlueZ + OTA client)

**Tier 4 — Mention as future work in the README; do not build unless there's real spare
time and it won't dilute polish on Tiers 1-2:**
- LLM-assisted VEX drafting/CVE summarization
- eBPF-based runtime monitoring
- CBOM / post-quantum readiness inventory
- Full ISO/SAE 21434 clause-mapped compliance report generator

If you have to stop after Tier 1, or Tier 1 + partial Tier 2, that is still a complete,
credible, differentiated portfolio project. Don't feel obligated to reach Tier 3/4.

---

## Week-by-week plan (assumes part-time effort; adjust pace to actual availability)

### Weeks 1-2: Stage 0 — Benchmark Harness
- Download AGL pre-built images with official SPDX SBOMs (ground truth).
- Set up a Yocto or Buildroot build for a small custom image (second ground-truth target).
- Install and run Syft, Trivy, and EMBA against both images.
- Manually verify a sample of reported CVEs against the ground truth.
- Write up: false-positive rate, false-negative rate, and specific failure examples
  (stripped binaries, backport mismatches, wildcarded CPEs — whichever you actually hit).
- **Checkpoint:** if generic tools perform *unexpectedly well* against your ground truth
  (unlikely, but possible), pivot emphasis toward Stage 3 (drift detection) as the
  primary novelty instead of Stage 1/2 false-positive reduction.

### Weeks 3-5: Stage 1 — Automotive-Tuned SBOM Generator
- Build the binwalk + Syft + EMBA wrapper.
- Implement Yocto/Buildroot backport-aware matching (read `CVE_STATUS`/
  `CVE_CHECK_IGNORE`-style metadata).
- Implement stripped/unknown-version binary flagging (don't silently drop these).
- Emit CycloneDX 1.6 (and optionally SPDX 2.3).
- Re-run against Stage 0's targets and confirm measurable improvement over the generic
  baseline — this improvement number is your second headline result.

### Weeks 6-8: Stage 2 — Automotive-Context VEX Layer
- Map Stage 1's CVE output to CVEs.
- Build the rules layer for automotive usage-context suppression (disabled Bluetooth
  profiles, network isolation, reachability where feasible).
- Generate OpenVEX statements with proper justification codes.
- Add the human-approval gate (never auto-suppress silently).
- Benchmark the false-positive reduction against your own Stage 0 numbers (see
  `02_RESEARCH_FINDINGS.md` corrections for which external benchmarks are safe to cite
  for comparison).

### Weeks 9-10: Stage 3 — Runtime Drift Detector
- Build the Pi 5 daemon: periodic re-inventory of loaded libraries, package hashes,
  kernel modules.
- Diff against the baseline SBOM.
- **Do this alongside Tier 2's signing work** (below) so the baseline the daemon trusts
  is a *signed* baseline from day one, not something to retrofit later.
- Demo: swap a shared library, confirm detection with zero false alarms over a clean
  24-hour run.

### Weeks 11-12 (Tier 2): Signing + Dashboard
- Add cosign keyless signing to the Stage 1 SBOM and the Stage 3 baseline.
- Add Rekor-inclusion verification to the drift daemon before it trusts a baseline.
- Stand up Dependency-Track; feed it your CycloneDX + VEX output.
- Build the custom attack-surface heatmap and drift timeline views.
- Generate a CycloneDX Sunshine HTML report per build.
- Record the 60-90 second demo video (heatmap → before/after VEX chart → drift
  timeline with a flagged event → signature-verified indicator).

### Weeks 13+ (Tier 3, if time allows): CI/CD + Demo Firmware
- GitHub Actions: Syft → Grype → VEX filter → cosign sign → gate → Dependency-Track
  upload. Frame in the README as "continuous compliance" mapped to R155/CRA (with the
  honest caveat about ENISA's portal-only reporting reality — see research doc).
- Build the demo firmware: SocketCAN + MCP2515 HAT + ICSim, a basic UDS service, BlueZ,
  and a stubbed OTA client, so the whole pipeline runs against realistic automotive
  components with real CVEs to find.

---

## Repo/writeup checklist (do this regardless of how far you get)
- [ ] README with the PerfektBlue story up front as the "why."
- [ ] Explicit "what this is / isn't" scope section (see `00_PROJECT_BRIEF.md`).
- [ ] Stage 0 benchmark numbers presented as a table, with 2-3 worked examples.
- [ ] Architecture diagram (can be simple — the four stages plus signing/dashboard).
- [ ] Every external citation double-checked against the corrections in
      `02_RESEARCH_FINDINGS.md`.
- [ ] Mapping paragraph: which R155/ISO 21434/CRA concepts each stage demonstrates
      (prose is fine — don't build a formal report generator unless doing Tier 4).
- [ ] Demo video linked/embedded.
- [ ] Clear "future work" section listing anything from Tier 4 you didn't build, framed
      as awareness rather than as claimed capability.
