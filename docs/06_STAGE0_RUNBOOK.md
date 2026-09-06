# Stage 0 Runbook — Producing the Real Benchmark Numbers

The harness (`autosbom benchmark`) is implemented and tested against
synthetic fixtures. The *headline artifact* — measured precision/recall of
generic tools against real automotive-style images — requires the steps
below on a machine with the tools installed and ~20+ GB free disk. Nothing
in the repo claims these numbers exist until you produce them.

## 1. Ground truth targets

**A. AGL pre-built image + official SPDX SBOM.** AGL publishes pre-built
images with SPDX SBOMs on its download server
(https://download.automotivelinux.org/AGL/release/ — pick a current release,
e.g. an ARM64 IVI demo image; the SPDX files sit alongside the image
artifacts, produced by Yocto's SPDX class). Download both the rootfs image
and its `.spdx.json`. If the layout has changed, the AGL documentation site
is the reference — flag any discrepancy rather than guessing.

**B. Your own Yocto/Buildroot image** (second target, fully known
composition). For Buildroot: `make raspberrypi5_defconfig && make` with
`BR2_PKG_STATS` / legal-info output as your composition record; for Yocto
enable `INHERIT += "create-spdx"` so the build emits SPDX ground truth
itself.

## 2. Extract the rootfs

```sh
# ext4 image example
mkdir rootfs && sudo mount -o loop,ro agl-image.ext4 /mnt && cp -a /mnt/. rootfs/
# or use binwalk for opaque formats: autosbom generate handles this too
```

## 3. Run the generic tools

```sh
syft dir:rootfs -o json > syft-agl.json
trivy fs --format json --list-all-pkgs rootfs > trivy-agl.json
# EMBA (heavyweight; run in its container):
sudo ./emba -l ./emba-log -f /path/to/agl-image -p ./scan-profiles/default-scan.emba
# then take the CycloneDX SBOM from the EMBA log directory (SBOM module output)
```

## 4. Score against ground truth

```sh
autosbom benchmark \
  --ground-truth agl-image.spdx.json \
  --tool-output syft=syft-agl.json \
  --tool-output trivy=trivy-agl.json \
  --tool-output emba=emba-sbom.cdx.json \
  --target-name "AGL <release> <image>" \
  --output stage0-results.md --json-output stage0-results.json
```

Component-name aliasing WILL need extending: inspect the reported false
positives/negatives for cases where two names mean the same component and
add them to `DEFAULT_ALIASES` in `autosbom/stage0_benchmark/compare.py`
(every entry should come from an observed mismatch — commit them with the
observation in the message).

## 5. CVE accuracy sample (the manual part)

Pick 20-40 reported CVEs across tools. For each, determine the true status
against the image (`affected` / `fixed` (backport!) / `not_present` /
`not_reachable`) using the distro's changelog, Yocto `cve-check` output, and
the actual image config. Record them as a JSON map and score with
`compare_cves` (see `tests/test_stage0.py` for the shape). *Only* verified
CVEs are scored; do not extrapolate.

## 6. Write it up

Fill the table + 2-3 worked examples per failure mode into the report
`autosbom benchmark` gives you, and only then cite your own numbers anywhere
public. Per `docs/02_RESEARCH_FINDINGS.md` (Corrections): do not transplant
general-software benchmark numbers onto firmware claims.
