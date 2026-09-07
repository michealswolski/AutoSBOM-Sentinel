# Changelog

All notable changes to this project are documented in this file.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/),
versioning follows [Semantic Versioning](https://semver.org/) once the
project reaches 1.0 — before that, minor bumps mark meaningful checkpoints
rather than strict API stability guarantees.

## [Unreleased]

### Fixed
- `autosbom/stage0_benchmark/tool_adapters.py`: the Syft/Trivy/Grype/CycloneDX
  JSON parsers now validate the parsed document is an object before reading
  fields from it, matching every other loader hardened in 0.2.0. A
  syntactically-valid but wrong-shaped file (e.g. a bare JSON array) previously
  crashed with a raw `AttributeError` traceback instead of a clean, file-named
  error — found by a follow-up code review. 5 new regression tests
  (`tests/test_hardening.py`); suite is now 69 of 70 tests passing.

## [0.2.0] — 2026-09-07

### Changed
- **License**: switched from MIT to an all-rights-reserved license
  requiring prior written consent for any use beyond evaluating the code.
  See [LICENSE](LICENSE).

### Added
- Defensive error handling across every file/subprocess boundary
  (`autosbom/common/io_utils.py`): malformed JSON/YAML, missing files, and
  failed external tools now fail with a clear, file-named message instead
  of a raw traceback. The CLI's `main()` catches expected operational
  failures and exits cleanly with code 1.
- `demo-target/`: a deliberately-vulnerable fixture (old pinned package
  versions) so the CI pipeline's Syft+Grype scan has real, non-fabricated
  CVEs to find, filter, and report on — verified live: a triggered run
  reported 120 real findings.
- 15 new tests covering the hardening changes (`tests/test_hardening.py`).

## [0.1.0] — 2026-09-06

Initial implementation: Stages 0-3 (benchmark harness, automotive-tuned
SBOM generator, VEX layer with mandatory human approval, runtime drift
detector), signing scripts, dashboard HTML report, CI/CD pipeline, demo
firmware scripts, and the CLI tying it all together. See the README's
"Honest status ledger" for what was verified at this point versus what
still needed real hardware/network access.
