# Demo Target — Deliberately Vulnerable Fixture

`requirements.txt` in this directory pins old versions of well-known
Python packages that carry multiple publicly-documented CVEs. It exists
for exactly one reason: **so the CI pipeline (`.github/workflows/sbom-pipeline.yml`)
has real, non-zero vulnerability data to generate, scan, filter, and sign** —
proving the full chain end-to-end against genuine findings, not the tool's
own source (which has zero runtime dependencies by design and always
scans clean).

## This is not:
- Something to install (`pip install -r demo-target/requirements.txt` is a
  bad idea on any machine you care about)
- A real dependency of AutoSBOM-Sentinel — `pyproject.toml` still declares
  `dependencies = []`; this file has no effect on `pip install -e .`
- A claim about which specific CVEs apply — the exact CVE IDs are whatever
  the live scan's vulnerability database reports at scan time, not
  hardcoded or asserted here

## What it's for
Syft's `path: .` scan in the CI workflow walks the whole repo and
auto-detects this `requirements.txt` as a Python/pip target alongside the
tool's own source, exactly like it would for a real project. Grype then
reports real CVEs against these real (old) package versions. This is the
same mechanism a real user would rely on when scanning their own project —
demonstrated here on a fixture instead of on someone else's real,
possibly-still-in-use dependency tree.
