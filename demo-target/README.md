# Demo Target — Deliberately Vulnerable Fixture

`requirements.txt` (Python/pip) and `package.json` (Node/npm) in this
directory pin old versions of well-known packages that carry multiple
publicly-documented CVEs, across two ecosystems. It exists for exactly one
reason: **so the CI pipeline (`.github/workflows/sbom-pipeline.yml`) has
real, non-zero, multi-ecosystem vulnerability data to generate, scan,
filter, and sign** — proving the full chain end-to-end against genuine
findings, not the tool's own source (which has zero runtime dependencies
by design and always scans clean).

## This is not:
- Something to install (`pip install -r demo-target/requirements.txt` or
  `npm install` in this directory are bad ideas on any machine you care
  about)
- A real dependency of AutoSBOM-Sentinel — `pyproject.toml` still declares
  `dependencies = []`; neither file has any effect on `pip install -e .`
- A claim about which specific CVEs apply — the exact CVE IDs are whatever
  the live scan's vulnerability database reports at scan time, not
  hardcoded or asserted here

## What it's for
Syft's `path: .` scan in the CI workflow walks the whole repo and
auto-detects both manifests as real ecosystem targets, exactly like it
would for a real project with both a Python and a Node component. Grype
then reports real CVEs against these real (old) package versions across
both ecosystems — giving the attack-surface heatmap (`autosbom report`)
more categories to actually light up than a single-ecosystem scan would.
This is the same mechanism a real user would rely on when scanning their
own project — demonstrated here on a fixture instead of on someone else's
real, possibly-still-in-use dependency tree.
