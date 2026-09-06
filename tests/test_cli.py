"""End-to-end CLI smoke tests exercising the full pipeline with fixtures."""
import json
from pathlib import Path

from autosbom.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_benchmark_command(tmp_path, capsys):
    out_md = tmp_path / "report.md"
    out_json = tmp_path / "report.json"
    rc = main([
        "benchmark",
        "--ground-truth", str(FIXTURES / "ground_truth.spdx.json"),
        "--tool-output", f"syft={FIXTURES / 'syft_output.json'}",
        "--tool-output", f"trivy={FIXTURES / 'trivy_output.json'}",
        "--target-name", "synthetic-image",
        "--output", str(out_md),
        "--json-output", str(out_json),
    ])
    assert rc == 0
    md = out_md.read_text()
    assert "| syft |" in md and "| trivy |" in md
    data = json.loads(out_json.read_text())
    assert len(data) == 2


def test_generate_command_on_directory(tmp_path):
    rootfs = tmp_path / "rootfs" / "usr" / "lib"
    rootfs.mkdir(parents=True)
    # borrow the minimal-ELF builder from the stage1 tests
    from tests.test_stage1 import _minimal_elf
    (rootfs / "libdemo.so.1.0").write_bytes(_minimal_elf(False))
    out = tmp_path / "out"
    rc = main([
        "generate", str(tmp_path / "rootfs"),
        "--workdir", str(tmp_path / "work"),
        "--output-dir", str(out),
    ])
    assert rc == 0
    doc = json.loads((out / "sbom.cdx.json").read_text())
    assert doc["specVersion"] == "1.6"
    names = {c["name"] for c in doc["components"]}
    assert "demo" in names


def test_vex_full_workflow(tmp_path, capsys):
    store = tmp_path / "review.json"
    rc = main([
        "vex", "--review-store", str(store), "propose",
        "--findings", str(FIXTURES / "grype_output.json"),
        "--findings-format", "grype",
        "--context", str(FIXTURES / "device-context.json"),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pending human review" in out

    # export before approval must fail
    rc = main([
        "vex", "--review-store", str(store), "export",
        "--output", str(tmp_path / "vex.json"),
        "--author", "Michael", "--product-purl", "pkg:generic/demo",
    ])
    assert rc == 1

    rc = main([
        "vex", "--review-store", str(store), "approve",
        "--cve", "CVE-2024-45434", "--component", "bluez5",
        "--reviewer", "Michael", "--note", "AVRCP verified disabled",
    ])
    assert rc == 0

    rc = main([
        "vex", "--review-store", str(store), "export",
        "--output", str(tmp_path / "vex.json"),
        "--author", "Michael", "--product-purl", "pkg:generic/demo",
    ])
    assert rc == 0
    doc = json.loads((tmp_path / "vex.json").read_text())
    assert len(doc["statements"]) == 1


def test_baseline_and_drift_once(tmp_path, capsys):
    libdir = tmp_path / "lib"
    libdir.mkdir()
    (libdir / "liba.so.1").write_bytes(b"\x7fELF-aaa")
    baseline = tmp_path / "baseline.json"
    rc = main(["baseline", "--output", str(baseline), "--lib-dirs", str(libdir)])
    assert rc == 0

    # clean sweep -> rc 0
    rc = main([
        "drift", "--baseline", str(baseline),
        "--allow-unverified-baseline",
        "--event-log", str(tmp_path / "events.jsonl"),
        "--lib-dirs", str(libdir), "--once",
    ])
    assert rc == 0

    # tamper -> rc 3
    (libdir / "liba.so.1").write_bytes(b"\x7fELF-TAMPERED")
    rc = main([
        "drift", "--baseline", str(baseline),
        "--allow-unverified-baseline",
        "--event-log", str(tmp_path / "events.jsonl"),
        "--lib-dirs", str(libdir), "--once",
    ])
    assert rc == 3


def test_report_command(tmp_path):
    # build a small CycloneDX doc via the generator API
    from autosbom.common.models import Component, Sbom
    from autosbom.stage1_generator.cyclonedx import export_cyclonedx_json

    sbom = Sbom(components=[Component(name="bluez5", version="5.66")],
                target="demo")
    cdx = tmp_path / "sbom.cdx.json"
    cdx.write_text(json.dumps(export_cyclonedx_json(sbom)))

    out = tmp_path / "report.html"
    rc = main([
        "report", "--sbom", str(cdx),
        "--findings", str(FIXTURES / "grype_output.json"),
        "--output", str(out),
        "--target-name", "demo-image",
    ])
    assert rc == 0
    html = out.read_text()
    assert "Attack-surface heatmap" in html
