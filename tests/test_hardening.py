"""Error-handling hardening: malformed input gets a clear message naming
the offending file, not a bare traceback; the CLI exits cleanly (code 1,
one-line stderr message) on expected operational failures.
"""
import subprocess
import sys

import pytest

from autosbom.cli import main
from autosbom.common.io_utils import load_json, load_yaml_or_json
from autosbom.common.spdx import load_spdx_json
from autosbom.stage0_benchmark import tool_adapters as ta
from autosbom.stage2_vex.context import DeviceContext
from autosbom.stage2_vex.review import ReviewStore
from autosbom.stage3_drift.inventory import Inventory


def test_load_json_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_json(tmp_path / "does-not-exist.json")


def test_load_json_malformed_names_file_and_location(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    with pytest.raises(ValueError, match=r"bad\.json.*not valid JSON.*line"):
        load_json(bad)


def test_load_yaml_or_json_malformed_yaml(tmp_path):
    pytest.importorskip("yaml", reason="PyYAML is an optional extra")
    bad = tmp_path / "bad.yaml"
    bad.write_text("key: [unbalanced\n")
    with pytest.raises(ValueError, match=r"bad\.yaml.*not valid YAML"):
        load_yaml_or_json(bad)


def test_load_yaml_or_json_missing_pyyaml_gives_clear_message(tmp_path, monkeypatch):
    """Without PyYAML installed, a .yaml file should fail with actionable
    guidance instead of a bare ModuleNotFoundError."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name == "yaml":
            raise ImportError("simulated: PyYAML not installed")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    bad = tmp_path / "context.yaml"
    bad.write_text("device_name: demo\n")
    with pytest.raises(RuntimeError, match="PyYAML is not installed"):
        load_yaml_or_json(bad)


def test_spdx_rejects_non_spdx_json(tmp_path):
    not_spdx = tmp_path / "not-spdx.json"
    not_spdx.write_text('{"hello": "world"}')
    with pytest.raises(ValueError, match="doesn't look like an SPDX document"):
        load_spdx_json(not_spdx)


def test_spdx_malformed_json_error_names_file(tmp_path):
    bad = tmp_path / "truth.spdx.json"
    bad.write_text("not json at all")
    with pytest.raises(ValueError, match="truth.spdx.json"):
        load_spdx_json(bad)


def test_grype_parser_malformed_json(tmp_path):
    bad = tmp_path / "grype.json"
    bad.write_text("{broken")
    with pytest.raises(ValueError, match="grype.json"):
        ta.parse_grype_json(bad)


def test_grype_parser_rejects_wrong_shape(tmp_path):
    # Syntactically-valid JSON that isn't grype's expected object shape
    # (e.g. a bare list) must not fall through to a raw AttributeError
    # from calling .get() on a list.
    wrong_shape = tmp_path / "grype.json"
    wrong_shape.write_text("[1, 2, 3]")
    with pytest.raises(ValueError, match="doesn't look like grype JSON output"):
        ta.parse_grype_json(wrong_shape)


def test_syft_parser_rejects_wrong_shape(tmp_path):
    wrong_shape = tmp_path / "syft.json"
    wrong_shape.write_text("[1, 2, 3]")
    with pytest.raises(ValueError, match="doesn't look like syft JSON output"):
        ta.parse_syft_json(wrong_shape)


def test_trivy_parser_rejects_wrong_shape(tmp_path):
    wrong_shape = tmp_path / "trivy.json"
    wrong_shape.write_text("[1, 2, 3]")
    with pytest.raises(ValueError, match="doesn't look like trivy JSON output"):
        ta.parse_trivy_json(wrong_shape)


def test_cyclonedx_parser_rejects_wrong_shape(tmp_path):
    wrong_shape = tmp_path / "cdx.json"
    wrong_shape.write_text("[1, 2, 3]")
    with pytest.raises(ValueError, match="doesn't look like CycloneDX JSON output"):
        ta.parse_cyclonedx_json(wrong_shape)


def test_cli_wrong_shape_findings_exits_clean_not_traceback(tmp_path, capsys):
    """End-to-end: a syntactically-valid but wrong-shaped grype findings
    file must produce a clean CLI error, not an uncaught AttributeError."""
    ctx = tmp_path / "context.json"
    ctx.write_text('{"device_name": "d"}')
    wrong_shape = tmp_path / "findings.grype.json"
    wrong_shape.write_text("[1, 2, 3]")
    rc = main([
        "vex", "--review-store", str(tmp_path / "review.json"), "propose",
        "--findings", str(wrong_shape), "--context", str(ctx),
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "Traceback" not in err


def test_device_context_rejects_non_object(tmp_path):
    bad = tmp_path / "context.json"
    bad.write_text("[1, 2, 3]")
    with pytest.raises(ValueError, match="must be a JSON/YAML object"):
        DeviceContext.load(bad)


def test_review_store_rejects_non_object(tmp_path):
    bad = tmp_path / "review.json"
    bad.write_text("[1, 2, 3]")
    with pytest.raises(ValueError, match="must be a JSON object"):
        ReviewStore.load(bad)


def test_inventory_rejects_non_object(tmp_path):
    bad = tmp_path / "baseline.json"
    bad.write_text('"just a string"')
    with pytest.raises(ValueError, match="must be a JSON object"):
        Inventory.load(bad)


def test_run_and_capture_reports_tool_failure(monkeypatch, tmp_path):
    # A command that exits non-zero should surface as RuntimeError naming
    # the tool and its exit status, not a raw CalledProcessError traceback.
    with pytest.raises(RuntimeError, match=r"false exited with status"):
        ta._run_and_capture(["false"], timeout=5)


def test_cli_missing_file_exits_clean_not_traceback(tmp_path, capsys):
    rc = main([
        "benchmark",
        "--ground-truth", str(tmp_path / "nope.json"),
        "--tool-output", f"syft={tmp_path / 'also-nope.json'}",
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "Traceback" not in err


def test_cli_malformed_findings_exits_clean(tmp_path, capsys):
    ctx = tmp_path / "context.json"
    ctx.write_text('{"device_name": "d"}')
    bad_findings = tmp_path / "findings.json"
    bad_findings.write_text("not json")
    rc = main([
        "vex", "--review-store", str(tmp_path / "review.json"), "propose",
        "--findings", str(bad_findings), "--context", str(ctx),
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err


def test_cli_as_subprocess_never_dumps_a_traceback(tmp_path):
    """End-to-end: invoke the real console entry point against bad input and
    confirm stderr is a clean message, not a Python traceback, regardless of
    any in-process test-harness behavior."""
    result = subprocess.run(
        [sys.executable, "-m", "autosbom.cli", "baseline",
         "--output", str(tmp_path / "out.json"),
         "--lib-dirs", str(tmp_path / "does-not-exist")],
        capture_output=True, text=True,
    )
    # A nonexistent lib-dir is swept as empty (not an error) -- this call
    # should actually succeed; the point is simply that it doesn't crash.
    assert result.returncode == 0
    assert "Traceback" not in result.stderr


def test_load_drift_log_tolerates_truncated_last_line(tmp_path, capsys):
    from autosbom.dashboard.html_report import load_drift_log

    log = tmp_path / "drift.jsonl"
    good1 = '{"timestamp": "t1", "kind": "sweep-complete", "drift_events": 0}'
    good2 = '{"timestamp": "t2", "kind": "sweep-complete", "drift_events": 0}'
    truncated = '{"timestamp": "t3", "kind": "library-hash-mism'  # cut off mid-write
    log.write_text(f"{good1}\n{good2}\n{truncated}")

    events = load_drift_log(str(log))
    assert len(events) == 2
    assert events[0]["timestamp"] == "t1"
    assert events[1]["timestamp"] == "t2"
    assert "skipping malformed" in capsys.readouterr().err
