import json
from pathlib import Path

from autosbom.common.spdx import export_spdx_json, load_spdx_json
from autosbom.stage0_benchmark import tool_adapters as ta
from autosbom.stage0_benchmark.compare import (
    canonical, compare_components, compare_cves,
)
from autosbom.stage0_benchmark.report import render_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_spdx_ground_truth():
    sbom = load_spdx_json(FIXTURES / "ground_truth.spdx.json")
    assert len(sbom.components) == 6
    ssl = sbom.find("openssl")
    assert ssl is not None
    assert ssl.version == "3.0.8"
    assert ssl.purl == "pkg:generic/openssl@3.0.8"
    assert "Apache-2.0" in ssl.licenses


def test_spdx_roundtrip():
    sbom = load_spdx_json(FIXTURES / "ground_truth.spdx.json")
    doc = export_spdx_json(sbom)
    assert doc["spdxVersion"] == "SPDX-2.3"
    names = {p["name"] for p in doc["packages"]}
    assert "openssl" in names and "bluez5" in names


def test_parse_syft():
    sbom = ta.parse_syft_json(FIXTURES / "syft_output.json")
    assert sbom.tool == "syft"
    assert len(sbom.components) == 5
    assert sbom.find("busybox").version == ""


def test_parse_trivy():
    sbom = ta.parse_trivy_json(FIXTURES / "trivy_output.json")
    assert sbom.tool == "trivy"
    assert len(sbom.components) == 3
    assert len(sbom.vulnerabilities) == 3
    crit = [v for v in sbom.vulnerabilities if v.cve_id == "CVE-2024-45434"][0]
    assert crit.severity == "CRITICAL"
    assert crit.cvss == 8.0


def test_parse_grype():
    sbom = ta.parse_grype_json(FIXTURES / "grype_output.json")
    assert {v.cve_id for v in sbom.vulnerabilities} == {
        "CVE-2024-45434", "CVE-2023-0464", "CVE-2022-9999"
    }


def test_alias_canonicalization():
    assert canonical("libc6") == "glibc"
    assert canonical("zlib1g") == "zlib"
    assert canonical("bluez5") == "bluez"
    assert canonical("Unknown_Pkg") == "unknown-pkg"


def test_compare_components_syft_vs_truth():
    truth = load_spdx_json(FIXTURES / "ground_truth.spdx.json")
    reported = ta.parse_syft_json(FIXTURES / "syft_output.json")
    result = compare_components(reported, truth, target="synthetic-image")

    # syft found openssl/zlib(as zlib1g)/busybox/libc6(glibc); missed
    # bluez5 and wpa-supplicant; libpng is a false positive.
    assert set(result.true_positives) == {"openssl", "zlib", "busybox", "glibc"}
    assert result.false_positives == ["libpng"]
    assert set(result.false_negatives) == {"bluez", "wpa_supplicant"}
    # openssl 3.0.7 vs truth 3.0.8 — the backport-style version mismatch.
    assert ("openssl", "3.0.7", "3.0.8") in result.version_mismatches
    # busybox reported with empty version — the stripped-binary failure mode.
    assert "busybox" in result.unknown_version_reports
    assert 0 < result.precision < 1
    assert 0 < result.recall < 1


def test_compare_cves_verified_sample():
    reported = ta.parse_trivy_json(FIXTURES / "trivy_output.json")
    verified = {
        "CVE-2023-0464": "affected",
        "CVE-2022-9999": "fixed",          # backported without version bump
        "CVE-2024-45434": "not_reachable", # AVRCP disabled on this device
        "CVE-2020-0001": "affected",       # missed entirely by the tool
    }
    result = compare_cves(reported, verified)
    assert result.true_positives == ["CVE-2023-0464"]
    assert ("CVE-2022-9999", "fixed") in result.false_positives
    assert ("CVE-2024-45434", "not_reachable") in result.false_positives
    assert result.false_negatives == ["CVE-2020-0001"]


def test_markdown_report_renders():
    truth = load_spdx_json(FIXTURES / "ground_truth.spdx.json")
    reported = ta.parse_syft_json(FIXTURES / "syft_output.json")
    comp = compare_components(reported, truth, target="synthetic-image")
    md = render_markdown([comp])
    assert "| syft |" in md
    assert "Version mismatch example" in md
    assert "stripped-binary failure mode" in md


def test_comparison_to_dict_is_json_serializable():
    truth = load_spdx_json(FIXTURES / "ground_truth.spdx.json")
    reported = ta.parse_syft_json(FIXTURES / "syft_output.json")
    comp = compare_components(reported, truth)
    json.dumps(comp.to_dict())


def test_cyclonedx_roundtrip_restores_flags(tmp_path):
    import json as _json
    from autosbom.common.models import Component, Sbom
    from autosbom.stage1_generator.cyclonedx import export_cyclonedx_json

    sbom = Sbom(components=[Component(
        name="mystery", version="", version_unknown=True,
        identification_confidence=0.3,
        flags=["stripped-binary", "needs-manual-review"])])
    p = tmp_path / "x.cdx.json"
    p.write_text(_json.dumps(export_cyclonedx_json(sbom)))
    back = ta.parse_cyclonedx_json(p)
    c = back.components[0]
    assert c.version_unknown
    assert "needs-manual-review" in c.flags
    assert c.identification_confidence == 0.3
