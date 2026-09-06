from pathlib import Path

from autosbom.common.models import Component, Sbom, Vulnerability
from autosbom.dashboard.heatmap import build_heatmap, categorize
from autosbom.dashboard.html_report import render_report

FIXTURES = Path(__file__).parent / "fixtures"


def _sample_sbom():
    return Sbom(
        components=[
            Component(name="bluez5", version="5.66"),
            Component(name="openssl", version="3.0.7"),
            Component(name="swupdate", version="2023.05"),
            Component(name="can-utils", version="2023.03"),
            Component(name="zlib", version="1.2.13"),
        ],
        target="pi5-demo-image",
    )


def _sample_vulns():
    return [
        Vulnerability(cve_id="CVE-2024-45434", component="bluez5",
                      severity="CRITICAL", cvss=8.0),
        Vulnerability(cve_id="CVE-2024-45433", component="bluez5",
                      severity="MEDIUM", cvss=5.7),
        Vulnerability(cve_id="CVE-2023-0464", component="openssl",
                      severity="HIGH", cvss=7.5),
        Vulnerability(cve_id="CVE-2022-9999", component="zlib",
                      severity="MEDIUM", cvss=5.0),
    ]


def test_categorize():
    assert categorize("bluez5") == "bluetooth"
    assert categorize("openssl") == "network-facing"
    assert categorize("swupdate") == "ota-update"
    assert categorize("can-utils") == "can-bus"
    assert categorize("libwhatever") == "base-system"


def test_build_heatmap_counts_and_suppression():
    cells = build_heatmap(_sample_sbom(), _sample_vulns(),
                          suppressed_cves={"CVE-2024-45434"})
    by_cat = {c.category: c for c in cells}
    bt = by_cat["bluetooth"]
    assert bt.component_count == 1
    assert bt.cve_count == 2
    assert bt.suppressed_cve_count == 1
    assert bt.actionable_cve_count == 1
    assert by_cat["network-facing"].cve_count == 1
    assert by_cat["ota-update"].component_count == 1
    # max CVSS only counts non-suppressed findings
    assert bt.max_cvss == 5.7


def test_render_report_contains_all_sections(tmp_path):
    drift_events = [
        {"timestamp": "2026-01-01T00:00:00Z", "kind": "sweep-complete",
         "baseline_verified": True, "drift_events": 0,
         "libraries_checked": 100, "packages_checked": 50,
         "kernel_modules_checked": 10},
        {"timestamp": "2026-01-01T01:00:00Z", "kind": "library-hash-mismatch",
         "subject": "/lib/libdemo.so.1", "detail": "baseline=aa current=bb",
         "severity": "critical", "baseline_verified": True},
    ]
    html = render_report(_sample_sbom(), _sample_vulns(),
                         suppressed_cves={"CVE-2024-45434"},
                         drift_events=drift_events, baseline_verified=True)
    assert "Attack-surface heatmap" in html
    assert "raw vs. post-VEX" in html
    assert "Runtime drift timeline" in html
    assert "library-hash-mismatch" in html
    assert "baseline signature verified" in html
    assert "pi5-demo-image" in html
    # accessibility: table fallbacks present, legend present
    assert html.count("Data table") >= 2
    assert "Raw CVE count" in html
    # theme handling: light + dark custom properties defined
    assert "prefers-color-scheme: dark" in html
    assert 'data-theme="dark"' in html
    # untrusted strings are escaped
    evil = _sample_sbom()
    evil.target = "<script>alert(1)</script>"
    html2 = render_report(evil, [], set(), [])
    assert "<script>alert(1)</script>" not in html2


def test_render_report_unverified_baseline_warns():
    html = render_report(_sample_sbom(), [], set(),
                         [{"timestamp": "t", "kind": "sweep-complete",
                           "baseline_verified": False, "drift_events": 0,
                           "libraries_checked": 1, "packages_checked": 0,
                           "kernel_modules_checked": 0}],
                         baseline_verified=False)
    assert "UNVERIFIED" in html
