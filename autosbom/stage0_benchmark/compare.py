"""Compare a tool-reported SBOM against a ground-truth SBOM.

Produces component-level precision/recall plus per-item classification so the
report can show *worked examples* of each failure mode, not just aggregate
numbers (per docs/01_ARCHITECTURE.md Stage 0).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..common.models import Sbom, normalize_name

# Known cross-tool aliases: distros and scanners name the same upstream
# component differently. Extend this table as real benchmark runs surface
# more cases — every entry should come from an actually-observed mismatch.
DEFAULT_ALIASES: dict[str, str] = {
    "libc6": "glibc",
    "libc-bin": "glibc",
    "libssl1.1": "openssl",
    "libssl3": "openssl",
    "openssl-libs": "openssl",
    "libcrypto3": "openssl",
    "zlib1g": "zlib",
    "libz1": "zlib",
    "busybox-static": "busybox",
    "linux-libc-dev": "linux",
    "linux-kernel": "linux",
    "kernel": "linux",
    "libsystemd0": "systemd",
    "libudev1": "systemd",
    "dbus-libs": "dbus",
    "libdbus-1-3": "dbus",
    "libcurl4": "curl",
    "libcurl3-gnutls": "curl",
    "curl-minimal": "curl",
    "libexpat1": "expat",
    "libpcre3": "pcre",
    "libpcre2-8-0": "pcre2",
    "bluez5": "bluez",
    "bluez-libs": "bluez",
    "libbluetooth3": "bluez",
    "wpa-supplicant": "wpa_supplicant",
    "libglib2.0-0": "glib",
    "glib2": "glib",
    "glib-2.0": "glib",
}


def canonical(name: str, aliases: dict[str, str] | None = None) -> str:
    n = normalize_name(name)
    table = {**DEFAULT_ALIASES, **(aliases or {})}
    return table.get(n, n)


@dataclass
class ComponentComparison:
    """Result of comparing one tool's component list to ground truth."""

    tool: str
    target: str
    true_positives: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)   # reported, not in ground truth
    false_negatives: list[str] = field(default_factory=list)   # in ground truth, missed
    version_mismatches: list[tuple[str, str, str]] = field(default_factory=list)
    # (name, reported_version, truth_version) — found but version differs;
    # counted inside true_positives for presence, listed separately because
    # version mismatch is exactly what turns into CVE false positives later.
    unknown_version_reports: list[str] = field(default_factory=list)
    # reported with an empty version — the stripped-binary failure mode.

    @property
    def precision(self) -> float:
        denom = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = len(self.true_positives) + len(self.false_negatives)
        return len(self.true_positives) / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "target": self.target,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "true_positives": sorted(self.true_positives),
            "false_positives": sorted(self.false_positives),
            "false_negatives": sorted(self.false_negatives),
            "version_mismatches": sorted(self.version_mismatches),
            "unknown_version_reports": sorted(self.unknown_version_reports),
        }


def compare_components(
    reported: Sbom,
    ground_truth: Sbom,
    aliases: dict[str, str] | None = None,
    target: str = "",
) -> ComponentComparison:
    """Component-presence comparison with version-mismatch tracking."""
    truth_map: dict[str, str] = {}
    for c in ground_truth.components:
        truth_map[canonical(c.name, aliases)] = c.version

    reported_map: dict[str, str] = {}
    for c in reported.components:
        key = canonical(c.name, aliases)
        # Keep the first version seen; duplicates across ecosystems collapse.
        reported_map.setdefault(key, c.version)

    result = ComponentComparison(tool=reported.tool, target=target or reported.target)

    for key, version in sorted(reported_map.items()):
        if key in truth_map:
            result.true_positives.append(key)
            truth_ver = truth_map[key]
            if version and truth_ver and version != truth_ver:
                result.version_mismatches.append((key, version, truth_ver))
        else:
            result.false_positives.append(key)
        if not version:
            result.unknown_version_reports.append(key)

    for key in sorted(truth_map):
        if key not in reported_map:
            result.false_negatives.append(key)

    return result


@dataclass
class CveComparison:
    """Compare reported CVEs against a manually-verified truth list.

    ``verified_status`` maps CVE id -> one of:
      "affected"      — genuinely applies to the image as configured
      "fixed"         — patched (e.g. distro backport without version bump)
      "not_present"   — component not actually in the image
      "not_reachable" — present but not in any execute path / disabled
    Anything reported whose status is not "affected" is a false positive;
    any "affected" CVE not reported is a false negative.
    """

    tool: str
    true_positives: list[str] = field(default_factory=list)
    false_positives: list[tuple[str, str]] = field(default_factory=list)  # (cve, reason)
    false_negatives: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = len(self.true_positives) + len(self.false_negatives)
        return len(self.true_positives) / denom if denom else 0.0


def compare_cves(reported: Sbom, verified_status: dict[str, str]) -> CveComparison:
    result = CveComparison(tool=reported.tool)
    reported_ids = {v.cve_id for v in reported.vulnerabilities if v.cve_id}
    for cve in sorted(reported_ids):
        status = verified_status.get(cve)
        if status == "affected":
            result.true_positives.append(cve)
        elif status is None:
            # Not in the verified sample — excluded from scoring rather than
            # guessed at. Only manually-verified CVEs are counted either way.
            continue
        else:
            result.false_positives.append((cve, status))
    for cve, status in sorted(verified_status.items()):
        if status == "affected" and cve not in reported_ids:
            result.false_negatives.append(cve)
    return result
