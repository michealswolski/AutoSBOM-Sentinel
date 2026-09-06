"""Yocto/Buildroot backport annotation handling.

The single biggest documented false-positive mechanism for embedded Linux:
a distro backports a CVE fix without bumping the component's version string,
so any version-range matcher keeps flagging the already-fixed CVE.

Yocto records this in recipe metadata:
  - modern syntax:  CVE_STATUS[CVE-2023-1234] = "backported-patch: fixed in..."
                    CVE_STATUS[CVE-2023-9999] = "not-applicable-config: ..."
  - legacy syntax:  CVE_CHECK_IGNORE += "CVE-2021-0001 CVE-2021-0002"
  - and `cve-check` output files list "Patched" CVEs per recipe.

This module parses those annotations out of a build tree (or a saved copy of
the recipe metadata) into a {cve_id: status} map that Stage 2 consumes to
propose VEX "fixed"/"not_affected" statements — proposed, never auto-applied
(see stage2_vex.review).
"""
from __future__ import annotations

import re
from pathlib import Path

# CVE_STATUS[CVE-2023-1234] = "backported-patch: <reason>"
_CVE_STATUS = re.compile(
    r'CVE_STATUS\[(CVE-\d{4}-\d{4,})\]\s*=\s*"([^":]+)(?::\s*([^"]*))?"'
)
# CVE_CHECK_IGNORE += "CVE-2021-0001 CVE-2021-0002"
_CVE_CHECK_IGNORE = re.compile(r'CVE_CHECK_IGNORE\s*[+:]?=\s*"([^"]+)"')
# cve-check text output lines: "CVE: CVE-2023-1234" followed near
# "CVE STATUS: Patched"
_CVE_LINE = re.compile(r"^CVE:\s*(CVE-\d{4}-\d{4,})", re.MULTILINE)

# Yocto CVE_STATUS status keywords → normalized status used by Stage 2.
_STATUS_MAP = {
    "backported-patch": "fixed",
    "cpe-incorrect": "not_affected",
    "disputed": "not_affected",
    "fixed-version": "fixed",
    "fix-file-included": "fixed",
    "not-applicable-config": "not_affected",
    "not-applicable-platform": "not_affected",
    "upstream-wontfix": "under_investigation",
    "vulnerable-investigating": "under_investigation",
    "ignored": "not_affected",
}


def parse_recipe_text(text: str) -> dict[str, dict]:
    """Parse CVE annotations from one recipe/.bb/.bbappend/.inc file's text."""
    results: dict[str, dict] = {}
    for m in _CVE_STATUS.finditer(text):
        cve, keyword, reason = m.group(1), m.group(2).strip(), (m.group(3) or "").strip()
        status = _STATUS_MAP.get(keyword, "under_investigation")
        results[cve] = {
            "status": status,
            "keyword": keyword,
            "reason": reason,
            "source": "CVE_STATUS",
        }
    for m in _CVE_CHECK_IGNORE.finditer(text):
        for cve in m.group(1).split():
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) and cve not in results:
                results[cve] = {
                    "status": "not_affected",
                    "keyword": "ignored",
                    "reason": "listed in CVE_CHECK_IGNORE",
                    "source": "CVE_CHECK_IGNORE",
                }
    return results


def scan_build_tree(root: str | Path) -> dict[str, dict]:
    """Walk a Yocto layer / build tree and collect all CVE annotations."""
    root = Path(root)
    annotations: dict[str, dict] = {}
    patterns = ("*.bb", "*.bbappend", "*.inc", "*.conf")
    for pattern in patterns:
        for path in root.rglob(pattern):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for cve, info in parse_recipe_text(text).items():
                info = dict(info, recipe=str(path.relative_to(root)))
                # First annotation wins; conflicting duplicates are recorded.
                if cve in annotations and annotations[cve]["status"] != info["status"]:
                    annotations[cve]["conflicts"] = annotations[cve].get("conflicts", [])
                    annotations[cve]["conflicts"].append(info)
                else:
                    annotations.setdefault(cve, info)
    return annotations


def parse_cve_check_output(text: str) -> dict[str, dict]:
    """Parse the text output of Yocto's cve-check class (per-recipe report)."""
    annotations: dict[str, dict] = {}
    blocks = re.split(r"\n\s*\n", text)
    for block in blocks:
        cve_m = _CVE_LINE.search(block)
        if not cve_m:
            continue
        cve = cve_m.group(1)
        status_m = re.search(r"CVE STATUS:\s*(\w+)", block)
        status_word = (status_m.group(1) if status_m else "").lower()
        if status_word == "patched":
            annotations[cve] = {
                "status": "fixed",
                "keyword": "patched",
                "reason": "reported Patched by yocto cve-check",
                "source": "cve-check",
            }
        elif status_word == "ignored":
            annotations[cve] = {
                "status": "not_affected",
                "keyword": "ignored",
                "reason": "reported Ignored by yocto cve-check",
                "source": "cve-check",
            }
    return annotations
