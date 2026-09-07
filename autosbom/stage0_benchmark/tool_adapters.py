"""Parse the JSON output of the generic tools under benchmark.

Each adapter turns a tool's native JSON report into the common Sbom model so
the comparison engine treats every tool identically. Adapters parse saved
report files; ``run_*`` helpers invoke the tool when it is installed and
return None (with a note) when it is not, so the harness degrades gracefully
on machines without the tools.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ..common.io_utils import load_json
from ..common.models import Component, Sbom, Vulnerability


# --------------------------------------------------------------------------
# Syft (JSON output: `syft <target> -o json`)
# --------------------------------------------------------------------------

def parse_syft_json(path: str | Path) -> Sbom:
    data = load_json(path)
    components = []
    for art in data.get("artifacts", []):
        components.append(
            Component(
                name=art.get("name", ""),
                version=art.get("version", "") or "",
                ecosystem=art.get("type", "generic"),
                purl=art.get("purl", "") or "",
                cpe=(art.get("cpes") or [""])[0] if art.get("cpes") else "",
                licenses=[
                    l.get("value", "") if isinstance(l, dict) else str(l)
                    for l in (art.get("licenses") or [])
                ],
            )
        )
    return Sbom(components=components, tool="syft",
                target=(data.get("source") or {}).get("target", "") if isinstance(
                    (data.get("source") or {}).get("target"), str) else "")


# --------------------------------------------------------------------------
# Trivy (JSON output: `trivy fs/image <target> -f json`)
# --------------------------------------------------------------------------

def parse_trivy_json(path: str | Path) -> Sbom:
    data = load_json(path)
    components: list[Component] = []
    vulns: list[Vulnerability] = []
    for result in data.get("Results", []) or []:
        for pkg in result.get("Packages", []) or []:
            components.append(
                Component(
                    name=pkg.get("Name", ""),
                    version=pkg.get("Version", "") or "",
                    ecosystem=(result.get("Type") or "generic"),
                    purl=(pkg.get("Identifier") or {}).get("PURL", ""),
                )
            )
        for v in result.get("Vulnerabilities", []) or []:
            vulns.append(
                Vulnerability(
                    cve_id=v.get("VulnerabilityID", ""),
                    component=v.get("PkgName", ""),
                    component_version=v.get("InstalledVersion", ""),
                    severity=(v.get("Severity") or "UNKNOWN").upper(),
                    cvss=_trivy_cvss(v),
                    description=(v.get("Title") or "")[:200],
                    source_tool="trivy",
                    fixed_version=v.get("FixedVersion", "") or "",
                )
            )
    return Sbom(components=components, vulnerabilities=vulns, tool="trivy",
                target=data.get("ArtifactName", ""))


def _trivy_cvss(v: dict) -> Optional[float]:
    cvss = v.get("CVSS") or {}
    for source in ("nvd", "redhat", "ghsa"):
        entry = cvss.get(source) or {}
        score = entry.get("V3Score") or entry.get("V2Score")
        if score is not None:
            return float(score)
    return None


# --------------------------------------------------------------------------
# Grype (JSON output: `grype <target> -o json`) — used by the CI pipeline
# --------------------------------------------------------------------------

def parse_grype_json(path: str | Path) -> Sbom:
    data = load_json(path)
    vulns = []
    components: dict[str, Component] = {}
    for m in data.get("matches", []) or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        name = art.get("name", "")
        if name and name not in components:
            components[name] = Component(
                name=name,
                version=art.get("version", "") or "",
                ecosystem=art.get("type", "generic"),
                purl=art.get("purl", "") or "",
            )
        sev = (vuln.get("severity") or "UNKNOWN").upper()
        cvss_score = None
        for c in vuln.get("cvss") or []:
            metrics = c.get("metrics") or {}
            if metrics.get("baseScore") is not None:
                cvss_score = float(metrics["baseScore"])
        vulns.append(
            Vulnerability(
                cve_id=vuln.get("id", ""),
                component=name,
                component_version=art.get("version", "") or "",
                severity=sev,
                cvss=cvss_score,
                source_tool="grype",
                fixed_version=", ".join((vuln.get("fix") or {}).get("versions") or []),
            )
        )
    return Sbom(components=list(components.values()), vulnerabilities=vulns,
                tool="grype")


# --------------------------------------------------------------------------
# EMBA (CycloneDX output from EMBA's SBOM module: f15 / sbom builder)
# EMBA emits CycloneDX JSON; reuse a small CycloneDX reader here.
# --------------------------------------------------------------------------

def parse_cyclonedx_json(path: str | Path, tool_name: str = "cyclonedx") -> Sbom:
    data = load_json(path)
    components = []
    for comp in data.get("components", []) or []:
        c = Component(
            name=comp.get("name", ""),
            version=comp.get("version", "") or "",
            purl=comp.get("purl", "") or "",
            cpe=comp.get("cpe", "") or "",
            licenses=[
                (l.get("license") or {}).get("id")
                or (l.get("license") or {}).get("name", "")
                for l in (comp.get("licenses") or [])
                if isinstance(l, dict)
            ],
        )
        # Restore autosbom-specific metadata written by the Stage 1 emitter,
        # so flags/confidence survive the CycloneDX round trip into reports.
        for prop in comp.get("properties", []) or []:
            pname, pval = prop.get("name", ""), prop.get("value", "")
            if pname == "autosbom:flag" and pval:
                c.flags.append(pval)
            elif pname == "autosbom:version-unknown":
                c.version_unknown = pval == "true"
            elif pname == "autosbom:identification-confidence":
                try:
                    c.identification_confidence = float(pval)
                except ValueError:
                    pass
            elif pname == "autosbom:source-file":
                c.source_file = pval
        components.append(c)
    vulns = []
    for v in data.get("vulnerabilities", []) or []:
        affected = v.get("affects") or []
        comp_ref = (affected[0].get("ref", "") if affected else "")
        ratings = v.get("ratings") or []
        sev = (ratings[0].get("severity", "unknown") if ratings else "unknown").upper()
        score = ratings[0].get("score") if ratings else None
        vulns.append(
            Vulnerability(
                cve_id=v.get("id", ""),
                component=comp_ref,
                severity=sev,
                cvss=float(score) if score is not None else None,
                source_tool=tool_name,
            )
        )
    return Sbom(components=components, vulnerabilities=vulns, tool=tool_name)


def parse_emba_cyclonedx(path: str | Path) -> Sbom:
    return parse_cyclonedx_json(path, tool_name="emba")


# --------------------------------------------------------------------------
# Live invocation helpers (used when the tool is installed on this machine)
# --------------------------------------------------------------------------

def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_and_capture(cmd: list[str], timeout: int) -> str:
    """Run an external scanner, raising RuntimeError with its stderr on failure."""
    tool = cmd[0]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                check=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"{tool} exited with status {exc.returncode}: "
            f"{(exc.stderr or '').strip()[:500]}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{tool} did not finish within {timeout}s "
                           f"(command: {' '.join(cmd)})") from exc
    return result.stdout


def run_syft(target: str, out_path: str | Path) -> Optional[Sbom]:
    """Run syft against a target directory/image; None if syft not installed."""
    if not tool_available("syft"):
        return None
    stdout = _run_and_capture(["syft", target, "-o", "json"], timeout=1800)
    Path(out_path).write_text(stdout, encoding="utf-8")
    return parse_syft_json(out_path)


def run_trivy_fs(target: str, out_path: str | Path) -> Optional[Sbom]:
    """Run trivy fs against a directory; None if trivy not installed."""
    if not tool_available("trivy"):
        return None
    stdout = _run_and_capture(
        ["trivy", "fs", "--format", "json", "--list-all-pkgs", target],
        timeout=3600,
    )
    Path(out_path).write_text(stdout, encoding="utf-8")
    return parse_trivy_json(out_path)
