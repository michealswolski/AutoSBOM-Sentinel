"""SPDX 2.3 JSON parsing (ground truth ingestion) and export.

AGL publishes official SPDX SBOMs alongside its pre-built images; Stage 0
loads those as ground truth. Stage 1 can also export SPDX 2.3 for consumers
that ask for it specifically.

Only the tag subset needed for component-level comparison is implemented —
this is not a full SPDX library.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .io_utils import load_json
from .models import Component, Sbom


def load_spdx_json(path: str | Path) -> Sbom:
    """Load an SPDX 2.x JSON document into an Sbom."""
    data = load_json(path)
    if not isinstance(data, dict) or "packages" not in data:
        raise ValueError(f"{path}: doesn't look like an SPDX document "
                         f"(missing top-level 'packages' array)")
    components: list[Component] = []
    for pkg in data.get("packages", []):
        name = pkg.get("name", "")
        if not name:
            continue
        version = pkg.get("versionInfo", "") or ""
        purl = ""
        cpe = ""
        for ref in pkg.get("externalRefs", []) or []:
            rt = ref.get("referenceType", "")
            if rt == "purl":
                purl = ref.get("referenceLocator", "")
            elif rt.startswith("cpe"):
                cpe = ref.get("referenceLocator", "")
        licenses = []
        for lic_field in ("licenseConcluded", "licenseDeclared"):
            lic = pkg.get(lic_field)
            if lic and lic not in ("NOASSERTION", "NONE") and lic not in licenses:
                licenses.append(lic)
        hashes = {}
        for cs in pkg.get("checksums", []) or []:
            algo = cs.get("algorithm", "").lower().replace("-", "")
            if algo and cs.get("checksumValue"):
                hashes[algo] = cs["checksumValue"]
        components.append(
            Component(
                name=name,
                version=version,
                purl=purl,
                cpe=cpe,
                licenses=licenses,
                hashes=hashes,
                supplier=(pkg.get("supplier") or "").replace("Organization: ", ""),
            )
        )
    return Sbom(
        components=components,
        target=data.get("name", str(path)),
        tool="spdx-document",
        timestamp=(data.get("creationInfo") or {}).get("created", ""),
    )


def export_spdx_json(sbom: Sbom, document_name: str = "autosbom-sentinel-sbom") -> dict:
    """Export an Sbom as a minimal SPDX 2.3 JSON document."""
    now = sbom.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    packages = []
    for i, c in enumerate(sbom.components):
        pkg: dict = {
            "SPDXID": f"SPDXRef-Package-{i}",
            "name": c.name,
            "versionInfo": c.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": c.licenses[0] if c.licenses else "NOASSERTION",
            "licenseDeclared": c.licenses[0] if c.licenses else "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        refs = []
        if c.purl:
            refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl,
                }
            )
        if c.cpe:
            refs.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": c.cpe,
                }
            )
        if refs:
            pkg["externalRefs"] = refs
        if c.hashes:
            pkg["checksums"] = [
                {"algorithm": algo.upper(), "checksumValue": v}
                for algo, v in sorted(c.hashes.items())
            ]
        packages.append(pkg)
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document_name,
        "documentNamespace": f"https://autosbom-sentinel.local/{document_name}",
        "creationInfo": {
            "created": now,
            "creators": [f"Tool: {sbom.tool}-{sbom.tool_version}"],
        },
        "packages": packages,
    }
