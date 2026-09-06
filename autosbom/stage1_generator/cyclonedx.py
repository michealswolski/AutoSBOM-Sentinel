"""CycloneDX 1.6 JSON emitter.

Emits the fields the CISA draft minimum-elements update recommends where we
have them (component hash, license, tool name, generation context), plus the
automotive-tuning metadata (confidence, review flags) as CycloneDX properties
so no information is lost between stages.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..common.models import Sbom

PROPERTY_NS = "autosbom"


def export_cyclonedx_json(sbom: Sbom, serial_number: str | None = None) -> dict:
    components = []
    for c in sbom.components:
        entry: dict = {
            "type": "library",
            "name": c.name,
            "bom-ref": c.purl or f"{c.name}@{c.version}",
        }
        if c.version:
            entry["version"] = c.version
        if c.purl:
            entry["purl"] = c.purl
        if c.cpe:
            entry["cpe"] = c.cpe
        if c.supplier:
            entry["supplier"] = {"name": c.supplier}
        if c.licenses:
            entry["licenses"] = [{"license": {"name": l}} for l in c.licenses if l]
        if c.hashes:
            algo_map = {"sha256": "SHA-256", "sha1": "SHA-1", "sha512": "SHA-512", "md5": "MD5"}
            entry["hashes"] = [
                {"alg": algo_map.get(a, a.upper()), "content": v}
                for a, v in sorted(c.hashes.items())
                if a in algo_map
            ]
        props = []
        if c.identification_confidence < 1.0:
            props.append({
                "name": f"{PROPERTY_NS}:identification-confidence",
                "value": f"{c.identification_confidence:.2f}",
            })
        if c.version_unknown:
            props.append({"name": f"{PROPERTY_NS}:version-unknown", "value": "true"})
        for flag in c.flags:
            props.append({"name": f"{PROPERTY_NS}:flag", "value": flag})
        if c.source_file:
            props.append({"name": f"{PROPERTY_NS}:source-file", "value": c.source_file})
        if props:
            entry["properties"] = props
        components.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": sbom.timestamp
            or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": sbom.tool,
                        "version": sbom.tool_version,
                    }
                ]
            },
            "component": {
                "type": "firmware",
                "name": sbom.target or "unknown-target",
            },
        },
        "components": components,
    }
