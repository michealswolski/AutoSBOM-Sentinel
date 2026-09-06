"""OpenVEX document emitter.

Exports APPROVED proposals only (review.py enforces the human gate).
Format follows the OpenVEX spec (https://github.com/openvex/spec): a
document with @context/@id/author/timestamp and a statements array; each
not_affected statement carries a justification from the standard vocabulary.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .rules import VexProposal

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


def export_openvex(
    proposals: list[VexProposal],
    author: str,
    product_purl: str,
    tooling: str = "autosbom-sentinel/0.1.0",
) -> dict:
    """Build an OpenVEX document from approved proposals.

    Raises ValueError if any non-approved proposal is passed — callers must
    go through ReviewStore.approved(), and this check makes bypassing the
    review gate an error rather than a silent possibility.
    """
    not_approved = [p for p in proposals if p.state != "approved"]
    if not_approved:
        raise ValueError(
            "refusing to export non-approved VEX proposals: "
            + ", ".join(f"{p.cve_id}({p.state})" for p in not_approved[:5])
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    statements = []
    for p in proposals:
        stmt: dict = {
            "vulnerability": {"name": p.cve_id},
            "products": [
                {
                    "@id": product_purl,
                    "subcomponents": [{"@id": f"pkg:generic/{p.component}"}],
                }
            ],
            "status": p.proposed_status,
            "timestamp": now,
        }
        if p.proposed_status == "not_affected":
            # OpenVEX requires justification (or action_statement) here.
            stmt["justification"] = p.justification or "component_not_present"
        if p.impact_statement:
            stmt["impact_statement"] = p.impact_statement
        statements.append(stmt)

    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://autosbom-sentinel.local/vex/{uuid.uuid4()}",
        "author": author,
        "role": "document creator",
        "timestamp": now,
        "version": 1,
        "tooling": tooling,
        "statements": statements,
    }
