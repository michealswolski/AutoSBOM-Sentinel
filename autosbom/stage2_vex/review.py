"""Human-approval gate for VEX proposals.

Design rule (docs/01_ARCHITECTURE.md, Stage 2): the tool NEVER treats a CVE
as suppressed on its own. The lifecycle is:

    rules engine -> proposal (state=pending)
                 -> human review (approve/reject, with name + note)
                 -> only APPROVED proposals are exported as OpenVEX / used
                    to filter reports.

The review store is a plain JSON file so reviews are diffable and can be
checked into source control like code review records.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..common.io_utils import load_json
from .rules import VexProposal


class ReviewError(RuntimeError):
    pass


@dataclass
class ReviewStore:
    path: Path
    proposals: list[VexProposal] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> "ReviewStore":
        p = Path(path)
        if not p.exists():
            return cls(path=p, proposals=[])
        data = load_json(p)
        if not isinstance(data, dict):
            raise ValueError(f"{p}: review store must be a JSON object, "
                             f"got {type(data).__name__}")
        return cls(
            path=p,
            proposals=[VexProposal.from_dict(d) for d in data.get("proposals", [])],
        )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {
                    "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "proposals": [p.to_dict() for p in self.proposals],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    # ---- lifecycle --------------------------------------------------------

    def add_proposals(self, new: list[VexProposal]) -> int:
        """Add newly-generated proposals, skipping ones already tracked.

        An existing proposal (same CVE+component) is never overwritten —
        re-running the rules engine must not clobber a human decision.
        """
        existing = {(p.cve_id, p.component) for p in self.proposals}
        added = 0
        for p in new:
            if (p.cve_id, p.component) in existing:
                continue
            p.state = "pending"
            self.proposals.append(p)
            added += 1
        return added

    def _find(self, cve_id: str, component: str) -> VexProposal:
        for p in self.proposals:
            if p.cve_id == cve_id and p.component == component:
                return p
        raise ReviewError(f"no proposal for {cve_id} / {component}")

    def approve(self, cve_id: str, component: str, reviewer: str, note: str = "") -> None:
        if not reviewer.strip():
            raise ReviewError("a reviewer name is required to approve a proposal")
        p = self._find(cve_id, component)
        p.state = "approved"
        p.reviewer = reviewer
        p.review_note = note

    def reject(self, cve_id: str, component: str, reviewer: str, note: str = "") -> None:
        if not reviewer.strip():
            raise ReviewError("a reviewer name is required to reject a proposal")
        p = self._find(cve_id, component)
        p.state = "rejected"
        p.reviewer = reviewer
        p.review_note = note

    # ---- queries ----------------------------------------------------------

    def pending(self) -> list[VexProposal]:
        return [p for p in self.proposals if p.state == "pending"]

    def approved(self) -> list[VexProposal]:
        return [p for p in self.proposals if p.state == "approved"]

    def suppressed_cves(self) -> set[str]:
        """CVE ids that reports may treat as suppressed — approved ONLY."""
        return {
            p.cve_id
            for p in self.approved()
            if p.proposed_status in ("not_affected", "fixed")
        }
