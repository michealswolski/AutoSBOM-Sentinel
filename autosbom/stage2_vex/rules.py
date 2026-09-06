"""Automotive-context VEX rules engine.

Takes vulnerability findings plus a DeviceContext (and optional Yocto backport
annotations from Stage 1) and produces *proposed* VEX statements. Every
proposal carries the rule that fired, the evidence, and an OpenVEX
justification code. Nothing is suppressed until a human approves the
proposal (review.py) — auto-suppression is deliberately not implemented.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..common.models import Vulnerability, normalize_name
from .context import DeviceContext

# OpenVEX status + justification vocabulary (https://github.com/openvex/spec)
STATUS_NOT_AFFECTED = "not_affected"
STATUS_FIXED = "fixed"
STATUS_AFFECTED = "affected"
STATUS_UNDER_INVESTIGATION = "under_investigation"

J_COMPONENT_NOT_PRESENT = "component_not_present"
J_CODE_NOT_PRESENT = "vulnerable_code_not_present"
J_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
J_CANNOT_BE_CONTROLLED = "vulnerable_code_cannot_be_controlled_by_adversary"
J_INLINE_MITIGATIONS = "inline_mitigations_already_exist"

# CVE -> feature mapping knowledge base. Maps a CVE (or a component) to the
# device feature whose disablement makes it unreachable. The shipped entries
# are the PerfektBlue set (documented in docs/02_RESEARCH_FINDINGS.md);
# users extend this per-device via the rules_kb parameter.
DEFAULT_FEATURE_KB: dict[str, str] = {
    # PerfektBlue: CVE-2024-45434 is a UAF in the AVRCP service.
    "CVE-2024-45434": "bluetooth.avrcp",
    # The RFCOMM pair and the L2CAP CID issue require the Bluetooth stack
    # to be reachable at all.
    "CVE-2024-45433": "bluetooth",
    "CVE-2024-45432": "bluetooth",
    "CVE-2024-45431": "bluetooth",
}

# Component -> exposure feature (used when no CVE-specific mapping exists).
DEFAULT_COMPONENT_FEATURES: dict[str, str] = {
    "bluez": "bluetooth",
    "wpa_supplicant": "wifi",
    "hostapd": "wifi",
    "dnsmasq": "network.dhcp",
    "openssh": "network.ssh",
    "dropbear": "network.ssh",
}


@dataclass
class VexProposal:
    """A proposed (NOT yet applied) VEX statement for one CVE/component pair."""

    cve_id: str
    component: str
    proposed_status: str
    justification: str = ""            # required by OpenVEX when not_affected
    impact_statement: str = ""
    rule: str = ""                     # machine name of the rule that fired
    evidence: str = ""                 # human-readable evidence trail
    state: str = "pending"             # pending | approved | rejected (review.py)
    reviewer: str = ""
    review_note: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "component": self.component,
            "proposed_status": self.proposed_status,
            "justification": self.justification,
            "impact_statement": self.impact_statement,
            "rule": self.rule,
            "evidence": self.evidence,
            "state": self.state,
            "reviewer": self.reviewer,
            "review_note": self.review_note,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "VexProposal":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class RuleEngine:
    context: DeviceContext
    backport_annotations: dict[str, dict] = field(default_factory=dict)
    feature_kb: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_FEATURE_KB))
    component_features: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_COMPONENT_FEATURES)
    )

    def evaluate(self, vuln: Vulnerability) -> Optional[VexProposal]:
        """Return a proposal for this finding, or None (finding stands as-is)."""
        for rule in (
            self._rule_backported_fix,
            self._rule_feature_disabled,
            self._rule_not_in_execute_path,
            self._rule_network_isolated,
            self._rule_local_access_not_possible,
        ):
            proposal = rule(vuln)
            if proposal is not None:
                return proposal
        return None

    def evaluate_all(self, vulns: list[Vulnerability]) -> list[VexProposal]:
        proposals = []
        for v in vulns:
            p = self.evaluate(v)
            if p is not None:
                proposals.append(p)
        return proposals

    # ---- individual rules -------------------------------------------------

    def _rule_backported_fix(self, v: Vulnerability) -> Optional[VexProposal]:
        ann = self.backport_annotations.get(v.cve_id)
        if not ann:
            return None
        status = ann.get("status", "")
        if status == "fixed":
            return VexProposal(
                cve_id=v.cve_id,
                component=v.component,
                proposed_status=STATUS_FIXED,
                impact_statement=(
                    "Fix backported by the distro without a version bump "
                    f"({ann.get('keyword', '')}: {ann.get('reason', '')})"
                ),
                rule="yocto-backport-annotation",
                evidence=f"source={ann.get('source', '')} recipe={ann.get('recipe', '')}",
            )
        if status == "not_affected":
            return VexProposal(
                cve_id=v.cve_id,
                component=v.component,
                proposed_status=STATUS_NOT_AFFECTED,
                justification=J_CODE_NOT_PRESENT,
                impact_statement=ann.get("reason", ""),
                rule="yocto-not-applicable-annotation",
                evidence=f"source={ann.get('source', '')} recipe={ann.get('recipe', '')}",
            )
        return None

    def _feature_for(self, v: Vulnerability) -> Optional[str]:
        if v.cve_id in self.feature_kb:
            return self.feature_kb[v.cve_id]
        return self.component_features.get(normalize_name(v.component))

    def _rule_feature_disabled(self, v: Vulnerability) -> Optional[VexProposal]:
        feature = self._feature_for(v)
        if feature is None:
            return None
        enabled = self.context.feature_enabled(feature)
        if enabled is False:
            return VexProposal(
                cve_id=v.cve_id,
                component=v.component,
                proposed_status=STATUS_NOT_AFFECTED,
                justification=J_CODE_NOT_IN_EXECUTE_PATH,
                impact_statement=(
                    f"Feature '{feature}' is disabled in this device configuration; "
                    "the vulnerable code path is compiled in but not reachable."
                ),
                rule="feature-disabled",
                evidence=f"device-context: features[{feature}]=false "
                         f"(device={self.context.device_name})",
            )
        return None

    def _rule_not_in_execute_path(self, v: Vulnerability) -> Optional[VexProposal]:
        comp = normalize_name(v.component)
        declared = {normalize_name(c) for c in self.context.not_in_execute_path}
        if comp in declared:
            return VexProposal(
                cve_id=v.cve_id,
                component=v.component,
                proposed_status=STATUS_NOT_AFFECTED,
                justification=J_CODE_NOT_IN_EXECUTE_PATH,
                impact_statement=(
                    f"Component '{v.component}' is present on disk but declared "
                    "not loaded/executed in this configuration."
                ),
                rule="not-in-execute-path",
                evidence=f"device-context: not_in_execute_path includes {comp}",
            )
        return None

    def _rule_network_isolated(self, v: Vulnerability) -> Optional[VexProposal]:
        comp = normalize_name(v.component)
        isolated = {normalize_name(c) for c in self.context.network_isolated_components}
        if comp not in isolated:
            return None
        text = f"{v.description} {v.cve_id}".lower()
        # Only propose for findings that plausibly need network reachability.
        if any(k in text for k in ("remote", "network", "http", "tls", "packet",
                                   "request", "server", "protocol")):
            return VexProposal(
                cve_id=v.cve_id,
                component=v.component,
                proposed_status=STATUS_NOT_AFFECTED,
                justification=J_CANNOT_BE_CONTROLLED,
                impact_statement=(
                    f"Component '{v.component}' has no path to a reachable "
                    "network interface in this topology; remote exploitation "
                    "prerequisites are not met."
                ),
                rule="network-isolated",
                evidence=f"device-context: network_isolated_components includes {comp}",
            )
        return None

    def _rule_local_access_not_possible(self, v: Vulnerability) -> Optional[VexProposal]:
        if self.context.local_access_possible:
            return None
        text = f"{v.description}".lower()
        if "local" in text and not any(k in text for k in ("remote", "network")):
            return VexProposal(
                cve_id=v.cve_id,
                component=v.component,
                proposed_status=STATUS_NOT_AFFECTED,
                justification=J_CANNOT_BE_CONTROLLED,
                impact_statement=(
                    "Vulnerability requires local access, which is not "
                    "achievable in this device's deployed configuration "
                    "(no shell, no debug interfaces exposed)."
                ),
                rule="local-access-not-possible",
                evidence="device-context: local_access_possible=false",
            )
        return None
