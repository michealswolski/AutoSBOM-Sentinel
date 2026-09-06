"""Attack-surface categorization for the automotive heatmap.

Groups components by *exposure category* (Bluetooth / network-facing / CAN /
OTA-update / diagnostics / crypto / base-system) instead of by package name —
the automotive-domain view a generic SBOM dashboard doesn't provide.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..common.models import Sbom, Vulnerability, normalize_name

CATEGORIES = [
    "bluetooth",
    "network-facing",
    "can-bus",
    "ota-update",
    "diagnostics",
    "crypto",
    "base-system",
]

# Component-name substrings -> category. Extend per-image as real scans
# surface components; unknowns land in base-system rather than vanishing.
_CATEGORY_PATTERNS: dict[str, list[str]] = {
    "bluetooth": ["bluez", "bluetooth", "btusb", "rfcomm", "avrcp", "a2dp", "obex"],
    "network-facing": [
        "openssl", "curl", "wget", "openssh", "dropbear", "dnsmasq", "avahi",
        "wpa-supplicant", "wpa_supplicant", "hostapd", "connman", "systemd-networkd",
        "netifd", "nginx", "lighttpd", "mosquitto", "gnutls", "nss",
    ],
    "can-bus": ["socketcan", "can-utils", "canutils", "libsocketcan", "mcp251",
                "can-isotp", "j1939"],
    "ota-update": ["swupdate", "rauc", "mender", "ostree", "aktualizr", "uptane",
                   "hawkbit", "fwup"],
    "diagnostics": ["uds", "doip", "obd", "isotp", "diag"],
    "crypto": ["libgcrypt", "libsodium", "mbedtls", "wolfssl", "libssh", "gpg",
               "gnupg", "p11-kit", "libp11"],
}


def categorize(component_name: str) -> str:
    n = normalize_name(component_name)
    for category, patterns in _CATEGORY_PATTERNS.items():
        for p in patterns:
            if p in n:
                return category
    return "base-system"


@dataclass
class HeatmapCell:
    category: str
    component_count: int = 0
    cve_count: int = 0
    suppressed_cve_count: int = 0
    max_cvss: float = 0.0
    components: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)

    @property
    def actionable_cve_count(self) -> int:
        return self.cve_count - self.suppressed_cve_count

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "component_count": self.component_count,
            "cve_count": self.cve_count,
            "suppressed_cve_count": self.suppressed_cve_count,
            "actionable_cve_count": self.actionable_cve_count,
            "max_cvss": self.max_cvss,
            "components": self.components,
            "cves": self.cves,
        }


def build_heatmap(
    sbom: Sbom,
    vulnerabilities: list[Vulnerability] | None = None,
    suppressed_cves: set[str] | None = None,
) -> list[HeatmapCell]:
    """Aggregate components + findings into per-category heatmap cells."""
    vulns = vulnerabilities if vulnerabilities is not None else sbom.vulnerabilities
    suppressed = suppressed_cves or set()

    cells = {cat: HeatmapCell(category=cat) for cat in CATEGORIES}
    comp_category: dict[str, str] = {}

    for comp in sbom.components:
        cat = categorize(comp.name)
        comp_category[comp.key] = cat
        cells[cat].component_count += 1
        cells[cat].components.append(comp.name)

    for v in vulns:
        cat = comp_category.get(normalize_name(v.component)) or categorize(v.component)
        cell = cells[cat]
        cell.cve_count += 1
        cell.cves.append(v.cve_id)
        if v.cve_id in suppressed:
            cell.suppressed_cve_count += 1
        elif v.cvss is not None:
            cell.max_cvss = max(cell.max_cvss, v.cvss)

    return [cells[cat] for cat in CATEGORIES]
