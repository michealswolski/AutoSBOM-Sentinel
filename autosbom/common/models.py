"""Shared data models used across all stages."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Optional


def normalize_name(name: str) -> str:
    """Normalize a component name for cross-tool comparison.

    Different tools report the same component under slightly different names
    (e.g. ``libssl1.1`` vs ``openssl``, ``glibc`` vs ``libc6``). We lowercase,
    strip common lib prefixes/suffix version digits, and collapse separators.
    Alias mapping for known cases lives in stage0_benchmark.compare.
    """
    n = name.strip().lower()
    n = re.sub(r"[_\s]+", "-", n)
    return n


@dataclass
class Component:
    """A single software component in an SBOM."""

    name: str
    version: str = ""
    ecosystem: str = "generic"          # pypi, deb, rpm, apk, npm, generic, ...
    purl: str = ""
    cpe: str = ""
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)   # algo -> hexdigest
    supplier: str = ""
    # Automotive-tuning metadata (Stage 1):
    identification_confidence: float = 1.0   # 0.0-1.0; <1.0 means uncertain match
    version_unknown: bool = False            # stripped binary / no version string
    flags: list[str] = field(default_factory=list)  # e.g. ["stripped-binary", "needs-manual-review"]
    source_file: str = ""                    # path inside the image it was found at

    def __post_init__(self) -> None:
        if not self.purl and self.name:
            ver = f"@{self.version}" if self.version else ""
            self.purl = f"pkg:{self.ecosystem}/{self.name}{ver}"

    @property
    def key(self) -> str:
        """Identity used for ground-truth comparison: normalized name."""
        return normalize_name(self.name)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Component":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Vulnerability:
    """A vulnerability finding attached to a component."""

    cve_id: str
    component: str                 # component name as reported
    component_version: str = ""
    severity: str = ""             # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    cvss: Optional[float] = None
    description: str = ""
    source_tool: str = ""          # which scanner reported it
    fixed_version: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Vulnerability":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Sbom:
    """An in-memory SBOM: a component list plus generation metadata."""

    components: list[Component] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    target: str = ""               # what was scanned (path / image name)
    tool: str = "autosbom-sentinel"
    tool_version: str = "0.1.0"
    timestamp: str = ""

    def component_keys(self) -> set[str]:
        return {c.key for c in self.components}

    def find(self, name: str) -> Optional[Component]:
        key = normalize_name(name)
        for c in self.components:
            if c.key == key:
                return c
        return None
