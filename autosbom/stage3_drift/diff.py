"""Diff a fresh inventory against the (verified) baseline -> drift events."""
from __future__ import annotations

from dataclasses import dataclass
from .inventory import Inventory


@dataclass
class DriftEvent:
    kind: str        # library-added | library-removed | library-hash-mismatch |
                     # package-added | package-removed | package-version-changed |
                     # kmod-added | kmod-removed
    subject: str     # path / package / module name
    detail: str = ""
    severity: str = "warning"   # hash mismatches and additions are "critical"

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "detail": self.detail,
            "severity": self.severity,
        }


def diff_inventories(baseline: Inventory, current: Inventory) -> list[DriftEvent]:
    events: list[DriftEvent] = []

    b_libs, c_libs = baseline.shared_libraries, current.shared_libraries
    for path in sorted(set(c_libs) - set(b_libs)):
        events.append(DriftEvent("library-added", path,
                                 f"sha256={c_libs[path][:16]}…", "critical"))
    for path in sorted(set(b_libs) - set(c_libs)):
        events.append(DriftEvent("library-removed", path, severity="warning"))
    for path in sorted(set(b_libs) & set(c_libs)):
        if b_libs[path] != c_libs[path]:
            events.append(
                DriftEvent(
                    "library-hash-mismatch",
                    path,
                    f"baseline={b_libs[path][:16]}… current={c_libs[path][:16]}…",
                    "critical",
                )
            )

    b_pkgs, c_pkgs = baseline.packages, current.packages
    for name in sorted(set(c_pkgs) - set(b_pkgs)):
        events.append(DriftEvent("package-added", name, c_pkgs[name], "critical"))
    for name in sorted(set(b_pkgs) - set(c_pkgs)):
        events.append(DriftEvent("package-removed", name, severity="warning"))
    for name in sorted(set(b_pkgs) & set(c_pkgs)):
        if b_pkgs[name] != c_pkgs[name]:
            events.append(
                DriftEvent("package-version-changed", name,
                           f"{b_pkgs[name]} -> {c_pkgs[name]}", "warning")
            )

    b_mods, c_mods = set(baseline.kernel_modules), set(current.kernel_modules)
    for name in sorted(c_mods - b_mods):
        events.append(DriftEvent("kmod-added", name, severity="critical"))
    for name in sorted(b_mods - c_mods):
        events.append(DriftEvent("kmod-removed", name, severity="warning"))

    return events
