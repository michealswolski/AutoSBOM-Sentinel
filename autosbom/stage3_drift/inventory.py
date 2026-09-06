"""Runtime inventory: what is actually on/loaded by this system right now.

Three inventory sources (docs/01_ARCHITECTURE.md, Stage 3):
  1. shared libraries in the standard library paths (path + SHA-256),
  2. installed package manifests (dpkg/opkg/rpm when available),
  3. loaded kernel modules (/proc/modules).

Everything degrades gracefully: a source that doesn't exist on this system
contributes an empty section plus a note, rather than failing the sweep.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LIB_DIRS = ["/lib", "/usr/lib", "/lib64", "/usr/lib64", "/usr/local/lib"]


@dataclass
class Inventory:
    timestamp: str
    hostname: str
    shared_libraries: dict[str, str] = field(default_factory=dict)  # path -> sha256
    packages: dict[str, str] = field(default_factory=dict)          # name -> version
    kernel_modules: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "shared_libraries": self.shared_libraries,
            "packages": self.packages,
            "kernel_modules": self.kernel_modules,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Inventory":
        return cls(
            timestamp=d.get("timestamp", ""),
            hostname=d.get("hostname", ""),
            shared_libraries=d.get("shared_libraries", {}),
            packages=d.get("packages", {}),
            kernel_modules=d.get("kernel_modules", []),
            notes=d.get("notes", []),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True),
                              encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sweep_shared_libraries(lib_dirs: list[str] | None = None,
                           max_files: int = 20000) -> tuple[dict[str, str], list[str]]:
    libs: dict[str, str] = {}
    notes: list[str] = []
    count = 0
    for d in lib_dirs or DEFAULT_LIB_DIRS:
        base = Path(d)
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.so*")):
            if count >= max_files:
                notes.append(f"library sweep truncated at {max_files} files")
                return libs, notes
            if not path.is_file() or path.is_symlink():
                continue
            try:
                libs[str(path)] = _sha256(path)
                count += 1
            except OSError as exc:
                notes.append(f"unreadable: {path} ({exc.__class__.__name__})")
    return libs, notes


def sweep_packages() -> tuple[dict[str, str], list[str]]:
    """Query whichever package manager exists (dpkg, opkg, rpm)."""
    notes: list[str] = []
    for cmd, parser in (
        (["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"], _parse_tsv),
        (["opkg", "list-installed"], _parse_opkg),
        (["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], _parse_tsv),
    ):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=120, check=True)
            return parser(out.stdout), notes
        except (FileNotFoundError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired):
            continue
    notes.append("no supported package manager found (dpkg/opkg/rpm)")
    return {}, notes


def _parse_tsv(text: str) -> dict[str, str]:
    pkgs = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0]:
            pkgs[parts[0]] = parts[1]
    return pkgs


def _parse_opkg(text: str) -> dict[str, str]:
    pkgs = {}
    for line in text.splitlines():
        parts = line.split(" - ")
        if len(parts) >= 2 and parts[0]:
            pkgs[parts[0].strip()] = parts[1].strip()
    return pkgs


def sweep_kernel_modules() -> tuple[list[str], list[str]]:
    proc = Path("/proc/modules")
    if not proc.exists():
        return [], ["/proc/modules not available on this system"]
    mods = []
    for line in proc.read_text(encoding="utf-8").splitlines():
        name = line.split(" ", 1)[0]
        if name:
            mods.append(name)
    return sorted(mods), []


def take_inventory(lib_dirs: list[str] | None = None) -> Inventory:
    import socket

    libs, lib_notes = sweep_shared_libraries(lib_dirs)
    pkgs, pkg_notes = sweep_packages()
    mods, mod_notes = sweep_kernel_modules()
    return Inventory(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        hostname=socket.gethostname(),
        shared_libraries=libs,
        packages=pkgs,
        kernel_modules=mods,
        notes=lib_notes + pkg_notes + mod_notes,
    )
