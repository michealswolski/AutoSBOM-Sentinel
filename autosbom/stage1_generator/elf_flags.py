"""Stripped/unknown-version ELF binary detection.

The Stage 0 research identifies stripped binaries with no version metadata as
an open failure mode (arXiv 2601.01308): a scanner that cannot identify a
version either guesses (false positives) or silently drops the binary (false
negatives). Stage 1's rule is: *flag, never drop* — every ELF binary we cannot
version gets a Component with ``version_unknown=True`` and a
``needs-manual-review`` flag so it shows up in reports instead of vanishing.

Pure-stdlib ELF section-header parsing — no pyelftools dependency, so this
runs on a stock Raspberry Pi Python install.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

from ..common.models import Component

ELF_MAGIC = b"\x7fELF"

# Version-ish strings inside a binary, e.g. "OpenSSL 1.1.1n  15 Mar 2022"
# or "zlib version 1.2.11". Deliberately conservative: a match only *suggests*
# a version (identification_confidence < 1.0), it never asserts one.
_VERSION_PATTERN = re.compile(rb"(?:version |ver\.? |v)?(\d+\.\d+(?:\.\d+){0,2}[a-z]?)\b")
_SONAME_VERSION = re.compile(r"\.so\.(\d+(?:\.\d+)*)$")


def is_elf(path: str | Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def is_stripped(path: str | Path) -> bool:
    """True if the ELF file has no .symtab section (i.e. is stripped).

    Parses the section header table directly. On any parse failure the file
    is treated as stripped (the conservative direction: it gets flagged for
    manual review rather than trusted).
    """
    try:
        with open(path, "rb") as f:
            ident = f.read(16)
            if ident[:4] != ELF_MAGIC:
                return False
            is64 = ident[4] == 2
            little = ident[5] == 1
            end = "<" if little else ">"
            if is64:
                f.seek(0x28)
                (shoff,) = struct.unpack(end + "Q", f.read(8))
                f.seek(0x3A)
                shentsize, shnum = struct.unpack(end + "HH", f.read(4))
            else:
                f.seek(0x20)
                (shoff,) = struct.unpack(end + "I", f.read(4))
                f.seek(0x2E)
                shentsize, shnum = struct.unpack(end + "HH", f.read(4))
            if shoff == 0 or shnum == 0:
                return True  # no section headers at all
            SHT_SYMTAB = 2
            for i in range(shnum):
                f.seek(shoff + i * shentsize + 4)  # sh_type is at offset 4
                (sh_type,) = struct.unpack(end + "I", f.read(4))
                if sh_type == SHT_SYMTAB:
                    return False
            return True
    except (OSError, struct.error):
        return True


def guess_version_from_soname(filename: str) -> str:
    m = _SONAME_VERSION.search(filename)
    return m.group(1) if m else ""


def guess_version_from_strings(path: str | Path, max_bytes: int = 4 * 1024 * 1024) -> str:
    """Best-effort version hint from printable strings in the binary.

    Returns the most frequent plausible version string, or "". This is a
    *hint* — callers must keep identification_confidence < 1.0 when using it.
    """
    try:
        data = Path(path).read_bytes()[:max_bytes]
    except OSError:
        return ""
    counts: dict[bytes, int] = {}
    for m in _VERSION_PATTERN.finditer(data):
        v = m.group(1)
        # Skip obviously-not-a-package-version matches (dates, tiny numbers).
        if v.count(b".") >= 1 and len(v) <= 12:
            counts[v] = counts.get(v, 0) + 1
    if not counts:
        return ""
    best = max(counts, key=lambda k: counts[k])
    return best.decode("ascii", errors="replace")


def component_from_binary(path: str | Path) -> Component:
    """Build a Component record for a lone ELF binary found in a firmware tree."""
    p = Path(path)
    base = p.name
    name = re.sub(r"\.so(\.\d+)*$", "", base)
    name = re.sub(r"^lib", "", name) or base
    stripped = is_stripped(p)
    version = guess_version_from_soname(base)
    confidence = 0.6 if version else 0.3
    if not version:
        version = guess_version_from_strings(p)
        if version:
            confidence = 0.4
    flags = ["binary-analysis"]
    if stripped:
        flags.append("stripped-binary")
    version_unknown = not version
    if version_unknown or confidence < 0.5:
        flags.append("needs-manual-review")
    return Component(
        name=name,
        version=version,
        ecosystem="generic",
        identification_confidence=confidence,
        version_unknown=version_unknown,
        flags=flags,
        source_file=str(p),
    )
