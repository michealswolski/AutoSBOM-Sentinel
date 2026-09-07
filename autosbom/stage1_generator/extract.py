"""Firmware extraction step: binwalk wrapper with graceful fallback.

If binwalk is installed, use it to unpack a firmware image into a directory.
If not (or the input is already an extracted rootfs directory), pass the
directory through unchanged. Every result records which path was taken so
the generated SBOM's metadata is honest about how the tree was obtained.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from ..common.io_utils import run_subprocess_or_raise


@dataclass
class ExtractionResult:
    root: Path              # directory containing the extracted / original tree
    method: str             # "binwalk" | "directory-passthrough"
    notes: list[str]


def extract(target: str | Path, workdir: str | Path) -> ExtractionResult:
    target = Path(target)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    if target.is_dir():
        return ExtractionResult(
            root=target,
            method="directory-passthrough",
            notes=["input was already a directory; binwalk not needed"],
        )

    if shutil.which("binwalk") is None:
        raise RuntimeError(
            "binwalk is not installed and the target is a firmware image file. "
            "Install binwalk (https://github.com/ReFirmLabs/binwalk) or extract "
            "the image manually and pass the extracted directory instead."
        )

    run_subprocess_or_raise(
        ["binwalk", "--extract", "--directory", str(workdir), str(target)],
        timeout=3600,
        error_label=f"binwalk extracting {target}",
    )
    # binwalk extracts into _<name>.extracted under the output directory
    candidates = sorted(workdir.glob("_*.extracted"))
    root = candidates[0] if candidates else workdir
    return ExtractionResult(
        root=root,
        method="binwalk",
        notes=[f"binwalk extracted {target.name} -> {root}"],
    )
