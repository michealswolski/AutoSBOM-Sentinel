"""Stage 1 pipeline: extract -> identify -> flag -> annotate -> emit.

Combines:
  1. Syft component identification when syft is installed (best coverage for
     package-manager-visible components),
  2. a native ELF walk that *flags* stripped/unknown-version binaries syft
     can't attribute (never silently drops them),
  3. Yocto/Buildroot backport annotations (CVE_STATUS / CVE_CHECK_IGNORE),
     carried in the SBOM metadata for Stage 2 to turn into proposed VEX.

Output: CycloneDX 1.6 JSON (primary) and optional SPDX 2.3.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..common.models import Component, Sbom
from ..stage0_benchmark.tool_adapters import run_syft
from . import backports as backports_mod
from .elf_flags import component_from_binary, is_elf
from .extract import extract

# Directories inside a rootfs where standalone ELF components live.
_BINARY_DIRS = ("lib", "usr/lib", "lib64", "usr/lib64", "bin", "usr/bin", "sbin", "usr/sbin")


@dataclass
class GenerationResult:
    sbom: Sbom
    backport_annotations: dict[str, dict] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def walk_elf_binaries(root: Path, limit: int = 5000) -> list[Component]:
    """Walk standard binary directories and build flagged Components for ELFs."""
    components: list[Component] = []
    seen_names: set[str] = set()
    count = 0
    for rel in _BINARY_DIRS:
        d = root / rel
        if not d.is_dir():
            continue
        for path in sorted(d.rglob("*")):
            if count >= limit:
                return components
            if not path.is_file() or path.is_symlink():
                continue
            if not is_elf(path):
                continue
            count += 1
            comp = component_from_binary(path)
            comp.source_file = str(path.relative_to(root))
            digest = _hash_file(path)
            if digest:
                comp.hashes["sha256"] = digest
            # Deduplicate by name+version, keep the first occurrence.
            dedupe_key = f"{comp.key}@{comp.version}"
            if dedupe_key in seen_names:
                continue
            seen_names.add(dedupe_key)
            components.append(comp)
    return components


def merge_components(primary: list[Component], secondary: list[Component]) -> list[Component]:
    """Merge syft-identified components (primary) with the native ELF walk.

    A secondary (binary-walk) component is only added when no primary
    component already covers the same normalized name — syft's attribution
    is trusted where it exists; the walk fills the gaps and carries flags.
    """
    covered = {c.key for c in primary}
    merged = list(primary)
    for c in secondary:
        if c.key not in covered:
            merged.append(c)
            covered.add(c.key)
    return merged


def generate(
    target: str | Path,
    workdir: str | Path,
    yocto_metadata_dir: str | Path | None = None,
) -> GenerationResult:
    """Run the full Stage 1 pipeline against a firmware image or rootfs dir."""
    notes: list[str] = []
    extraction = extract(target, workdir)
    notes += extraction.notes
    root = extraction.root

    syft_components: list[Component] = []
    syft_sbom = run_syft(str(root), Path(workdir) / "syft-output.json")
    if syft_sbom is not None:
        syft_components = syft_sbom.components
        notes.append(f"syft identified {len(syft_components)} components")
    else:
        notes.append("syft not installed — component identification relies on the "
                     "native ELF walk only (coverage will be lower)")

    elf_components = walk_elf_binaries(root)
    flagged = [c for c in elf_components if "needs-manual-review" in c.flags]
    notes.append(
        f"native ELF walk found {len(elf_components)} binaries, "
        f"{len(flagged)} flagged for manual review (stripped/unknown version)"
    )

    components = merge_components(syft_components, elf_components)

    annotations: dict[str, dict] = {}
    if yocto_metadata_dir is not None:
        annotations = backports_mod.scan_build_tree(yocto_metadata_dir)
        notes.append(f"parsed {len(annotations)} Yocto CVE annotations "
                     f"(backports / not-applicable)")

    sbom = Sbom(
        components=components,
        target=str(target),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    return GenerationResult(sbom=sbom, backport_annotations=annotations, notes=notes)


def save_result(result: GenerationResult, out_dir: str | Path) -> dict[str, Path]:
    """Write CycloneDX (primary), annotations, and notes to out_dir."""
    from .cyclonedx import export_cyclonedx_json

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {}

    cdx_path = out / "sbom.cdx.json"
    cdx_path.write_text(
        json.dumps(export_cyclonedx_json(result.sbom), indent=2), encoding="utf-8"
    )
    paths["cyclonedx"] = cdx_path

    ann_path = out / "backport-annotations.json"
    ann_path.write_text(json.dumps(result.backport_annotations, indent=2), encoding="utf-8")
    paths["annotations"] = ann_path

    notes_path = out / "generation-notes.txt"
    notes_path.write_text("\n".join(result.notes) + "\n", encoding="utf-8")
    paths["notes"] = notes_path
    return paths
