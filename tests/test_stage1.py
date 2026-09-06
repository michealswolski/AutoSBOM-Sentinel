import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from autosbom.common.models import Component, Sbom
from autosbom.stage1_generator import backports
from autosbom.stage1_generator.cyclonedx import export_cyclonedx_json
from autosbom.stage1_generator.elf_flags import (
    component_from_binary, guess_version_from_soname,
    guess_version_from_strings, is_elf, is_stripped,
)
from autosbom.stage1_generator.extract import extract
from autosbom.stage1_generator.generate import merge_components, walk_elf_binaries


def _minimal_elf(with_symtab: bool) -> bytes:
    """Hand-assemble a tiny but structurally valid 64-bit little-endian ELF
    with a section header table; optionally include a SHT_SYMTAB section."""
    ehsize, shentsize = 64, 64
    sections = [0]  # SHT_NULL
    if with_symtab:
        sections.append(2)  # SHT_SYMTAB
    shoff = ehsize
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header += struct.pack("<HHIQQQIHHHHHH",
                          2, 0x3E, 1,        # type=EXEC, machine=x86-64, version
                          0,                  # entry
                          0, shoff,           # phoff, shoff
                          0,                  # flags
                          ehsize, 0, 0,       # ehsize, phentsize, phnum
                          shentsize, len(sections), 0)  # shentsize, shnum, shstrndx
    body = b""
    for sh_type in sections:
        body += struct.pack("<IIQQQQIIQQ", 0, sh_type, 0, 0, 0, 0, 0, 0, 0, 0)
    return header + body


def test_is_elf(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(_minimal_elf(with_symtab=True))
    assert is_elf(f)
    g = tmp_path / "not-elf"
    g.write_bytes(b"#!/bin/sh\necho hi\n")
    assert not is_elf(g)


def test_is_stripped_synthetic(tmp_path):
    stripped = tmp_path / "stripped.so"
    stripped.write_bytes(_minimal_elf(with_symtab=False))
    assert is_stripped(stripped)

    unstripped = tmp_path / "unstripped.so"
    unstripped.write_bytes(_minimal_elf(with_symtab=True))
    assert not is_stripped(unstripped)


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")
def test_is_stripped_real_binary(tmp_path):
    src = tmp_path / "t.c"
    src.write_text("int main(void){return 0;}\n")
    out = tmp_path / "t"
    subprocess.run(["gcc", "-o", str(out), str(src)], check=True)
    assert is_elf(out)
    assert not is_stripped(out)
    subprocess.run(["strip", str(out)], check=True)
    assert is_stripped(out)


def test_soname_version():
    assert guess_version_from_soname("libssl.so.1.1") == "1.1"
    assert guess_version_from_soname("libfoo.so") == ""


def test_version_from_strings(tmp_path):
    f = tmp_path / "libcrypto.so"
    f.write_bytes(_minimal_elf(True) + b"\x00OpenSSL 1.1.1n  15 Mar 2022\x00"
                  + b"1.1.1n\x00" * 3)
    v = guess_version_from_strings(f)
    assert v == "1.1.1n"


def test_component_from_binary_flags_stripped_unknown(tmp_path):
    f = tmp_path / "libmystery.so"
    f.write_bytes(_minimal_elf(with_symtab=False))
    comp = component_from_binary(f)
    assert comp.name == "mystery"
    assert comp.version_unknown
    assert "stripped-binary" in comp.flags
    assert "needs-manual-review" in comp.flags
    assert comp.identification_confidence < 0.5


def test_backport_cve_status_parsing():
    text = '''
SUMMARY = "zlib"
CVE_STATUS[CVE-2022-9999] = "backported-patch: fixed via debian patch 001"
CVE_STATUS[CVE-2021-1234] = "not-applicable-config: feature disabled"
CVE_CHECK_IGNORE += "CVE-2020-0001 CVE-2020-0002"
'''
    result = backports.parse_recipe_text(text)
    assert result["CVE-2022-9999"]["status"] == "fixed"
    assert result["CVE-2021-1234"]["status"] == "not_affected"
    assert result["CVE-2020-0001"]["status"] == "not_affected"
    assert result["CVE-2020-0001"]["source"] == "CVE_CHECK_IGNORE"


def test_backport_scan_build_tree(tmp_path):
    recipe = tmp_path / "meta-demo" / "recipes-core" / "zlib"
    recipe.mkdir(parents=True)
    (recipe / "zlib_1.2.13.bb").write_text(
        'CVE_STATUS[CVE-2022-9999] = "backported-patch: debian patch"\n'
    )
    annotations = backports.scan_build_tree(tmp_path)
    assert "CVE-2022-9999" in annotations
    assert annotations["CVE-2022-9999"]["recipe"].endswith("zlib_1.2.13.bb")


def test_cve_check_output_parsing():
    text = """
PACKAGE NAME: zlib
CVE: CVE-2022-9999
CVE STATUS: Patched

PACKAGE NAME: zlib
CVE: CVE-2023-1111
CVE STATUS: Unpatched
"""
    result = backports.parse_cve_check_output(text)
    assert result["CVE-2022-9999"]["status"] == "fixed"
    assert "CVE-2023-1111" not in result


def test_walk_and_merge(tmp_path):
    libdir = tmp_path / "usr" / "lib"
    libdir.mkdir(parents=True)
    (libdir / "libssl.so.3.0.7").write_bytes(_minimal_elf(False))
    (libdir / "libunknown.so").write_bytes(_minimal_elf(False))

    found = walk_elf_binaries(tmp_path)
    names = {c.name for c in found}
    assert names == {"ssl", "unknown"}
    ssl = [c for c in found if c.name == "ssl"][0]
    assert ssl.version == "3.0.7"
    assert "sha256" in ssl.hashes

    # merge: syft already knows openssl -> the walk's "ssl" is still added
    # (different normalized name), but a duplicate of an existing key is not.
    primary = [Component(name="unknown", version="1.0", ecosystem="pypi")]
    merged = merge_components(primary, found)
    merged_names = [c.name for c in merged]
    assert merged_names.count("unknown") == 1
    assert "ssl" in merged_names


def test_extract_passthrough(tmp_path):
    result = extract(tmp_path, tmp_path / "work")
    assert result.method == "directory-passthrough"
    assert result.root == tmp_path


def test_extract_missing_binwalk_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    img = tmp_path / "firmware.bin"
    img.write_bytes(b"\x00" * 128)
    with pytest.raises(RuntimeError, match="binwalk"):
        extract(img, tmp_path / "work")


def test_cyclonedx_export_structure():
    sbom = Sbom(
        components=[
            Component(name="openssl", version="3.0.8", ecosystem="generic",
                      licenses=["Apache-2.0"], hashes={"sha256": "ab" * 32}),
            Component(name="mystery", version="", ecosystem="generic",
                      version_unknown=True,
                      identification_confidence=0.3,
                      flags=["stripped-binary", "needs-manual-review"]),
        ],
        target="demo-image",
    )
    doc = export_cyclonedx_json(sbom)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["metadata"]["component"]["name"] == "demo-image"
    mystery = [c for c in doc["components"] if c["name"] == "mystery"][0]
    props = {p["name"]: p["value"] for p in mystery["properties"]
             if p["name"] != "autosbom:flag"}
    assert props["autosbom:version-unknown"] == "true"
    flags = [p["value"] for p in mystery["properties"] if p["name"] == "autosbom:flag"]
    assert "stripped-binary" in flags
    json.dumps(doc)  # serializable
