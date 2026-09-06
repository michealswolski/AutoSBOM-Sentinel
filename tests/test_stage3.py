import json
from pathlib import Path

import pytest

from autosbom.stage3_drift.daemon import DaemonConfig, create_baseline, run_once
from autosbom.stage3_drift.diff import diff_inventories
from autosbom.stage3_drift.inventory import Inventory, take_inventory
from autosbom.stage3_drift.verify import (
    BaselineVerificationError, VerificationPolicy, verify_baseline,
)


@pytest.fixture
def fake_rootfs(tmp_path):
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "libdemo.so.1").write_bytes(b"\x7fELF-original-demo-library")
    (lib / "libother.so.2").write_bytes(b"\x7fELF-other-library")
    return tmp_path


def test_take_inventory_scoped_to_dir(fake_rootfs):
    inv = take_inventory([str(fake_rootfs / "lib")])
    assert len(inv.shared_libraries) == 2
    assert all(len(h) == 64 for h in inv.shared_libraries.values())
    assert inv.timestamp


def test_inventory_roundtrip(fake_rootfs, tmp_path):
    inv = take_inventory([str(fake_rootfs / "lib")])
    p = tmp_path / "baseline.json"
    inv.save(p)
    loaded = Inventory.load(p)
    assert loaded.shared_libraries == inv.shared_libraries


def test_diff_detects_swap_add_remove(fake_rootfs):
    libdir = str(fake_rootfs / "lib")
    baseline = take_inventory([libdir])

    # Simulate the demo tamper scenario: swap a shared library's contents,
    # add a new one, remove another.
    (fake_rootfs / "lib" / "libdemo.so.1").write_bytes(b"\x7fELF-TAMPERED-library!!")
    (fake_rootfs / "lib" / "libinjected.so").write_bytes(b"\x7fELF-injected")
    (fake_rootfs / "lib" / "libother.so.2").unlink()

    current = take_inventory([libdir])
    events = diff_inventories(baseline, current)
    kinds = {(e.kind, Path(e.subject).name) for e in events}
    assert ("library-hash-mismatch", "libdemo.so.1") in kinds
    assert ("library-added", "libinjected.so") in kinds
    assert ("library-removed", "libother.so.2") in kinds
    mismatch = [e for e in events if e.kind == "library-hash-mismatch"][0]
    assert mismatch.severity == "critical"


def test_clean_diff_zero_events(fake_rootfs):
    libdir = str(fake_rootfs / "lib")
    baseline = take_inventory([libdir])
    current = take_inventory([libdir])
    assert diff_inventories(baseline, current) == []


def test_package_and_kmod_diff():
    b = Inventory(timestamp="t0", hostname="h",
                  packages={"openssl": "3.0.8", "zlib": "1.2.13"},
                  kernel_modules=["can", "vcan"])
    c = Inventory(timestamp="t1", hostname="h",
                  packages={"openssl": "3.0.9", "curl": "8.0"},
                  kernel_modules=["can"])
    kinds = {(e.kind, e.subject) for e in diff_inventories(b, c)}
    assert ("package-version-changed", "openssl") in kinds
    assert ("package-added", "curl") in kinds
    assert ("package-removed", "zlib") in kinds
    assert ("kmod-removed", "vcan") in kinds


def test_verify_requires_cosign_or_fails(tmp_path, monkeypatch):
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: None)
    baseline = tmp_path / "b.json"
    baseline.write_text("{}")
    sig = tmp_path / "b.sig"
    sig.write_text("x")
    with pytest.raises(BaselineVerificationError, match="cosign is not installed"):
        verify_baseline(baseline, sig, VerificationPolicy(require_signature=True))


def test_verify_skipped_only_when_policy_allows(tmp_path):
    baseline = tmp_path / "b.json"
    baseline.write_text("{}")
    result = verify_baseline(baseline, tmp_path / "missing.sig",
                             VerificationPolicy(require_signature=False))
    assert result is False  # explicitly unverified, no exception


def test_run_once_end_to_end(fake_rootfs, tmp_path):
    libdir = str(fake_rootfs / "lib")
    baseline_path = tmp_path / "baseline.json"
    create_baseline(baseline_path, [libdir])

    # Tamper after baselining.
    (fake_rootfs / "lib" / "libdemo.so.1").write_bytes(b"\x7fELF-TAMPERED")

    cfg = DaemonConfig(
        baseline_path=baseline_path,
        event_log_path=tmp_path / "events.jsonl",
        poll_interval_seconds=1,
        lib_dirs=[libdir],
        policy=VerificationPolicy(require_signature=False),  # dev mode for test
    )
    records = run_once(cfg)
    drift = [r for r in records if r.get("kind") == "library-hash-mismatch"]
    assert len(drift) == 1
    assert drift[0]["baseline_verified"] is False

    # Log is JSONL and includes the heartbeat sweep record.
    lines = [json.loads(l) for l in
             (tmp_path / "events.jsonl").read_text().splitlines()]
    assert any(l.get("kind") == "sweep-complete" for l in lines)


def test_daemon_refuses_unsigned_baseline_by_default(fake_rootfs, tmp_path):
    libdir = str(fake_rootfs / "lib")
    baseline_path = tmp_path / "baseline.json"
    create_baseline(baseline_path, [libdir])
    cfg = DaemonConfig(
        baseline_path=baseline_path,
        event_log_path=tmp_path / "events.jsonl",
        lib_dirs=[libdir],
        policy=VerificationPolicy(require_signature=True),
        signature_path=None,
    )
    with pytest.raises(BaselineVerificationError):
        run_once(cfg)
