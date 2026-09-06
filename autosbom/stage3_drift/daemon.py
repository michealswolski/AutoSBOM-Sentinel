"""The drift-detection daemon loop.

Runs on the device (Raspberry Pi 5 as the ECU stand-in): verify the signed
baseline once at startup, then periodically re-inventory and append drift
events to a JSONL log. Also usable one-shot (``run_once``) for cron-style
scheduling or testing.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .diff import diff_inventories
from .inventory import Inventory, take_inventory
from .verify import BaselineVerificationError, VerificationPolicy, verify_baseline


@dataclass
class DaemonConfig:
    baseline_path: Path
    event_log_path: Path
    signature_path: Path | None = None
    poll_interval_seconds: int = 300
    lib_dirs: list[str] | None = None
    policy: VerificationPolicy = field(default_factory=VerificationPolicy)


def _log_event(log_path: Path, record: dict) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def load_verified_baseline(cfg: DaemonConfig) -> tuple[Inventory, bool]:
    """Load the baseline, enforcing the signature policy. Returns (baseline, verified)."""
    verified = False
    if cfg.policy.require_signature:
        if cfg.signature_path is None:
            raise BaselineVerificationError(
                "verification policy requires a signature but no signature "
                "path was configured"
            )
        verified = verify_baseline(cfg.baseline_path, cfg.signature_path, cfg.policy)
    baseline = Inventory.load(cfg.baseline_path)
    return baseline, verified


def run_once(cfg: DaemonConfig, baseline: Inventory | None = None,
             baseline_verified: bool = False) -> list[dict]:
    """One polling sweep: inventory, diff, log. Returns logged event dicts."""
    if baseline is None:
        baseline, baseline_verified = load_verified_baseline(cfg)
    current = take_inventory(cfg.lib_dirs)
    events = diff_inventories(baseline, current)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    records = []
    for e in events:
        record = {
            "timestamp": now,
            "baseline_verified": baseline_verified,
            **e.to_dict(),
        }
        _log_event(cfg.event_log_path, record)
        records.append(record)
    # Heartbeat record so a clean 24h run is demonstrably clean, not silent.
    heartbeat = {
        "timestamp": now,
        "kind": "sweep-complete",
        "baseline_verified": baseline_verified,
        "drift_events": len(events),
        "libraries_checked": len(current.shared_libraries),
        "packages_checked": len(current.packages),
        "kernel_modules_checked": len(current.kernel_modules),
    }
    _log_event(cfg.event_log_path, heartbeat)
    records.append(heartbeat)
    return records


def run_forever(cfg: DaemonConfig) -> None:  # pragma: no cover - infinite loop
    baseline, verified = load_verified_baseline(cfg)
    if not verified:
        _log_event(cfg.event_log_path, {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "kind": "warning-unverified-baseline",
            "detail": "daemon started WITHOUT baseline signature verification "
                      "(development mode). Do not trust drift results for "
                      "integrity claims.",
        })
    while True:
        run_once(cfg, baseline, verified)
        time.sleep(cfg.poll_interval_seconds)


def create_baseline(out_path: str | Path, lib_dirs: list[str] | None = None) -> Inventory:
    """Take an inventory and save it as the baseline (to be signed afterwards)."""
    inv = take_inventory(lib_dirs)
    inv.save(out_path)
    return inv
