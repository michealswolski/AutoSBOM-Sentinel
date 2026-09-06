#!/usr/bin/env python3
"""Stub OTA update client — gives Stage 3 drift detection its story.

Simulates an over-the-air update by replacing a target file with new content
fetched from a local "update server" directory. Two modes:

  authorized:    updates the file AND re-runs `autosbom baseline` afterwards,
                 mirroring the legitimate flow (update -> re-baseline -> re-sign).
  unauthorized:  updates the file and does NOT touch the baseline — exactly the
                 tamper/unauthorized-update scenario the drift daemon exists to
                 catch on its next sweep.

Usage:
  ./ota_stub.py authorized   /path/updates/libdemo.so.1 /target/lib/libdemo.so.1 baseline.json
  ./ota_stub.py unauthorized /path/updates/libdemo.so.1 /target/lib/libdemo.so.1
"""
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    mode, src, dst = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    if mode not in ("authorized", "unauthorized"):
        print("mode must be 'authorized' or 'unauthorized'", file=sys.stderr)
        return 2

    shutil.copy2(src, dst)
    print(f"applied update: {src} -> {dst}")

    if mode == "authorized":
        baseline = sys.argv[4] if len(sys.argv) > 4 else "baseline.json"
        lib_dir = str(dst.parent)
        subprocess.run(
            [sys.executable, "-m", "autosbom.cli", "baseline",
             "--output", baseline, "--lib-dirs", lib_dir],
            check=True,
        )
        print(f"re-baselined to {baseline} — REMEMBER: re-sign it "
              f"(signing/sign_artifact.sh) before the drift daemon will trust it.")
    else:
        print("baseline NOT updated — the drift daemon should flag this file "
              "on its next sweep (that's the demo).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
