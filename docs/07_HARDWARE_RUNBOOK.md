# Hardware Runbook — Raspberry Pi + AGL Benchmark

A single, ordered, copy-paste checklist for the parts of this project that
need real hardware and real internet access — neither of which the
development sandbox that built this repo had. Everything here has been
written and validated as far as possible without a Pi in hand (scripts
exist, compose files validate, unit tests cover the logic); what's left is
mechanical execution, not design work. Work through it top to bottom; check
off each `[ ]` as you go and note the actual result next to it (a runbook
only some steps of which were run is worth less than one that's honest
about where it stopped).

Total time: roughly a weekend for Tier 1 (drift + demo firmware), plus
another weekend for Tier 2 (AGL benchmark) if you do both. They're
independent — do either first.

---

## Part A — Raspberry Pi: drift detector + demo firmware

### A0. Prerequisites

- [ ] Raspberry Pi 5, powered, on the network, SSH reachable
- [ ] Raspberry Pi OS (64-bit) flashed and booted
- [ ] `sudo apt update && sudo apt full-upgrade -y` run once, rebooted

### A1. Install autosbom + external tools on the Pi

```sh
sudo apt install -y python3-pip python3-venv git
git clone https://github.com/michealswolski/AutoSBOM-Sentinel.git
cd AutoSBOM-Sentinel
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
autosbom --version   # confirm it prints 0.2.0 (or newer)
pytest -q            # confirm all tests pass on the Pi's own Python (arm64)
```

- [ ] `autosbom --version` prints the expected version
- [ ] `pytest -q` — record pass/fail count here: ____________
  (if anything fails *only* on the Pi and not on x86, that's a real,
  reportable finding — open an issue on it rather than ignoring it)

Install cosign (for signing the drift baseline):

```sh
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-arm64 \
  -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign
cosign version
```

- [ ] `cosign version` works on the Pi (arm64 build)

### A2. Baseline the Pi and sign it

```sh
autosbom baseline --output baseline.json
cosign generate-key-pair            # on your workstation, NOT the Pi --
                                     # copy only cosign.pub to the Pi
./signing/sign_artifact.sh key baseline.json     # run wherever cosign.key lives
scp baseline.json baseline.json.sig cosign.pub pi@<pi-host>:~/AutoSBOM-Sentinel/
```

- [ ] `baseline.json` created, records a real library/package count (compare
      to the 987 libs / 686 packages measured in the dev sandbox as a sanity
      check — a fresh Pi OS should be in the same ballpark, not wildly off)
- [ ] Baseline signed; `cosign.key` stays OFF the Pi

### A3. Run the drift daemon and prove detection

```sh
autosbom drift --baseline baseline.json --signature baseline.json.sig \
    --public-key cosign.pub --event-log /var/log/autosbom/drift.jsonl \
    --interval 300 &
```

- [ ] Daemon starts without a signature-verification error (confirms the
      cosign key-based flow — the one thing not yet exercised anywhere in
      this project, dev sandbox included)
- [ ] Let it run **24 hours untouched**. Record: zero drift events? Y/N —
      any false alarm here is a real bug, not a demo nuisance, and worth
      filing
- [ ] Tamper test: `sudo cp /bin/true /usr/lib/aarch64-linux-gnu/libdemo.so.1`
      (or any real shared lib you're comfortable overwriting) — confirm a
      `library-hash-mismatch` critical event appears within one poll interval
- [ ] Stop the daemon (`kill %1`), restore/reboot as needed

### A4. Demo firmware bring-up

Follow `demo-firmware/README.md` directly — it already has the exact
commands. In order:

- [ ] `sudo ./demo-firmware/setup_vcan_icsim.sh` — vcan0 up, ICSim running
      (build ICSim first per the script's own instructions if not installed)
- [ ] `modprobe can-isotp && ./demo-firmware/uds_sim.py vcan0` — UDS
      simulator answers a test request (`isotpsend`/`candump` per the
      script's docstring)
- [ ] `sudo apt install bluez && sudo bluetoothd --noplugin=avrcp &` — BlueZ
      running with AVRCP disabled (the PerfektBlue demo scenario)
- [ ] Run the full pipeline against this device: `autosbom generate` on a
      snapshot of the Pi's installed packages, `autosbom vex propose` against
      `examples/device-context.json` (already declares
      `"bluetooth.avrcp": false`), approve the CVE-2024-45434 proposal by
      name, export OpenVEX
- [ ] `./demo-firmware/ota_stub.py unauthorized <src> <dst>` — confirm the
      *next* drift sweep flags it (this is the "unauthorized OTA update"
      story end to end)

### A5. Dependency-Track, for real this time

The dev sandbox validated `dashboard/docker-compose.yml`'s syntax and
confirmed `docker compose up` correctly began pulling images before a
network policy blocked the layer download. On the Pi (or any machine with
normal internet):

```sh
./dashboard/verify.sh
```

- [ ] Reports healthy API + serving frontend (script fails loudly and
      specifically if not — read its output rather than assuming success)
- [ ] Upload a real build's SBOM via the API command the script prints at
      the end; confirm it appears in the UI

---

## Part B — Stage 0: real AGL benchmark

Full detail already lives in `docs/06_STAGE0_RUNBOOK.md` — this section is
just the ordered checklist version of it, run on a machine with normal
internet (the dev sandbox confirmed `download.automotivelinux.org` is
blocked by its network policy, so this genuinely could not be done there).

- [ ] Download an AGL release image + its official `.spdx.json` from
      `https://download.automotivelinux.org/AGL/release/` (pick a current
      ARM64 IVI-demo-class image; if the layout has visibly changed from
      what `docs/06` describes, note the discrepancy rather than guessing)
- [ ] Extract the rootfs (`docs/06` §2)
- [ ] Install syft, trivy; if attempting EMBA too, budget real time — it's
      heavyweight and containerized
- [ ] Run all three against the extracted rootfs, save each tool's JSON
      output
- [ ] `autosbom benchmark --ground-truth <agl>.spdx.json --tool-output
      syft=... --tool-output trivy=... --output stage0-results.md`
- [ ] Read the generated report. **Extend `DEFAULT_ALIASES` in
      `autosbom/stage0_benchmark/compare.py`** for any real cross-tool
      naming mismatch you find (every entry in that table should trace to
      an actual observed case — add the new ones the same way, and say so
      in the commit message)
- [ ] Manually verify a 20-40 CVE sample against the image's actual
      configuration (`docs/06` §5) — this is the slow, non-automatable part
      and also the most valuable one
- [ ] Score CVE accuracy with `compare_cves`; write the real precision/
      recall numbers into the report
- [ ] Only once you have real numbers: replace the "**Not yet produced**"
      row in the main README's status ledger with them, and cite this
      benchmark (not a borrowed statistic — see `docs/02_RESEARCH_FINDINGS.md`
      Corrections) anywhere else the project is described publicly

---

## Part C — Demo video

Once Parts A and B (or at least A) are done, a 60-90 second screen
recording:

1. Attack-surface heatmap (from a real `autosbom report` run on real data)
2. Raw-vs-post-VEX bar chart, narrating the PerfektBlue AVRCP suppression
   and that it required your named approval
3. Drift timeline showing the tamper event caught in Part A3
4. The green/verified signature indicator on the trusted baseline

- [ ] Recorded, under 90 seconds, all four beats present
- [ ] Linked from the main README (replace "Demo video: Not recorded")

---

## When you're done

Update these two places to match reality — don't leave them saying "not
yet" once they're not true anymore, and don't mark something done that
only partly worked:

- [ ] `README.md` → "Honest status ledger" table
- [ ] `CHANGELOG.md` → new entry (`0.3.0` feels right for "hardware-verified")
