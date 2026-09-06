# Demo Firmware Environment (Tier 3)

Realistic automotive stacks on the Raspberry Pi 5 so the pipeline has
authentic, CVE-bearing targets — not just generic Linux packages.

## Pieces

| Piece | File / package | Status |
|---|---|---|
| Virtual CAN bus + ICSim | `setup_vcan_icsim.sh` | script provided; ICSim built separately; **requires a Linux box with module loading — not yet run on the target Pi** |
| UDS diagnostic simulator | `uds_sim.py` | implemented (ISO-TP sockets); **requires `can-isotp` kernel module — not yet run on the target Pi** |
| Bluetooth stack | BlueZ (distro package) | see PerfektBlue demo below |
| OTA client stub | `ota_stub.py` | implemented; drives the Stage 3 drift demo |

## Hardware CAN (optional)

With an MCP2515 HAT, add to `/boot/firmware/config.txt`:

```
dtparam=spi=on
dtoverlay=mcp2515-can0,oscillator=16000000,interrupt=25
```

then `sudo ip link set can0 up type can bitrate 500000`. Everything in this
directory also works on `vcan0` with no hardware.

## The PerfektBlue VEX demo scenario

1. Install BlueZ (`sudo apt install bluez`) — a real, CVE-bearing Bluetooth
   stack that echoes the PerfektBlue narrative.
2. Disable the AVRCP profile in the demo configuration (e.g. run `bluetoothd`
   with a restricted plugin set: `bluetoothd --noplugin=avrcp`).
3. Declare that in the device context (`examples/device-context.json` has
   `"bluetooth.avrcp": false`).
4. Run a scan + `autosbom vex propose` — the AVRCP-profile CVE gets a
   *proposed* `not_affected` (`vulnerable_code_not_in_execute_path`), which
   you then review and approve by name. That is the PerfektBlue story told
   in tooling: the same class of CVE, correctly triaged in minutes because
   the SBOM + context existed.

## The unauthorized-OTA drift demo

```sh
autosbom baseline --output baseline.json --lib-dirs /usr/lib
./signing/sign_artifact.sh key baseline.json     # sign it (see signing/)
autosbom drift --baseline baseline.json --signature baseline.json.sig \
    --public-key cosign.pub --event-log drift.jsonl &   # daemon running
./ota_stub.py unauthorized updates/libdemo.so.1 /usr/lib/libdemo.so.1
# next sweep -> critical library-hash-mismatch event in drift.jsonl
```

The tamper-detection mechanics (baseline → swap file → critical
`library-hash-mismatch` within one sweep) are unit-tested and were exercised
end-to-end in a Linux container; the 24-hour zero-false-alarm baseline run
described in the build plan still needs to be performed on the actual Pi.
