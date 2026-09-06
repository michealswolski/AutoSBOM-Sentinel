#!/usr/bin/env bash
# Set up a virtual CAN bus and (optionally) launch ICSim on the Raspberry Pi.
# ICSim: https://github.com/zombieCraig/ICSim  (build it separately)
# Hardware CAN (MCP2515 HAT) setup is in the README — this script is the
# no-hardware virtual-bus path so the demo works on any Linux box.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (needs to load kernel modules / create interfaces)" >&2
  exit 1
fi

modprobe can can_raw vcan
ip link show vcan0 >/dev/null 2>&1 || ip link add dev vcan0 type vcan
ip link set up vcan0
echo "vcan0 is up."

if command -v icsim >/dev/null 2>&1; then
  echo "starting ICSim on vcan0 (Ctrl-C to stop)..."
  icsim vcan0 &
  controls vcan0
else
  cat <<'MSG'
ICSim not found on PATH. Build it:
  git clone https://github.com/zombieCraig/ICSim && cd ICSim && make
Then run:  ./icsim vcan0   and   ./controls vcan0
Sanity check without ICSim:  cansend vcan0 123#DEADBEEF  +  candump vcan0
MSG
fi
