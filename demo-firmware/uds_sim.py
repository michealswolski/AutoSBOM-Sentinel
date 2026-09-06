#!/usr/bin/env python3
"""Minimal UDS (ISO 14229) diagnostic-service simulator over SocketCAN ISO-TP.

Answers a small, realistic subset so diagnostic traffic exists on the demo
bus for the pipeline's narrative (a diagnostics-exposed component):

  0x10 DiagnosticSessionControl  -> positive response
  0x22 ReadDataByIdentifier      -> VIN (0xF190) and SW version (0xF195)
  0x27 SecurityAccess            -> seed, and a deliberately-trivial key check
                                    (the point is to HAVE an auth surface to
                                    talk about, not a strong one)
  anything else                  -> NRC 0x11 serviceNotSupported

Requires the can-isotp kernel module (Linux >= 5.10 has it in-tree):
  sudo modprobe can-isotp
Run:
  ./uds_sim.py vcan0            # server on rx 0x7E0 / tx 0x7E8
Test from another shell (needs can-utils isotp tools):
  echo "22 F1 90" | isotpsend -s 7E0 -d 7E8 vcan0
"""
import socket
import struct
import sys

VIN = b"AUTOSBOMSENTINEL1"          # 17 chars, synthetic
SW_VERSION = b"autosbom-demo-0.1.0"
SEED = bytes.fromhex("11223344")

NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNC_NOT_SUPPORTED = 0x12
NRC_REQUEST_OUT_OF_RANGE = 0x31
NRC_INVALID_KEY = 0x35


def negative(service: int, nrc: int) -> bytes:
    return bytes([0x7F, service, nrc])


def handle(req: bytes) -> bytes:
    if not req:
        return negative(0x00, NRC_SERVICE_NOT_SUPPORTED)
    service = req[0]
    if service == 0x10 and len(req) >= 2:              # DiagnosticSessionControl
        return bytes([0x50, req[1]]) + struct.pack(">HH", 0x0032, 0x01F4)
    if service == 0x22 and len(req) >= 3:              # ReadDataByIdentifier
        did = (req[1] << 8) | req[2]
        if did == 0xF190:
            return bytes([0x62, 0xF1, 0x90]) + VIN
        if did == 0xF195:
            return bytes([0x62, 0xF1, 0x95]) + SW_VERSION
        return negative(service, NRC_REQUEST_OUT_OF_RANGE)
    if service == 0x27 and len(req) >= 2:              # SecurityAccess
        sub = req[1]
        if sub == 0x01:
            return bytes([0x67, 0x01]) + SEED
        if sub == 0x02:
            key = req[2:6]
            expected = bytes(b ^ 0xFF for b in SEED)   # toy algorithm, on purpose
            if key == expected:
                return bytes([0x67, 0x02])
            return negative(service, NRC_INVALID_KEY)
        return negative(service, NRC_SUBFUNC_NOT_SUPPORTED)
    return negative(service, NRC_SERVICE_NOT_SUPPORTED)


def main() -> int:
    iface = sys.argv[1] if len(sys.argv) > 1 else "vcan0"
    rx_id, tx_id = 0x7E0, 0x7E8
    try:
        sock = socket.socket(socket.AF_CAN, socket.CAN_ISOTP)
        sock.bind((iface, rx_id, tx_id))
    except OSError as exc:
        print(f"error: ISO-TP socket on {iface} failed ({exc}). "
              f"Did you `modprobe can-isotp` and create the interface?",
              file=sys.stderr)
        return 1
    print(f"UDS simulator listening on {iface} rx=0x{rx_id:X} tx=0x{tx_id:X}")
    while True:
        req = sock.recv(4095)
        resp = handle(req)
        sock.send(resp)
        print(f"  <- {req.hex(' ')}   -> {resp.hex(' ')}")


if __name__ == "__main__":
    raise SystemExit(main())
