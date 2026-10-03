#!/usr/bin/env python3
"""
Characterise the pre-auth gate on the remote-reachable GMS Nearby Connections WIFI_LAN listener.
Goal: determine how far an unauthenticated LAN attacker gets, and whether any input reaches a
service handler before authentication.
"""
import socket
import struct
import subprocess
import time

HOST = "192.168.1.34"
PORT = None  # discovered at runtime


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=90)


def discover():
    out = sh("adb shell cat /proc/net/tcp6").stdout
    cand = []
    for ln in out.splitlines()[1:]:
        p = ln.split()
        if len(p) < 4 or p[3] != "0A":
            continue
        port = int(p[1].rsplit(":", 1)[1], 16)
        cand.append(port)
    # probe each until one is a Nearby listener
    for p in cand:
        sh("adb logcat -c")
        try:
            s = socket.create_connection((HOST, p), timeout=3)
            s.sendall(b"\x00\x00\x00\x04TEST")
            time.sleep(1.5)
            s.close()
        except Exception:
            continue
        time.sleep(1)
        log = sh("adb logcat -d").stdout
        if "MultiplexSocket" in log or "NearbyConnections" in log:
            return p
    return None


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def tag(field, wt):
    return varint((field << 3) | wt)


def s_field(field, s):
    b = s.encode()
    return tag(field, 2) + varint(len(b)) + b


def v_field(field, n):
    return tag(field, 0) + varint(n)


def frame(payload):
    return struct.pack(">I", len(payload)) + payload


def send_raw(payload, label, hold=4.0):
    sh("adb logcat -c")
    time.sleep(0.3)
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
    except Exception as e:
        print(f"  {label}: CONNECT_FAIL {e}")
        return
    s.settimeout(hold)
    try:
        s.sendall(frame(payload))
        time.sleep(hold)
        try:
            d = s.recv(2048)
        except socket.timeout:
            d = b"<no reply>"
    finally:
        try:
            s.close()
        except Exception:
            pass
    time.sleep(1)
    log = sh("adb logcat -d -v time").stdout
    keep = [l for l in log.splitlines()
            if any(k in l for k in ("Nearby", "nearby", "Multiplex", "ConnectionRequest",
                                    "Failed", "failed", "Exception", "auth", "Auth",
                                    "token", "Token", "password"))]
    print(f"\n  --- {label}  ({len(payload)} bytes)")
    seen = set()
    for l in keep:
        k = l[:150]
        if k in seen:
            continue
        seen.add(k)
        print("      " + l[:250])
        if len(seen) > 12:
            break


if __name__ == "__main__":
    PORT = discover()
    print(f"### Nearby WIFI_LAN listener at {HOST}:{PORT}\n")
    if not PORT:
        print("could not rediscover port")
        raise SystemExit(1)
    # 1. pure garbage inside a valid length prefix
    send_raw(b"\xde\xad\xbe\xef" * 8, "garbage-in-valid-length")
    # 2. plausible ConnectionRequestFrame shape: strings + ints, no real token
    crf = (s_field(1, "ATTACKER") + s_field(2, "0.0.0.0") + v_field(3, 1)
           + s_field(4, "WiFi") + v_field(5, 1) + v_field(6, 5000)
           + v_field(7, 5000) + v_field(8, 1000) + s_field(9, "ATTACKER_PASSWORD"))
    send_raw(crf, "plausible-ConnectionRequestFrame-bad-token")
    # 3. empty frame
    send_raw(b"", "empty-frame")