#!/usr/bin/env python3
"""
Identify LAN-reachable TCP listeners on the Pixel and who owns them.
A connection from a *different machine on the LAN* is a remote attack surface with no app
install — the class that Google does not downgrade to "user must install a malicious app".
"""
import socket
import subprocess
import threading
import time

HOST = "192.168.1.34"
PORTS = [51692, 53601, 64660, 46697, 8009, 8443, 5353, 32768, 3000, 8080]


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=60)


def lcat():
    sh("adb logcat -c")
    return sh("adb logcat -d -v time").stdout


def probe(port, payload=b"", wait=3.0):
    sh("adb logcat -c")
    time.sleep(0.4)
    try:
        s = socket.create_connection((HOST, port), timeout=4)
    except Exception as e:
        return None, f"CONNECT_FAIL {e}"
    s.settimeout(wait)
    banner = b""
    try:
        if payload:
            s.sendall(payload)
        else:
            s.sendall(b"\r\n\r\n")
        try:
            banner = s.recv(2048)
        except socket.timeout:
            banner = b"<timeout: server sent nothing>"
    except Exception as e:
        banner = f"<recv err {e}>".encode()
    finally:
        try:
            s.close()
        except Exception:
            pass
    time.sleep(1.5)
    log = sh("adb logcat -d -v time").stdout
    return banner, log


if __name__ == "__main__":
    import sys
    targets = [int(x) for x in sys.argv[1:]] or PORTS
    for p in targets:
        print(f"\n{'='*95}\n### PORT {p}")
        banner, log = probe(p)
        if banner is None:
            print("   ", banner)
            continue
        try:
            btxt = banner.decode("utf-8", "replace")
        except Exception:
            btxt = repr(banner)
        print(f"    BANNER: {btxt[:400]}")
        # which app reacted?
        interesting = [l for l in log.splitlines()
                       if any(k in l for k in (
                           "Cast", "cast", "HomeApp", "chromecast", "Nearby", "nearby",
                           "WifiAware", "Aware", "NSD", "nsd", "Mdns", "mdns",
                           "GATT", "gatt", "Bluetooth", "bluetooth",
                           "MediaProjection", "screen", "Screen",
                           "AdbService", "adbd", "debuggerd",
                           "Socket", "socket", "accept", "Accept",
                           "NetworkService", "dns", "DNS"))]
        seen = set()
        for l in interesting:
            k = l[:160]
            if k in seen:
                continue
            seen.add(k)
            print("    ~ " + k[:230])
            if len(seen) > 25:
                break