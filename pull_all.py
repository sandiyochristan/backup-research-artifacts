#!/usr/bin/env python3
"""Pull base.apk for every com.google.* / com.android.* package. Resumable, parallel-ish."""
import os
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
APKS = os.path.join(BASE, "apks")
os.makedirs(APKS, exist_ok=True)
PKGS = [l.strip() for l in open(os.path.join(BASE, "all_pkgs.txt")) if l.strip()]


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=180)


def main():
    todo = []
    for p in PKGS:
        dest = os.path.join(APKS, f"{p}-base.apk")
        if os.path.exists(dest) and os.path.getsize(dest) > 1000:
            continue
        todo.append(p)
    print(f"total={len(PKGS)} already={len(PKGS)-len(todo)} todo={len(todo)}", flush=True)
    ok = fail = 0
    for i, p in enumerate(todo):
        r = sh(f"adb shell pm path {p}")
        paths = [l.replace("package:", "").strip() for l in r.stdout.splitlines() if l.strip()]
        # system packages are named e.g. Settings.apk, not base.apk -> prefer base.apk else first
        base = [x for x in paths if x.endswith("/base.apk")]
        src = base[0] if base else (paths[0] if paths else None)
        if not src:
            fail += 1
            continue
        dest = os.path.join(APKS, f"{p}-base.apk")
        try:
            rr = subprocess.run(["adb", "pull", src, dest], capture_output=True,
                                text=True, timeout=300)
            if rr.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 1000:
                ok += 1
            else:
                fail += 1
        except Exception:
            fail += 1
        if (i + 1) % 25 == 0:
            print(f"  [{i+1}/{len(todo)}] ok={ok} fail={fail}", flush=True)
    print(f"DONE ok={ok} fail={fail}", flush=True)


if __name__ == "__main__":
    main()