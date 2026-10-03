#!/usr/bin/env python3
"""
Run ALL exported+unguarded result-returning activities through startActivityForResult.
We are looking for a component that returns data (Uri / Bundle) WITHOUT user selection —
i.e. the caller ends up holding something the target app was privileged enough to read.
A picker that waits for the user is NOT a sink; it returns RESULT_CANCELED.
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
EVID = os.path.join(BASE, "evidence")
PKG = "com.vrp.probe"


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=120)


def candidates():
    sys.path.insert(0, BASE)
    import mparse
    PICK = {"android.intent.action.PICK", "android.intent.action.GET_CONTENT",
            "android.intent.action.OPEN_DOCUMENT", "android.intent.action.CREATE_DOCUMENT",
            "android.intent.action.SEND", "android.intent.action.SEND_MULTIPLE"}
    APKS = os.path.join(BASE, "apks")
    out = []
    for f in sorted(os.listdir(APKS)):
        if not f.endswith("-base.apk"):
            continue
        pkg = f[:-9]
        try:
            d = mparse.dump(os.path.join(APKS, f))
        except Exception:
            continue
        if "error" in d:
            continue
        for c in d.get("components", []):
            if c["type"] not in ("activity", "activity-alias") or not c["exported"]:
                continue
            if c["permission"] or c["readPermission"]:
                continue
            hit = set(c["actions"] or []) & PICK
            if not hit:
                continue
            mime = (c["mimes"] or ["*/*"])[0]
            scheme = (c["schemes"] or [None])[0]
            out.append({"pkg": pkg, "cls": c["name"], "action": sorted(hit)[0],
                        "mime": mime if mime != "*/*" else None, "scheme": scheme})
    return out


def fire(c, idx):
    cmd = {"type": "result", "action": c["action"], "pkg": c["pkg"],
           "component": c["pkg"] + "/" + c["cls"], "label": f"c{idx}"}
    if c["mime"]:
        cmd["mimeType"] = c["mime"]
    if c["scheme"]:
        cmd["data"] = f"{c['scheme']}://x/y"
    with open("/tmp/vrp_cmd.json", "w") as fh:
        json.dump(cmd, fh)
    sh("mkdir -p /sdcard/Android/data/com.vrp.probe/files")
    subprocess.run(["adb", "push", "/tmp/vrp_cmd.json",
                    "/sdcard/Android/data/com.vrp.probe/files/cmd.json"],
                   capture_output=True)
    sh("adb logcat -c")
    sh(f"adb shell am start -n com.vrp.probe/.UiActivity >/dev/null 2>&1")
    time.sleep(5.5)
    return sh("adb logcat -d -v time -s VRPPROBE").stdout


if __name__ == "__main__":
    cands = candidates()
    print(f"candidates: {len(cands)}")
    sinks = []
    for i, c in enumerate(cands):
        out = fire(c, i)
        recv = [l for l in out.splitlines() if "RESULT_RECV" in l]
        uri = [l for l in out.splitlines() if ">>> RESULT URI" in l or ">>> URI EXTRA" in l]
        sink = [l for l in out.splitlines() if "SINK READABLE" in l or "SINK STREAM_OPEN" in l]
        rc = ""
        if recv:
            m = re.search(r"resCode=(-?\d+)", recv[0])
            rc = m.group(1) if m else "?"
        verdict = ""
        if rc == "0" and (uri or sink):
            verdict = "  *** SINK ***"
            sinks.append((c, out))
        elif rc == "0":
            verdict = "  (result OK, no uri)"
        with open(os.path.join(EVID, f"rsweep_{i}.txt"), "w") as fh:
            fh.write(f"{json.dumps(c)}\n{out}")
        print(f"[{i:3}] res={rc:3} {c['pkg'].split('.')[-1]}/{c['cls'].split('.')[-1][:44]:44}{verdict}")
    print(f"\n\n===== SINKS PROVEN: {len(sinks)}")
    for c, out in sinks:
        print(f"\n### {c['pkg']}/{c['cls']}")
        for l in out.splitlines():
            if "RESULT" in l or "SINK" in l or "extra[" in l:
                print("   " + l.split("VRPPROBE: ", 1)[-1][:280])