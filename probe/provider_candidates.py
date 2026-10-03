#!/usr/bin/env python3
"""
Systematic sweep: query EVERY exported content provider that has no permission guard,
from the zero-permission probe app. Any provider that returns rows is a proven data-exposure
finding (this is the "sensitive data theft" class Google explicitly pays for).

Uses triage.json (built by triage.py) as the candidate source.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)
import mparse  # noqa

TRIAGE = os.path.join(BASE, "manifests", "triage.json")
APKS = os.path.join(BASE, "apks")


def build_candidates():
    if os.path.exists(TRIAGE):
        rows = json.load(open(TRIAGE))
        cands = []
        for r in rows:
            c = r["comp"]
            if c["type"] != "provider" or not c["exported"]:
                continue
            if c["permission"] or c["readPermission"] or c["writePermission"]:
                continue
            auth = c.get("authorities")
            if auth:
                cands.append((r["pkg"], c["name"], auth, r["score"]))
        return cands

    # rebuild from APKs directly
    cands = []
    for f in sorted(os.listdir(APKS)):
        if not f.endswith("-base.apk"):
            continue
        pkg = f[:-len("-base.apk")]
        try:
            d = mparse.dump(os.path.join(APKS, f))
        except Exception:
            continue
        if "error" in d:
            continue
        for c in d.get("components", []):
            if (c["type"] == "provider" and c["exported"]
                    and not (c["permission"] or c["readPermission"] or c["writePermission"])
                    and c.get("authorities")):
                cands.append((pkg, c["name"], c["authorities"], 0))
    return cands


if __name__ == "__main__":
    c = build_candidates()
    # also read the on-device provider list to catch anything the APK scan missed
    import subprocess
    out = subprocess.run("adb shell dumpsys package providers", shell=True,
                         capture_output=True, text=True).stdout
    on_device = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("[") and ":" in line:
            auth = line[1:].split("]")[0]
            on_device.append(auth)
    print(f"exported+unguarded providers from APKs: {len(c)}")
    print(f"authorities present on device            : {len(on_device)}")
    print()
    for pkg, name, auth, score in sorted(c, key=lambda x: -x[3]):
        present = "ON-DEVICE" if auth in on_device else "not-on-device"
        print(f"  {pkg}\n      {name}\n      authority: {auth}   [{present}]")
    json.dump([{"pkg": p, "cls": n, "authority": a, "score": s} for p, n, a, s in c],
              open(os.path.join(BASE, "manifests", "unguarded_providers.json"), "w"), indent=1)
    json.dump(on_device, open(os.path.join(BASE, "manifests", "device_authorities.json"), "w"))