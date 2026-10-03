#!/usr/bin/env python3
"""
Batch 4: fuzz the fully-open googlehome:// deep-link surface of Google Home.
Every path is exported with NO permission. Goal: find one that executes a privileged
smart-home action without user confirmation.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture as C

CH = "com.google.android.apps.chromecast.app"

# high-value smart-home / credential / hierarchy paths from the manifest
PATHS = [
    ("structures", "list home structures (homes)"),
    ("invite-to-structure", "join a home / structure via invite"),
    ("share-password", "password sharing to Home"),
    ("device", "device management"),
    ("safety", "safety + security routines"),
    ("controller", "device controller"),
    ("homeagent", "home agent / routines"),
    ("automations", "home automations"),
    ("settings", "home settings"),
    ("wifi", "wifi (network) setup"),
    ("camera", "camera access"),
    ("camera_event", "camera event history"),
    ("nest-aware", "nest aware integrations"),
    ("feed", "home activity feed"),
    ("history", "home event history"),
]

if __name__ == "__main__":
    only = sys.argv[1:] or None
    for host, why in PATHS:
        if only and host not in only:
            continue
        label = f"ghdl_{host}"
        cmd = {"type": "start", "action": "android.intent.action.VIEW",
               "data": f"googlehome://{host}/", "pkg": CH, "label": host}
        C.capture(label, cmd, [CH], settle=3)
        log = open(os.path.join(C.EVID, f"{label}.full.txt")).read()
        started = [l for l in log.splitlines() if "ActivityTaskManager: START" in l
                   and "com.vrp.probe" in l]
        bal = [l for l in log.splitlines() if "Background activity launch blocked" in l]
        crash = [l for l in log.splitlines() if "FATAL EXCEPTION" in l or "AndroidRuntime" in l and "chromecast" in l]
        target = ""
        for l in started:
            seg = l.split("cmp=", 1)[-1].split("}")[0]
            target = seg
        print(f"{host:22} {'BLOCKED' if bal else 'LAUNCHED':8} -> {target[:110]}   ({why})")