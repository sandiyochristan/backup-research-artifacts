#!/usr/bin/env python3
"""Batch 2: probe ContentResolver.call() on the three providers reached without permission denial."""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from probe import run

WDB = "content://com.google.android.inputmethod.latin.wdb"
WB_API = "content://com.google.android.apps.wellbeing.api"
WB_AUTODND = "content://com.google.android.apps.wellbeing.autodnd.ui.provider"

TESTS = []
for uri, tag in ((WDB, "wdb"), (WB_API, "wbapi"), (WB_AUTODND, "wbautodnd")):
    for m in ("", "null", "ping", "getWebView", "list", "open", "get", "run", "enable",
              "debug", "getWebViewList", "attach", "webview", "load", "eval", "setUrl"):
        TESTS.append((f"call_{tag}_{m or 'empty'}",
                      {"type": "call", "uri": uri, "method": m, "arg": "", "label": f"{tag}:{m}"}))
    TESTS.append((f"gettype_{tag}", {"type": "getType", "uri": uri + "/", "label": f"gettype:{tag}"}))

if __name__ == "__main__":
    for name, cmd in TESTS:
        out = run(json.dumps(cmd), name, wait=2)
        lines = [l.split("VRPPROBE: ", 1)[-1] for l in out.splitlines() if "VRPPROBE" in l]
        body = [l for l in lines if ("CALL_" in l or "GETTYPE" in l or "SecurityException" in l
                                     or "CMD type" in l)]
        print(f"--- {name}")
        for b in body:
            print("   ", b[:400])