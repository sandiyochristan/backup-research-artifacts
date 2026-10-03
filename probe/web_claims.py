#!/usr/bin/env python3
"""
Enumerate every web origin that a Google/Android app has CLAIMED via
<intent-filter android:autoVerify="true">.

Why this matters: autoVerify + BROWSABLE means a plain <a href> on any web page — or a QR code,
or a push notification — launches the claimed APP instead of a browser, and the app typically
loads that URL in a WebView **carrying the user's live session cookies for that Google origin**.

If any claimed path lets attacker input reach the WebView URL, an attacker gets script execution on
accounts.google.com / payments.google.com / etc. = cookie + token theft = account takeover.
That is a full chain (entry -> confused deputy on trusted origin -> sink), web-reachable, no app
install required.
"""
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
import mparse  # noqa

APKS = os.path.join(BASE, "apks")

SENSITIVE = re.compile(
    r"accounts\.google|mail\.google|myaccount|payments\.google|wallet|play\.google|"
    r"drive\.google|docs\.google|photos\.google|calendar\.google|contacts\.google|"
    r"passwords\.google|onepassword|groups\.google|admin\.google|"
    r"oauth|login|signin|auth|token|sso|apis\.google", re.I)


def scan():
    claims = defaultdict(list)
    for f in sorted(os.listdir(APKS)):
        if not f.endswith("-base.apk"):
            continue
        pkg = f[:-len("-base.apk")]
        try:
            d = mparse.dump(os.path.join(APKS, f))
        except Exception:
            continue
        if "error" in d or not d.get("components"):
            continue
        for c in d["components"]:
            if not c["exported"]:
                continue
            if "android.intent.category.BROWSABLE" not in (c["categories"] or []):
                continue
            hosts = set(c["hosts"] or [])
            schemes = set(c["schemes"] or [])
            if not hosts:
                continue
            if "android" in schemes and "http" in schemes:
                hosts.add("*ANDROID-SCHEME*")
            for h in hosts:
                if h.startswith("*"):
                    continue
                claims[h].append({
                    "pkg": pkg,
                    "cls": c["name"],
                    "type": c["type"],
                    "paths": c["paths"],
                    "schemes": sorted(schemes),
                    "actions": c["actions"],
                    "permission": c["permission"],
                    "autoVerify": bool(c.get("autoVerify")),
                })
    return claims


if __name__ == "__main__":
    claims = scan()
    json.dump({k: v for k, v in claims.items()},
              open(os.path.join(BASE, "manifests", "web_claims.json"), "w"), indent=1)
    print(f"total distinct claimed hosts: {len(claims)}\n")
    print("=" * 100)
    print("HIGH-VALUE CLAIMED ORIGINS (account / payment / auth class)\n")
    sens = {h: v for h, v in claims.items() if SENSITIVE.search(h)}
    for host in sorted(sens, key=lambda x: -len(sens[x])):
        print(f"\n### https://{host}   ({len(sens[host])} component(s))")
        for c in sens[host][:10]:
            print(f"    [{c['type']:15}] {c['cls']}")
            print(f"        paths   : {c['paths'][:8] if c['paths'] else '(any)'}")
            print(f"        perm    : {c['permission'] or 'NONE'}")
            if c["autoVerify"]:
                print(f"        *** autoVerify=true ***")
    print("\n" + "=" * 100)
    print(f"\nALL claimed hosts ({len(claims)}):")
    for host in sorted(claims):
        mark = "  <== SENSITIVE" if SENSITIVE.search(host) else ""
        print(f"   {host}  ({len(claims[host])}){mark}")