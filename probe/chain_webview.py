#!/usr/bin/env python3
"""
CHAIN HUNT — web entry -> privileged WebView -> proven script execution.

Rule being applied: reaching a component is not a finding. Only a proven sink is. The sink here
is *attacker JS executing inside a WebView that carries a trusted Google origin / session*.

Method (dynamic, gives proof directly):
  for every sensitive autoVerify claim (BROWSABLE, no permission):
      fire  https://<host><attacker-controlled-path-or-query>
      and watch logcat for the target app building a WebView on OUR string.

A hit means: entry (web link, no install) -> chain (app's WebView on a trusted origin) ->
sink candidate (JS execution => cookie/token theft). Each hit is then escalated by hand to prove
actual execution, using chromium console output as the evidence.
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import capture as C  # noqa

CLAIMS = os.path.join(BASE, "manifests", "web_claims.json")

# chromium prints WebView console messages to logcat under these tags
WEBVIEW = re.compile(
    r"(chromium|WebView|cr_Chromium|WebViewFactory|loadUrl|shouldOverrideUrlLoading|"
    r"console|Console|WebContents|AwContents|sandboxed|net::|SafeBrowsing)",
    re.I)
# the string we plant, so we can see OUR url land in the WebView
MARK = "VRPMARKER"


def load_claims():
    if not os.path.exists(CLAIMS):
        print("run web_claims.py first")
        return []
    raw = json.load(open(CLAIMS))
    out = []
    for host, comps in raw.items():
        if not re.search(r"accounts\.google|myaccount|payments\.google|wallet|play\.google|"
                         r"drive\.google|docs\.google|photos\.google|mail\.google|"
                         r"oauth|login|signin|auth|passwords\.google", host, re.I):
            continue
        for c in comps:
            for p in (c["paths"] or [])[:3]:
                if p.startswith("@"):        # resource refs, unusable
                    continue
                out.append((host, p, c))
    return out


def fire(host, path, comp):
    url = f"https://{host}{path}?{MARK}=1&q=%3Cscript%3Ealert(1)%3C/script%3E"
    C.capture(f"wv_{comp['pkg'].split('.')[-1]}_{host.split('.')[0]}"
              f"_{abs(hash(path))%99999}",
              {"type": "start", "action": "android.intent.action.VIEW", "data": url,
               "label": "wv"},
              [comp["pkg"]], settle=4, fg=True)
    tag = f"wv_{comp['pkg'].split('.')[-1]}_{host.split('.')[0]}_{abs(hash(path))%99999}"
    return open(os.path.join(C.EVID, f"{tag}.full.txt")).read()


def analyse(log):
    lines = log.splitlines()
    launched = [l for l in lines if "ActivityTaskManager: START" in l]
    bal = [l for l in lines if "Background activity launch blocked" in l]
    crash = [l for l in lines if "FATAL EXCEPTION" in l]
    wv, seen = [], set()
    for l in lines:
        if WEBVIEW.search(l) and MARK in l:
            if l not in seen:
                seen.add(l)
                wv.append(l)
    wv_any = []
    for l in lines:
        if WEBVIEW.search(l) and l not in seen:
            seen.add(l)
            wv_any.append(l)
    return launched, bal, crash, wv, wv_any


if __name__ == "__main__":
    claims = load_claims()
    print(f"sensitive claim targets: {len(claims)}")
    hits = []
    seen_pairs = set()
    for host, path, comp in claims:
        key = (host, path)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        log = fire(host, path, comp)
        launched, bal, crash, wv, wv_any = analyse(log)
        tgt = ""
        for l in launched:
            m = re.search(r"cmp=(\S+?)\}", l)
            if m:
                tgt = m.group(1)
        status = "BAL" if bal else "LAUNCH"
        flag = ""
        if wv:
            flag = "  *** MARKER-IN-WEBVIEW ***"
        if crash:
            flag += "  CRASH"
        print(f"{status:7} {host}{path[:46]:46} -> {tgt[-60:]:60}{flag}")
        if wv or crash:
            hits.append((host, path, comp, tgt, wv, crash))
    print(f"\n\n===== HITS: {len(hits)}")
    for host, path, comp, tgt, wv, crash in hits:
        print(f"\n### https://{host}{path}")
        print(f"    component: {tgt}")
        for l in wv[:4]:
            print("    MARK " + l[:250])
        for l in crash[:1]:
            print("    CRASH " + l[:250])