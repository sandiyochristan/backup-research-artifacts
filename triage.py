#!/usr/bin/env python3
"""
Critical-class triage across every pulled com.google.* / com.android.* APK.

Ranks by ACTUAL Google-VRP leverage, not by "interesting looking":
  +NO_INSTALL   reachable without installing an app (BROWSABLE / autoVerify web links,
                or a network listener) -> escapes the "user must install app" penalty
  +TIER1        GMS / Android platform / Google account-class targets
  +SENSITIVE    sink touches auth tokens, accounts, contacts, messages, credentials
  +UNGUARDED    no android:permission and no read/writePermission
"""
import json
import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import mparse  # noqa: E402

APKS = os.path.join(BASE, "apks")

TIER1 = re.compile(r"^(com\.google\.android\.gms|com\.android\.(vending|server|providers|"
                   r"systemui|phone|shell|settings|keychain|permissioncontroller|"
                   r"package|compatibility|internal|externalstorage|certinstaller|"
                   r"webview|netd|deviceprovision|printspooler|inputflinger|"
                   r"adbd|conscrypt|mtc|net|ims|cts|privapp|statsd|userspace|"
                   r"hardware|services|system|bluetooth|nfc|media|audio|"
                   r"se|security|provisioning)|com\.google\.android\.googlequicksearchbox|"
                   r"com\.google\.android\.gms\.supervision|com\.android\.vending)$")

# schemes/hosts that make a component reachable from a web page (NO INSTALL)
OAUTH_HOSTS = re.compile(r"oauth|auth|callback|redirect|signin|login|account", re.I)
SENSITIVE_AUTHORITY = re.compile(
    r"contact|calllog|sms|telephony|calendar|account|token|cookie|credential|"
    r"password|auth|session|keychain|keystore|media|photo|file|download|"
    r"location|gmscore|gservices|deviceid|advertising|clipboard", re.I)


def score(pkg, comp):
    s = 0.0
    why = []
    browsable = "android.intent.category.BROWSABLE" in (comp["categories"] or [])
    exported = comp["exported"]
    unguarded = not (comp["permission"] or comp["readPermission"] or comp["writePermission"])
    auto_verify = bool(comp.get("autoVerify"))

    if exported and browsable:
        s += 40; why.append("BROWSABLE(remote,no-install)")
    if exported and auto_verify:
        s += 25; why.append("autoVerify(remote,no-install)")
    if exported and unguarded:
        s += 15; why.append("exported+NO-PERMISSION")
    if TIER1.match(pkg):
        s += 25; why.append("TIER1")
    if comp["type"] == "provider" and exported and unguarded:
        s += 20; why.append("provider:data-access")
    if comp["type"] == "activity" and exported and unguarded and browsable:
        s += 15; why.append("unguarded-web-activity")

    blob = " ".join([pkg, comp["name"] or ""] + (comp["schemes"] or [])
                    + (comp["hosts"] or []) + (comp["actions"] or []))
    if OAUTH_HOSTS.search(blob):
        s += 20; why.append("AUTH-SURFACE")
    auth = comp.get("authorities") or ""
    if SENSITIVE_AUTHORITY.search(auth or ""):
        s += 20; why.append("SENSITIVE-AUTHORITY")
    if comp["type"] == "provider" and (comp.get("grantUriPermissions") == "true"):
        s += 5; why.append("grantUriPermissions")
    # sensitive actions on unguarded receivers/services
    act = " ".join(comp["actions"] or [])
    if re.search(r"oauth|account|auth|login|token|password|session", act, re.I):
        s += 15; why.append("AUTH-ACTION")
    return s, why


def main():
    rows = []
    apks = [f for f in sorted(os.listdir(APKS)) if f.endswith("-base.apk")]
    print(f"scanning {len(apks)} APKs", flush=True)
    for i, f in enumerate(apks):
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
            s, why = score(pkg, c)
            if s <= 0:
                continue
            rows.append(dict(pkg=pkg, score=s, why=why, comp=c))
        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(apks)}] hits={len(rows)}", flush=True)

    rows.sort(key=lambda r: -r["score"])
    json.dump([{**r, "comp": r["comp"]} for r in rows],
              open(os.path.join(BASE, "manifests", "triage.json"), "w"), indent=1)

    print(f"\n{'='*100}\nTOP CRITICAL-CANDIDATE COMPONENTS ({len(rows)} total)\n")
    for r in rows[:70]:
        c = r["comp"]
        print(f"[{r['score']:.0f}] {r['pkg']}")
        print(f"      {c['type']:15} {c['name']}")
        print(f"      why: {', '.join(r['why'])}")
        if c["schemes"] or c["hosts"]:
            print(f"      data: {list(zip(c['schemes'], c['hosts']))[:4]}")
        if c["actions"]:
            print(f"      act : {c['actions'][:5]}")
        if c.get("authorities"):
            print(f"      auth: {c['authorities']}")
        if c["permission"]:
            print(f"      perm: {c['permission']}")
        print()


if __name__ == "__main__":
    main()