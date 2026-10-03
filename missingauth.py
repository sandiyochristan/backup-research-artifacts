#!/usr/bin/env python3
"""Find exported components whose handler has NO caller verification.

Google enforces authorization in code, not manifests. So: for each exported component,
read its onReceive/onBind/onCreate/handleIntent and look for caller verification.
None present => prime "missing authorization" candidate.
"""
import os, re, sys, json, subprocess

BASE = "/Users/sandiyochristan/Downloads/ExtractedApks"
SMALI = os.path.join(BASE, "smali")
sys.path.insert(0, BASE)
import mparse

VERIFY = [
    "getCallingUid", "getCallingPid", "getCallingPackage", "getCallingActivity",
    "checkCallingPermission", "enforceCallingPermission", "checkCallingOrSelfPermission",
    "getPackagesForUid", "checkSignatures", "getPackageInfo",
    "Binder;->getCallingUid", "Binder;->getCallingPid",
    "checkPermission", "enforcePermission", "getPermission",
    "checkUid", "verifyCaller", "UidChecker",
]
HANDLER = ("onReceive", "onBind", "onCreate", "onStartCommand", "handleIntent",
           "onHandleIntent", "onTransact", "dispatchTransaction")

def short(cls):
    return cls.lstrip("L").rstrip(";").replace("/", ".")

def component_class(cls):
    return cls.replace(".", "/") + ".smali"

def read_body(path, methods):
    try:
        t = open(path, errors="replace").read()
    except Exception:
        return None
    for m in methods:
        # find ".method ... m(" and take until .end method
        for mm in re.finditer(r"\.method[^\n]*\b" + re.escape(m) + r"\(", t):
            end = t.find(".end method", mm.start())
            if end > 0:
                seg = t[mm.start():end]
                yield seg

def analyze(smali_root, pkg):
    findings = []
    for dirpath, _, files in os.walk(smali_root):
        for fn in files:
            if not fn.endswith(".smali"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                t = open(path, errors="replace").read()
            except Exception:
                continue
            if ".source" not in t:
                pass
            # does it declare an exported component? Look for the class name in manifest first
            cls = os.path.relpath(path, smali_root)[:-6].replace("/", ".")
            has_verify = any(v in t for v in VERIFY)
            has_handler = any(h in t for h in HANDLER)
            if has_handler and not has_verify:
                # confirm it's actually a component class (extends Activity/Service/Provider/Binder stub)
                if re.search(r"\.super\s+L?(com/google/android/(app|net|os)/)?"
                             r"(Activity|Service|ContentProvider|IntentService|"
                             r"ChimeraService|Service;|.*Chimera.*|.*Receiver.*)", t):
                    findings.append(cls)
    return findings

def exported_set(pkg):
    try:
        apk = os.path.join(BASE, "apks", pkg + "-base.apk")
        if not os.path.exists(apk):
            return set()
        d = mparse.dump(apk)
        return {c["name"] for c in d.get("components", []) if c["exported"]
                and not (c["permission"] or c["readPermission"] or c["writePermission"])}
    except Exception:
        return set()

if __name__ == "__main__":
    targets = {
        "chromecast": "com.google.android.apps.chromecast.app",
        "photos": "com.google.android.apps.photos",
        "wellbeing": "com.google.android.apps.wellbeing",
        "gboard": "com.google.android.inputmethod.latin",
        "contactkeys": "com.google.android.contactkeys",
        "gms": "com.google.android.gms",
    }
    which = sys.argv[1:] or list(targets)
    for key in which:
        if key not in targets:
            continue
        root = os.path.join(SMALI, key)
        if not os.path.isdir(root):
            continue
        pkg = targets[key]
        exp = exported_set(pkg)
        print(f"\n{'='*90}\n### {pkg}  (exported+unguarded in manifest: {len(exp)})")
        cands = analyze(root, pkg)
        # keep only those that appear in the exported set
        hits = [c for c in cands if c in exp]
        print(f"    classes with handler but NO caller-verify token: {len(cands)}")
        print(f"    ...of which EXPORTED+unguarded: {len(hits)}")
        for h in sorted(hits)[:60]:
            print("      * " + h)
