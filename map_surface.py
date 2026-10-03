#!/usr/bin/env python3
"""PHASE 1: pull APKs + dump exported component surface via aapt2."""
import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
AAPT2 = os.path.expanduser("~/Library/Android/sdk/build-tools/35.0.1/aapt2")
APKS = os.path.join(BASE, "apks")
OUT = os.path.join(BASE, "manifests")
os.makedirs(APKS, exist_ok=True)
os.makedirs(OUT, exist_ok=True)


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                          text=True, **kw)


def package_paths(pkg):
    r = sh(["adb", "shell", "pm", "path", pkg])
    return [l.replace("package:", "").strip() for l in r.stdout.splitlines() if l.strip()]


def pull(pkg):
    got = []
    for path in package_paths(pkg):
        fn = path.split("/")[-1]
        if fn == "base.apk":
            fn = f"{pkg}-base.apk"
        else:
            fn = f"{pkg}-{fn}"
        dest = os.path.join(APKS, fn)
        if not os.path.exists(dest) or os.path.getsize(dest) < 1000:
            r = sh(["adb", "pull", path, dest])
            if r.returncode != 0:
                continue
        got.append(dest)
    return got


ATTR_RE = re.compile(r'^[EI]:([^=]+)=(.*)$')


def parse_manifest(apk):
    r = sh([AAPT2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk])
    if r.returncode != 0:
        return None
    lines = r.stdout.splitlines()
    comps = []
    perms = []
    cur = None
    depth = 0
    in_manifest = False
    i = 0
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        if s.startswith("E: "):
            tag = s[3:].split()[0]
            attrs = {}
            for m in ATTR_RE.finditer(ln):
                attrs[m.group(1)] = m.group(2)
            if tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                cur = {"type": tag, "name": attrs.get("name", "?"), "attrs": attrs, "perm": []}
                comps.append(cur)
            elif tag in ("uses-permission", "uses-permission-sdk-23",
                         "uses-permission-sdk-m"):
                perms.append(attrs.get("name", ""))
            elif tag == "manifest":
                in_manifest = True
        elif s.startswith("A:") and cur is not None and cur is not None:
            m = ATTR_RE.match("E:" + s[2:])
            if m:
                cur["attrs"][m.group(1)] = m.group(2)
        i += 1
    return comps, perms, lines


def main(pkgs):
    report = []
    for pkg in pkgs:
        apks = pull(pkg)
        if not apks:
            report.append((pkg, "PULL FAILED", [], []))
            continue
        allc, allp = [], []
        for a in apks:
            p = parse_manifest(a)
            if p:
                allc += p[0]
                allp += p[1]
            # save raw manifest
            r = sh([AAPT2, "dump", "xmltree", "--file", "AndroidManifest.xml", a])
            mf = os.path.join(OUT, f"{pkg}__{os.path.basename(a)}.manifest.txt")
            with open(mf, "w") as fh:
                fh.write(r.stdout)
        report.append((pkg, f"{len(apks)} apks", allc, allp))
    return report


def exported(attrs):
    ex = attrs.get("exported")
    if ex == "true":
        return True
    if ex == "false":
        return False
    # infer from intent-filters (pre-12 default true)
    return "intent-filter" in attrs


if __name__ == "__main__":
    pkgs = [l.strip() for l in open(sys.argv[1]) if l.strip()] if len(sys.argv) > 1 else []
    rep = main(pkgs)
    summary = []
    for pkg, status, comps, perms in rep:
        exp = [c for c in comps if exported(c["attrs"])]
        summary.append(f"\n{'='*90}\n### {pkg}  [{status}]  exported={len(exp)}/{len(comps)}")
        summary.append("  -- Sensitive perms: " + ", ".join(
            sorted({p.split('.')[-1] for p in perms if any(
                k in p for k in ('READ_', 'WRITE_', 'ACCESS_', 'MANAGE_', 'BIND_',
                                 'CALL_', 'RECORD_', 'CAMERA', 'LOCATION', 'CONTACTS',
                                 'SMS', 'PHONE', 'ACCOUNT', 'AUTHENTICATE', 'USE_FINGERPRINT',
                                 'BODY_SENSORS', 'ACTIVITY_RECOGNITION', 'READ_PHONE'))}))[:600])
        for c in exp:
            p = c["attrs"].get("permission", "-")
            r = c["attrs"].get("readPermission", "-")
            w = c["attrs"].get("writePermission", "-")
            gp = c["attrs"].get("grantUriPermissions", "-")
            summary.append(
                f"  [{c['type']:14}] {c['name']}")
            summary.append(
                f"      perm={p} read={r} write={w} grantUri={gp} "
                f"directBoot={c['attrs'].get('directBootAware','-')}")
    txt = "\n".join(summary)
    open(os.path.join(BASE, "manifests", "EXPORTED_SURFACE.txt"), "w").write(txt)
    print(txt)