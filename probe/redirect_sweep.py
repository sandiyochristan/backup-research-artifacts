#!/usr/bin/env python3
"""
Static sweep for INTENT REDIRECTION (CWE-940) — the class that historically paid for the
Gmail CSE / GMS redirect bugs. Pattern: a component reachable from outside takes an
Intent/ComponentName out of its own extras and starts it, so a privileged app launches an
attacker-chosen intent under its own identity and permissions.

Two passes:
  1. grep decompiled sources for intent-from-extras followed by startActivity/startService
  2. cross-reference the class against exported components in the triage data
"""
import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "src")
SMALI = os.path.join(BASE, "smali")

# strings that carry an Intent through an extra
INTENT_EXTRA = re.compile(
    r'("(android\.intent\.extra\.INTENT|extra_redirect_intent|redirect_intent|'
    r'intent|target_intent|forward_intent|next_intent|navigate_intent|'
    r'android\.intent\.extra\.SHORT_CUT|component|component_name|target|'
    r'com\.google\.android\.gms\.auth\.api\.credentials\.[a-z_]+)")', re.I)

LAUNCH = re.compile(r'(startActivity|startService|bindService|startActivityForResult|'
                    r'sendBroadcast|startForegroundService)')

DEFANGED = re.compile(r'(Parcelable|getParcelableExtra|getParcelable|Intent;->getParcelableExtra)')


def sweep_smali(root, limit_hits=60):
    hits = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".smali"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                t = open(p, errors="replace").read()
            except Exception:
                continue
            if "getParcelableExtra" not in t:
                continue
            # find classes that BOTH read an intent-typed extra AND launch something
            if not LAUNCH.search(t):
                continue
            extras = set(m.group(1) for m in INTENT_EXTRA.finditer(t))
            if not extras:
                continue
            launches = set(m.group(1) for m in LAUNCH.finditer(t))
            cls = ""
            for line in t.splitlines()[:40]:
                if line.startswith(".class"):
                    cls = line.split()[-1].rstrip(";")
                    break
            hits.append((p, cls, sorted(extras), sorted(launches)))
    hits.sort(key=lambda x: -len(x[2]))
    return hits


def sweep_java(root):
    hits = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                t = open(p, errors="replace").read()
            except Exception:
                continue
            if "getParcelableExtra" not in t:
                continue
            if not LAUNCH.search(t):
                continue
            extras = set(m.group(1) for m in INTENT_EXTRA.finditer(t))
            if not extras:
                continue
            hits.append((p, sorted(extras), sorted(set(m.group(1) for m in LAUNCH.finditer(t)))))
    return hits


if __name__ == "__main__":
    total = 0
    for root in (SMALI, SRC):
        if not os.path.isdir(root):
            continue
        label = os.path.basename(root)
        for sub in sorted(os.listdir(root)):
            full = os.path.join(root, sub)
            if not os.path.isdir(full):
                continue
            h = sweep_smali(full) if label == "smali" else sweep_java(full)
            if not h:
                continue
            print(f"\n{'='*100}\n## {label}/{sub}  -> {len(h)} candidate(s)")
            for item in h[:25]:
                if label == "smali":
                    p, cls, extras, launches = item
                else:
                    p, extras, launches = item
                    cls = ""
                print(f"   {os.path.basename(p)}")
                print(f"      class   : {cls}")
                print(f"      extras  : {[e.strip(chr(34)) for e in extras][:6]}")
                print(f"      launches: {launches}")
                total += 1
    print(f"\nTOTAL candidates: {total}")
    print("\nNext step: each candidate must be cross-checked against whether the component is")
    print("EXPORTED, then validated live (does the target actually start under the privileged app?).")