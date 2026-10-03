#!/usr/bin/env python3
"""PendingIntent abuse sweep (BlackHat EU'21 'Re-route Your Intent' class).

Detect in exported components:
  A) FLAG_MUTABLE PendingIntent wrapping an IMPLICIT intent  -> redirect/collision
  B) PendingIntent created then dispatched to a target we control (re-route)
  C) exported component that returns/stores a PendingIntent built from caller data
"""
import os, re, sys, json

SMALI = "smali"
FLAG_MUTABLE = re.compile(r'->mShowingMutable|FLAG_MUTABLE|FLAG_IMMUTABLE|MUTABLE')
# PendingIntent.getBroadcast/getActivity/getService with mutable flag
GET_PI = re.compile(r'Landroid/app/PendingIntent;->get(Broadcast|Activity|Service)\(')

def consts(seg):
    return re.findall(r'const-string(?:/jumbo)? [^,]+, "([^"]*)"', seg)

def audit(path):
    try: t = open(path, errors="replace").read()
    except Exception: return []
    out = []
    if "Landroid/app/PendingIntent;" not in t: return out
    cls = ""
    for ln in t.splitlines()[:40]:
        if ln.startswith(".class"):
            cls = ln.split()[-1].rstrip(";")
            break
    # split into methods
    methods = re.split(r'\n    \.method ', t)
    for m in methods[1:]:
        name = m.split("\n",1)[0][:80]
        mutable = "->mShowingMutable" in m or "FLAG_MUTABLE" in m
        immut   = "->mShowingImmutable" in m or "FLAG_IMMUTABLE" in m
        if not mutable and not immut: continue
        # does it build an Intent right before?
        has_intent_new = "Landroid/content/Intent;-><init>()V" in m
        explicit = re.search(r'Landroid/content/Intent;->set(Component|Class|Package)', m)
        getpi = GET_PI.search(m)
        if getpi:
            out.append(dict(cls=cls, method=name, mutable=mutable,
                            explicit=bool(explicit), kind=getpi.group(1),
                            strings=consts(m)[:6]))
    return out

def main():
    rows = []
    apps = sorted(os.listdir(SMALI)) if os.path.isdir(SMALI) else []
    for app in apps:
        root = os.path.join(SMALI, app)
        if not os.path.isdir(root): continue
        n = 0
        for dp,_,fs in os.walk(root):
            for fn in fs:
                if not fn.endswith(".smali"): continue
                r = audit(os.path.join(dp,fn))
                if r:
                    rows += r; n += len(r)
        if n: print(f"  {app}: {n} PendingIntent sites", flush=True)
    json.dump(rows, open("manifests/pending_intents.json","w"), indent=1)
    print(f"\nTOTAL PendingIntent sites: {len(rows)}")
    mut = [r for r in rows if r["mutable"] and not r["explicit"]]
    print(f"MUTABLE + IMPLICIT (redirect-prone): {len(mut)}")
    for r in mut[:40]:
        print(f"  {r['cls']}\n      {r['method'][:70]} kind={r['kind']} strings={r['strings'][:3]}")

if __name__=="__main__":
    main()
