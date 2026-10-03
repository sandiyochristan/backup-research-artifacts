import os,re,sys,subprocess
BASE="/Users/sandiyochristan/Downloads/ExtractedApks"; AAPT=os.path.expanduser("~/Library/Android/sdk/build-tools/35.0.1/aapt2")
INTEREST=[
 (r'debuggable\(0x0101000f\)=true','DEBUGGABLE_TRUE'),
 (r'allowBackup\(0x01010280\)=false','allowBackup=false'),
 (r'usesCleartextTraffic\(0x010104ec\)=true','CLEARTEXT_ALLOWED'),
 (r'networkSecurityConfig','has-NSC'),
 (r'testOnly\(0x01010272\)=true','testOnly'),
 (r'persistent\(0x01010210\)=true','persistent'),
]
rows=[]
for f in sorted(os.listdir(BASE+"/apks")):
    if not f.endswith("-base.apk"): continue
    pkg=f[:-9]
    r=subprocess.run([AAPT,"dump","xmltree","--file","AndroidManifest.xml",BASE+"/apks/"+f],
                     capture_output=True,text=True)
    if r.returncode!=0: continue
    t=r.stdout
    hits=[n for p,n in INTEREST if re.search(p,t)]
    # is it a system/privileged app?
    sysd = os.path.exists(BASE+"/smali/gms") # placeholder
    if "DEBUGGABLE_TRUE" in hits or "CLEARTEXT_ALLOWED" in hits or "testOnly" in hits or "persistent" in hits:
        rows.append((pkg,hits))
print(f"scanned {len(os.listdir(BASE+'/apks'))} apks\n")
print("=== configuration findings ===")
for pkg,h in rows:
    print(f"  {pkg}: {h}")
if not rows: print("  none")
