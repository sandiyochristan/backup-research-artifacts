#!/usr/bin/env python3
"""
Escalation test: DeeplinkActivity is BROWSABLE + exported, so googlehome:// is reachable from a
web page (NO app install, NO user interaction beyond a link click). Find whether any path
performs a privileged action rather than just rendering a screen.
"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CH = "com.google.android.apps.chromecast.app"
EVID = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence")

# paths that could plausibly change state rather than navigate
PATHS = [
    ("invite_to_structure", "googlehome://invite-to-structure/?invite_token=ATTACKER"),
    ("ha_linking",          "googlehome://ha_linking/?code=ATTACKER"),
    ("permissions",         "googlehome://permissions/"),
    ("enrollment",          "googlehome://enrollment/"),
    ("play_iap",            "googlehome://play-iap/"),
    ("setup_interconnect",  "googlehome://setup/interconnect/"),
    ("wifi_share_password", "googlehome://wifi/share-password/"),
    ("familiar_face",       "googlehome://settings/camera/familiar-face/privacy/"),
    ("creategroup",         "googlehome://creategroup/"),
    ("3p_setup",            "googlehome://3p-setup/"),
    ("setup",               "googlehome://setup/"),
    ("controller",          "googlehome://controller/"),
]

# signals that an ACTION happened, not just a screen render
ACTION = re.compile(
    r"(startActivity|startService|bindService|AccountManager|addAccount|"
    r"grantRuntimePermission|PackageInstaller|ACTION_COMMISSION|commission|COMMISSION|"
    r"addDevice|AddDevice|unlink|Unlink|linkAccount|LinkAccount|"
    r"FATAL EXCEPTION|BinderProxy|Matter|Commissioning|createGroup|CreateGroup|"
    r"purchase|Purchase|billing|Billing)", re.I)


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=90)


def fire(url, label):
    sh("adb logcat -c")
    sh(f"adb shell am force-stop {CH}")
    time.sleep(1)
    sh(f"adb shell monkey -p {CH} -c android.intent.category.LAUNCHER 1")
    time.sleep(2.5)
    sh("adb logcat -c")
    cmd = {"type": "start", "action": "android.intent.action.VIEW",
           "data": url, "pkg": CH, "label": label}
    with open("/tmp/vrp_cmd.json", "w") as fh:
        json.dump(cmd, fh)
    subprocess.run(["adb", "push", "/tmp/vrp_cmd.json",
                    "/sdcard/Android/data/com.vrp.probe/files/cmd.json"],
                   capture_output=True)
    sh("adb shell am start -n com.vrp.probe/.UiActivity >/dev/null 2>&1")
    time.sleep(4.5)
    log = sh("adb logcat -d -v time").stdout
    with open(os.path.join(EVID, f"ghpath_{label}.full.txt"), "w") as fh:
        fh.write(f"CMD: {json.dumps(cmd)}\n\n{log}")
    return log


def analyse(log, url):
    launched = [l for l in log.splitlines() if "ActivityTaskManager: START" in l]
    bal = [l for l in log.splitlines() if "Background activity launch blocked" in l]
    crashes = [l for l in log.splitlines() if "FATAL EXCEPTION" in l]
    acts = [l for l in log.splitlines() if ACTION.search(l)
            and "WifiService" not in l and "usb" not in l.lower()
            and "Bluetooth" not in l]
    return launched, bal, crashes, acts


if __name__ == "__main__":
    print(f"{'path':22} {'status':10} target")
    for label, url in PATHS:
        log = fire(url, label)
        launched, bal, crashes, acts = analyse(log, url)
        tgt = ""
        for l in launched:
            m = re.search(r"cmp=(\S+?)\}", l)
            if m:
                tgt = m.group(1)
        status = "BAL_BLOCKED" if bal else ("CRASH" if crashes else "LAUNCHED")
        print(f"{label:22} {status:11} {tgt[:95]}")
        if acts:
            seen = set()
            for a in acts[:12]:
                k = a[:150]
                if k not in seen:
                    seen.add(k)
                    print(f"      ~ {k}")