#!/usr/bin/env python3
"""
Evidence capture: clear logcat, fire ONE probe command, then dump the FULL system log
filtered to the target app's process + crash/security-relevant tags. This is what proves
whether attacker-controlled data actually reached the target's logic.
"""
import json
import os
import re
import subprocess
import sys
import time

PKG = "com.vrp.probe"
HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(os.path.dirname(HERE), "evidence")


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=90)


def pid_of(pkg):
    r = sh(f"adb shell pidof {pkg}").stdout.strip()
    return r.split()[0] if r else None


def start_target(pkg):
    """Force the target app to be running so we can capture its process logs."""
    sh(f"adb shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1")
    time.sleep(2)
    return pid_of(pkg)


def capture(label, cmd, target_pkgs, settle=4, fg=True):
    sh("adb logcat -c")
    sh("adb shell am force-stop " + target_pkgs[0])
    time.sleep(1)
    for p in target_pkgs:
        sh(f"adb shell monkey -p {p} -c android.intent.category.LAUNCHER 1")
    time.sleep(2)
    pids = {p: pid_of(p) for p in target_pkgs}

    js = cmd if isinstance(cmd, str) else json.dumps(cmd)
    with open("/tmp/vrp_cmd.json", "w") as fh:
        fh.write(js)
    sh("mkdir -p /sdcard/Android/data/com.vrp.probe/files")
    subprocess.run(["adb", "push", "/tmp/vrp_cmd.json",
                    "/sdcard/Android/data/com.vrp.probe/files/cmd.json"],
                   capture_output=True, text=True)
    if fg:
        # BAL: caller must hold a visible activity; the activity runs the command itself
        sh("adb shell am start -n com.vrp.probe/.UiActivity >/dev/null 2>&1")
        time.sleep(2.0)
    else:
        sh(f"adb shell am broadcast -a com.vrp.probe.EXEC -p {PKG} --include-stopped-packages")
    time.sleep(settle)

    log = sh("adb logcat -d -v time").stdout
    os.makedirs(EVID, exist_ok=True)
    with open(os.path.join(EVID, f"{label}.full.txt"), "w") as fh:
        fh.write(f"### CMD: {js}\n### TARGETS: {target_pkgs}\n### PIDS_BEFORE: {pids}\n\n{log}")

    # Filter: lines whose pid matches a target process
    keep = []
    pidset = {v for v in pids.values() if v}
    for ln in log.splitlines():
        m = re.search(r"^\S+\s+\S+\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(.*)$", ln)
        if not m:
            continue
        pid = m.group(1)
        body = m.group(4)
        interesting = (pid in pidset
                       or re.search(r"(ActivityTaskManager|ActivityManager|PackageManager|"
                                    r"AndroidRuntime|libc|WindowManager|ContentProvider|"
                                    r"chromecast|wellbeing|fitness|safetycore|contactkeys|"
                                    r"inputmethod|Matter|Geofence|geofence)", body))
        if interesting:
            keep.append(ln)
    print(f"\n########## {label}")
    print(f"# cmd: {js}")
    for ln in keep[-120:]:
        print("  ", ln[:330])
    return log


if __name__ == "__main__":
    label = sys.argv[1]
    targets = sys.argv[2].split(",")
    cmd = json.loads(sys.argv[3])
    capture(label, cmd, targets)