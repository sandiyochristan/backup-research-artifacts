#!/usr/bin/env python3
"""
Universal probe driver: push a JSON command into the zero-perm probe app, capture logcat.
Usage:
  python3 probe.py '{"type":"query","uri":"content://..."}'
  python3 probe.py --file tests/contactkeys.json
  python3 probe.py --suite <name>
"""
import json
import os
import subprocess
import sys
import time

PKG = "com.vrp.probe"
HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(os.path.dirname(HERE), "evidence")


def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def push_cmd(js, no_broadcast=False):
    """Write the command JSON to the probe's external files dir (reachable from adb shell),
    then poke the receiver. No shell-quoting or size limits."""
    js = js if isinstance(js, str) else json.dumps(js)
    remote = "/sdcard/Android/data/com.vrp.probe/files/cmd.json"
    sh("mkdir -p /sdcard/Android/data/com.vrp.probe/files")
    tmp = "/tmp/vrp_cmd.json"
    with open(tmp, "w") as fh:
        fh.write(js)
    subprocess.run(["adb", "push", tmp, remote], capture_output=True, text=True)
    if no_broadcast:
        return ""
    r = sh(f"adb shell am broadcast -a com.vrp.probe.EXEC -p {PKG} --include-stopped-packages")
    return r.stdout.strip()


def foreground():
    """Bring the probe to the foreground so BAL (background activity launch) permits
    startActivity(). The activity itself executes the command file, so no broadcast is sent."""
    sh("adb logcat -c")
    sh("adb shell am start -n com.vrp.probe/.UiActivity >/dev/null 2>&1")
    time.sleep(2.0)


def quarantine():
    """Disable pre-existing PoC apps on the device that would otherwise intercept our intents
    and corrupt results (com.vrp.zeroperm registers an OAuth interception activity)."""
    for p in ("com.vrp.zeroperm", "com.poc.confused_deputy", "com.vrp.testonly",
              "com.vrp.testonly.control", "com.vrppoc"):
        sh(f"adb shell pm disable-user --user 0 {p} >/dev/null 2>&1")


def run(js, label="test", wait=3, fg=True):
    sh("adb logcat -c")
    js = js if isinstance(js, str) else json.dumps(js)
    push_cmd(js, no_broadcast=True)
    if fg:
        foreground()
    else:
        sh(f"adb shell am broadcast -a com.vrp.probe.EXEC -p {PKG} --include-stopped-packages")
    time.sleep(wait)
    out = sh(f"adb logcat -d -v time -s VRPPROBE").stdout
    os.makedirs(EVID, exist_ok=True)
    fn = os.path.join(EVID, f"{label}.txt")
    with open(fn, "a") as fh:
        fh.write(f"\n{'='*100}\nCMD: {js}\n{'-'*100}\n{out}\n")
    return out


SUITES = {}


def suite(name):
    def deco(fn):
        SUITES[name] = fn
        return fn
    return deco


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    a = sys.argv[1]
    if a == "--file":
        js = open(sys.argv[2]).read().strip()
        print(run(js, os.path.basename(sys.argv[2]).replace(".json", ""), wait=4))
    elif a == "--suite":
        fn = SUITES.get(sys.argv[2])
        if not fn:
            print("no suite"); return
        fn()
    else:
        print(run(a, "adhoc", wait=4))


if __name__ == "__main__":
    main()