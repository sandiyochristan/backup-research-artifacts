#!/usr/bin/env python3
"""
Photos deep-link chain test. Rule: only a proven SINK counts.

Candidates (all exported, BROWSABLE, autoVerify, NO permission, web-reachable):
  photos.google.com/album/.*        PrivateAlbumDeepLinkActivity  <- "private album by ID"
  photos.google.com/share/.*        AlbumActivity
  photos.google.com/photos/.*       AlbumActivity
  photos.google.com/link/ask_photos AskPhotosDeepLinkActivity      <- AI query over library

We are hunting for the sink, not the launch:
  SINK-A  photo content returned to OUR caller (activity result / broadcast / written file)
  SINK-B  a private object made PUBLIC or exported (integrity -> confidentiality)
  SINK-C  an album/photo resolved and rendered from the victim's session via attacker-chosen ID (IDOR)
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capture as C  # noqa

PHOTOS = "com.google.android.apps.photos"
ID = "1AbCdEfGhIjKlMnOpQrStUvWxYz"          # synthetic 28-char Google-style ID

CASES = [
    ("album_private", f"https://photos.google.com/album/{ID}"),
    ("album_private_u", f"https://photos.google.com/u/0/album/{ID}"),
    ("share_id", f"https://photos.google.com/share/{ID}"),
    ("photos_id", f"https://photos.google.com/photos/{ID}"),
    ("oneup_id", f"https://photos.google.com/photo/{ID}"),
    ("link_photo", f"https://photos.google.com/link/photo?id={ID}"),
    ("ask_photos", f"https://photos.google.com/link/ask_photos?query={ID}"),
]

# what Photos logs when it actually resolves an ID / talks to the backend
SIG = re.compile(
    r"(Envelope|Album|OneUp|AskPhotos|AskPhotos|photos\.prod|GetAlbum|getAlbum|albumId|"
    r"sharingId|SharedAlbum|resolve|Resolve|DeepLink|deeplink|Gateway|gateway|"
    r"FATAL|Exception|NullPointer|IllegalArgument|Required value|"
    r"RPC|grpc|ComesFromGooglePhotos|openingUrl|loadUrl)",
    re.I)


def run(label, url):
    C.capture(f"ph_{label}", {"type": "start", "action": "android.intent.action.VIEW",
                              "data": url, "label": label},
              [PHOTOS], settle=6, fg=True)
    return open(os.path.join(C.EVID, f"ph_{label}.full.txt")).read()


if __name__ == "__main__":
    for label, url in CASES:
        log = run(label, url)
        L = log.splitlines()
        launched = [l for l in L if "ActivityTaskManager: START" in l]
        tgt = ""
        for l in launched:
            m = re.search(r"cmp=(\S+?)\}", l)
            if m:
                tgt = m.group(1)
        crash = [l for l in L if "FATAL EXCEPTION" in l]
        cause = [l for l in L if "Caused by:" in l]
        print(f"\n{'='*100}")
        print(f"### {label}\n    {url}")
        print(f"    target : {tgt or '(no START line)'}")
        print(f"    crashed: {bool(crash)}")
        for l in crash[:1]:
            print("    X " + l.split(": ", 2)[-1][:220])
        for l in cause[:2]:
            print("    C " + l.split(": ", 2)[-1][:220])
        keep, seen = [], set()
        for l in L:
            if SIG.search(l) and "### CMD" not in l and "TopTaskTracker" not in l \
               and "WindowManager" not in l:
                if l not in seen:
                    seen.add(l)
                    keep.append(l)
        for l in keep[:10]:
            print("    ~ " + l[:240])