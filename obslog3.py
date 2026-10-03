#!/usr/bin/env python3
"""Correct the severity/claims recorded in Obsidian after triage-risk review."""
import sys
sys.path.insert(0, "/Users/sandiyochristan/Downloads/ExtractedApks")
import obs

FINDING = """# GH-GEOFENCE-INJECTION-01 — **LOW** (confirmed, dynamically proven)

> **REVISED 2026-10-02 after triage-risk review.** Originally logged as High. That was an
> overclaim and is corrected here. Severity is **Low** because the only trigger is a local app
> install, the target is a tier-2 consumer app, there is no data theft and no privilege
> escalation. Expected VRP outcome: informational to Low (~$0-500), plausible rejection.

## Component
`com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver`
- action `com.google.android.apps.chromecast.app.gf.GF_TRANSITION`
- `android:exported="true"`, **no `android:permission`**, no read/writePermission
- `onReceive()` has **no** `Binder.getCallingUid()`, no `getCallingPackage()`, no signature
  comparison — no code path can reject a non-Google caller

## CWE
CWE-862 Missing Authorization · CWE-20 Improper Input Validation · CWE-248 Uncaught Exception

## What is PROVEN

### 1. Availability — unconditional crash of Google Home  (strongest evidence)
`getSerializableExtra(GEOFENCE_LIST)` → unchecked `check-cast [B` → `ClassCastException`.

```
E/AndroidRuntime: FATAL EXCEPTION: main
E/AndroidRuntime: Process: com.google.android.apps.chromecast.app, PID: 7661
E/AndroidRuntime: java.lang.RuntimeException: Unable to start receiver
  com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver
E/AndroidRuntime: Caused by: java.lang.ClassCastException: java.lang.String cannot be cast to byte[]
E/AndroidRuntime:   at ...GeofenceTransitionBroadcastReceiver.onReceive(PG:127)
E/HomeApp|vaq: Crash detected. Clearing cached data
# restarted by the system and killed again on the next broadcast (pid 7661, then 8108)
```
Needs **no Google account and no Home structure**. Repeatable indefinitely.

### 2. Unauthorized input acceptance — downstream effect NOT demonstrated
A byte-exact forged `ParcelableGeofence` (156 B) was accepted and executed by Google Home:

```
E/HomeApp|qon(7139): Geofencing event error: 0
E/HomeApp|GeofenceTransitionReportingWorker(7139): Gf event error: 0 [CONTEXT is_gf_log=true ]
W/HomeApp|akhg(7139): Could not find home with ID: null
E/HomeApp|qsy(7139): java.lang.IllegalStateException: currentHome is null
```

**`currentHome is null`** — this test account has **no Google Home structure linked**. So it is
NOT proven that presence state, routines, locks, cameras or alarms actually change. Only that
arbitrary data crosses an unauthorized IPC boundary and reaches Google's presence pipeline.

**Do not claim:** privilege escalation, physical-security compromise, or proven presence corruption.

## Why the rating is Low (do not re-litigate without new evidence)
| Factor | Reality |
|---|---|
| User must install an app | **Unavoidable** — only an app can send a broadcast. This is the dominant VRP penalty. |
| Tier-2 app | Google Home is not GMS / Android platform / Google account |
| Data theft | none |
| Privilege escalation | none — writes stay in the app sandbox |
| Remote trigger | **none found.** See below. |

## Remote-escalation attempt — FAILED, do not repeat
`DeeplinkActivity` is `exported=true` **and** `CATEGORY_BROWSABLE`, so `googlehome://` IS reachable
from a web page (this is a genuinely useful lead for other bugs). 12 state-changing paths tested:

| Path | Result |
|---|---|
| `controller`, `creategroup`, `settings/camera/familiar-face/privacy`, `invite-to-structure`, `setup/interconnect`, `wifi/share-password` | resolve (`result code=0`) — **navigation render only, no privileged action** |
| `3p-setup`, `enrollment`, `ha_linking`, `permissions`, `play-iap`, `setup` | not resolvable (`result code=-91`) |

No path performed a privileged action, so the "no install required" claim cannot be made here.

## Fix
1. `android:permission="com.google.android.gms.permission.INTERNAL_BROADCAST"` (same pattern
   already used by `AppDoctorReceiver` in this APK)
2. explicit caller-cert check as defence in depth
3. validate list size + element type before use
4. never `Parcel.unmarshall()` untrusted bytes — use `createFromStream()` / `readParcelable()`
5. try/catch the parse so a malformed event cannot kill the process

## Evidence
`evidence/GH_GEOFENCE_FINAL_EVIDENCE.txt`, `evidence/gh_geo_forged2.full.txt`,
`evidence/geo_v_compfix.full.txt`, `probe/final_evidence.py`
"""

CHAIN = """# CHAIN-GH-001 — Unauthorized presence injection (LOW; impact bounded)

**Severity: Low.** Original "High physical-security" framing was an overclaim — see finding §Why
the rating is Low. The chain is complete up to the presence pipeline; the final security-relevant
step is **unproven** because no Home structure is linked on the test device.

## Chain (proven portion)
```
[1] Zero-permission app (com.vrp.probe, UID 10362)
      │  sendBroadcast() — no permission, no prompt, no user interaction
      ▼
[2] GeofenceTransitionBroadcastReceiver (exported, NO permission, NO caller check)
      │  getSerializableExtra → check-cast [B → Parcel.unmarshall() [no validation]
      ▼
[3] ParcelableGeofence.CREATOR.createFromParcel()  (GMS protobuf parser)
      │
      ▼
[4] Google Home presence repository + GeofenceTransitionReportingWorker
      │  "Gf event error: 0" → event accepted and enqueued
      ▼
[5] ??? — resolution requires a linked Home structure (currentHome is null on test device)
      → NOT DEMONSTRATED
```

## Second stage of the same chain (fully proven)
Same entry point, malformed element → unchecked `check-cast` → `FATAL EXCEPTION` → Google Home
process killed on demand. No account required, repeatable indefinitely.

## Weak signals combined
| # | Weakness | Alone | In the chain |
|---|---|---|---|
| W1 | `exported=true`, no `android:permission` | low | grants reachability |
| W2 | no `getCallingUid()` / signature check in code | low | removes the last defence |
| W3 | `getSerializableExtra` on attacker object graph | low | attacker-controlled bytes |
| W4 | unchecked `check-cast [B` | crash | **fully proven DoS** |
| W5 | `Parcel.unmarshall()` (no validation) | low | feeds the GMS protobuf parser |
| W6 | event accepted by presence pipeline | — | proven accepted; downstream effect unproven |

## Preconditions
- All paths: attacker installs a third-party app (this is why it is Low, not High)
- Injection path additionally needs a linked Home structure to resolve
- Crash path needs nothing beyond the install
"""

MASTER_ADD = """
### Correction — 2026-10-02 (read before reusing GH-GEOFENCE-INJECTION-01)
That finding was downgraded **High → Low** after a triage-risk review. Reasons:
1. **Only trigger is a local app install** — unavoidable for a broadcast receiver. This is the
   dominant Google VRP penalty and it caps the rating regardless of how good the code analysis is.
2. Google Home is a **tier-2** consumer app.
3. No data theft, no privilege escalation, no remote trigger.
4. The downstream security effect is **unproven**: the forged event reaches
   `GeofenceTransitionReportingWorker` with `error: 0` but then stops at `currentHome is null`
   because the test account has no linked Home structure.

**Do not resubmit it as High / "physical security compromise".** Expected: informational–Low
(~$0–500), with a real chance of rejection.

**What did work, and is reusable:** `DeeplinkActivity` in Google Home is `exported=true` **and**
`CATEGORY_BROWSABLE`, so the whole `googlehome://` scheme is **web-reachable with no app install**.
That removes the biggest penalty for any *future* deep-link bug there. So far 12 paths tested:
6 render navigation only, 6 do not resolve. Keep hunting this surface for a path that performs an
action rather than drawing a screen.

**General lesson:** to beat the "malicious app install" penalty, the trigger must be one of
(a) a `BROWSABLE` exported component (web-reachable), (b) a network-reachable service, or
(c) a media/USB/ADB path. Plain exported components will keep getting downgraded.
"""

obs.write("targets/com.google.android.apps.chromecast.app/findings/GH-GEOFENCE-INJECTION-01.md", FINDING)
obs.write("targets/com.google.android.apps.chromecast.app/chains/CHAIN-GH-001.md", CHAIN)

cur = obs.read("VRP_Master_Tracker.md")
if "Correction — 2026-10-02" not in cur:
    obs.write("VRP_Master_Tracker.md", cur + MASTER_ADD)
print("corrected finding + chain + master tracker")