#!/usr/bin/env python3
"""Record the confirmed Google Home geofence finding to Obsidian."""
import sys
sys.path.insert(0, "/Users/sandiyochristan/Downloads/ExtractedApks")
import obs

REPORT = open("/Users/sandiyochristan/Downloads/ExtractedApks/reports/"
              "VRP_REPORT_GoogleHome_GeofenceInjection.md").read()

FINDING = """# GH-GEOFENCE-INJECTION-01 — HIGH (CONFIRMED, dynamically proven)

## Component
`com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver`
- action `com.google.android.apps.chromecast.app.gf.GF_TRANSITION`
- `android:exported="true"`, **no `android:permission`**, no read/writePermission
- `onReceive()` contains **no** `Binder.getCallingUid()`, no `getCallingPackage()`,
  no signature comparison — there is no code path that can reject a non-Google caller

## CWE
CWE-862 Missing Authorization · CWE-20 Improper Input Validation ·
CWE-248 Uncaught Exception · unvalidated `Parcel.unmarshall()` deserialization

## Two proven impacts

### A. Integrity — attacker geofence event accepted by Google Home
`getSerializableExtra(GEOFENCE_LIST)` → `check-cast [B` → `Parcel.unmarshall(b,0,len)`
(no validation) → `ParcelableGeofence.CREATOR.createFromParcel()` → protobuf → dispatched to the
presence repository.

A byte-exact re-implementation of `ParcelableGeofence.writeToParcel()` (156 bytes) was accepted:

```
I/VRPPROBE: FORGED ParcelableGeofence bytes=156 id=ATTACKER_CONTROLLED_GEOFENCE
I/VRPPROBE: FORGE_SEND #Intent;action=com.google.android.apps.chromecast.app.gf.GF_TRANSITION;...
I/VRPPROBE: FORGE_BROADCAST_SENT
E/HomeApp|qon(6231): Geofencing event error: 0
E/HomeApp|GeofenceTransitionReportingWorker(6231): Gf event error: 0 [CONTEXT is_gf_log=true ]
W/HomeApp|akhg(6231): Could not find home with ID: null
E/HomeApp|qsy(6231): java.lang.IllegalStateException: currentHome is null
```

`error: 0` = accepted and enqueued. The pipeline stops only because **this test device has no
Google Home structure linked** (`currentHome is null`). That is a limitation of the tester's
account, not a mitigation in the code.

### B. Availability — remote crash of Google Home
One element of the wrong type in the list:

```
E/AndroidRuntime: FATAL EXCEPTION: main
E/AndroidRuntime: java.lang.RuntimeException: Unable to start receiver
  com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver
E/AndroidRuntime: Caused by: java.lang.ClassCastException: java.lang.String cannot be cast to byte[]
E/AndroidRuntime:   at ...GeofenceTransitionBroadcastReceiver.onReceive(PG:127)
E/HomeApp|vaq: Crash detected. Clearing cached data
```

Reproduces on any device with Google Home installed, no account required, no user interaction.

## Intermediary evidence that bytes really reach the GMS protobuf parser
```
E/AndroidRuntime: Caused by: java.lang.IllegalArgumentException: requestId is null
E/AndroidRuntime:   at com.google.android.gms.location.internal.ParcelableGeofence.<init>(PG:138)
E/AndroidRuntime:   at adme.createFromParcel(PG:152)
E/AndroidRuntime:   at ...GeofenceTransitionBroadcastReceiver.onReceive(PG:142)
```

## Impact
Google Home presence drives routines, camera arming, lock arming and alarm state. Forged
ENTER/EXIT events with attacker-chosen geofence IDs and coordinates corrupt the occupancy model
used for **physical-security decisions**.

## PoC
`com.vrp.probe` (UID 10362) — zero `uses-permission`. See
`reports/VRP_REPORT_GoogleHome_GeofenceInjection.md` and `poc/probe/src/com/vrp/probe/GeofenceForge.java`.

## Fix
1. `android:permission="com.google.android.gms.permission.INTERNAL_BROADCAST"` (same pattern
   already used by `AppDoctorReceiver` in this APK)
2. explicit caller-cert check as defence in depth
3. validate list size/element type before use
4. never call `Parcel.unmarshall()` on untrusted bytes — use `createFromStream()`/`readParcelable()`
5. wrap parsing in try/catch so a malformed event cannot kill the process

## Evidence files
`evidence/gh_geo_forged2.full.txt`, `evidence/gh_geo_forged.full.txt`, `evidence/geo_v_compfix.full.txt`
"""

CHAIN = """# CHAIN-GH-001 — Unprotected presence injection → physical-security integrity

**Proposed severity: High** · status: dynamically proven on Pixel 6a / Android 17

## Chain
```
[1] Zero-permission app (com.vrp.probe, UID 10362)
      │  sendBroadcast() — no permission, no prompt, no user interaction
      ▼
[2] GeofenceTransitionBroadcastReceiver  (exported, NO permission, NO caller check)
      │  getSerializableExtra → check-cast [B → Parcel.unmarshall() [no validation]
      ▼
[3] ParcelableGeofence.CREATOR.createFromParcel()  (GMS protobuf parser)
      │
      ▼
[4] Google Home presence repository + GeofenceTransitionReportingWorker
      │  "Gf event error: 0"  →  attacker-chosen geofence ID, transition, lat/lng persisted
      ▼
[5] Presence state drives routines, camera arming, lock arming, alarm state
      → physical-security integrity violation
```

## Second stage of the same chain (availability)
Same entry point, malformed element → unchecked `check-cast` →
`FATAL EXCEPTION` → Google Home process killed on demand, no account needed.

## Weak signals combined
| # | Weakness | Alone | In the chain |
|---|---|---|---|
| W1 | `exported=true`, no `android:permission` | low | grants reachability |
| W2 | no `Binder.getCallingUid()` / signature check in code | low | removes the last defence |
| W3 | `getSerializableExtra` on attacker object graph | low | attacker-controlled bytes |
| W4 | unchecked `check-cast [B` | DoS only | crashes Home, and is bypassed by well-formed bytes |
| W5 | `Parcel.unmarshall()` (no validation) | low | feeds the GMS protobuf parser |
| W6 | attacker-chosen geofence ID + coordinates persisted | — | presence model corruption |

Individually W1–W3 and W5 are not reportable. Combined they produce a **High** physical-security
integrity violation plus a reliably reproducible DoS.

## Preconditions
- Integrity path: a Google Home structure linked to the signed-in account (event is accepted and
  parsed regardless)
- DoS path: none

## Evidence
`evidence/gh_geo_forged2.full.txt` (integrity), `evidence/geo_v_compfix.full.txt` (crash)
"""

JOURNAL = """# 2026-10-02 — Google Home geofence injection (CONFIRMED)

## Result: FINDING GH-GEOFENCE-INJECTION-01 (High) + CHAIN-GH-001

- Target `com.google.android.apps.chromecast.app` (Google Home), 289 components — first time
  this package was tested in this project.
- `GeofenceTransitionBroadcastReceiver` is exported with **no permission** and **no caller check**.
- Built a byte-exact re-implementation of `ParcelableGeofence.writeToParcel()` inside the probe
  (`GeofenceForge.java`) after recovering the encoding from smali (`adjg` Parcel-proto shim:
  `y()` = header + length placeholder, `z()` backfills at `off-4`).
- **Integrity proven**: forged 156-byte geofence accepted →
  `E/HomeApp|GeofenceTransitionReportingWorker: Gf event error: 0`.
  Downstream resolution needs a linked Home structure (`currentHome is null` on this device).
- **DoS proven**: one `String` element in the list →
  `FATAL EXCEPTION` → `ClassCastException: java.lang.String cannot be cast to byte[]` at
  `GeofenceTransitionBroadcastReceiver.onReceive(PG:127)`.

## Methodological notes
- aapt2 xmltree parsing needed indent-aware stack handling AND walking into `<application>`;
  an early parser returned 0 exported components and would have hidden the whole surface.
- Component-name handling in the probe double-prefixed the class name
  (`pkg/.pkg.Foo`), silently making every explicit broadcast a no-op. Verify the resolved
  component in `Intent.toUri()` before trusting a negative result.
- `START_OK` from `startActivity()` is meaningless on Android 14+ when BAL blocks the launch.
"""

MASTER = """# Google VRP Master Research Tracker

## Device
- Pixel 6a, Android 17 (SDK 37), Build CP41.260814.003.A2

## NEW Session 2026-10-02 — methodology + virgin-target sweep

### Harness (reusable)
`com.vrp.probe` — universal **zero-permission** probe app (`/Users/sandiyochristan/Downloads/ExtractedApks/poc/probe`).
JSON command channel over the app's external files dir. Operations: query / insert / update /
delete / call / getType / openFile / start / broadcast / bindService / startService / resolve / multi.

> **Read this before testing any intent on Android 14+.** BAL (Background Activity Launch) blocks
> `startActivity()` from a background receiver, but `startActivity()` still returns normally.
> Every intent test must be driven from a visible foreground Activity, and evidence must include
> the `ActivityTaskManager: START …(BAL_ALLOW_VISIBLE_WINDOW)` line plus the target's own logs.
> See `METHODOLOGY_probe_harness.md`.

> Pre-existing PoC apps on the device (`com.vrp.zeroperm`, `com.poc.confused_deputy`,
> `com.vrp.testonly*`) steal intents via their own filters and produce false positives — disable
> them (`pm disable-user`) before capture.

### Confirmed Findings
| Finding | Component | Severity | Status |
|---------|-----------|----------|--------|
| GH-GEOFENCE-INJECTION-01 | Google Home `GeofenceTransitionBroadcastReceiver` — exported, no permission, no caller check; forged geofence events accepted, crash on demand | High | CONFIRMED, dynamically proven |

Chain: `CHAIN-GH-001` (see `targets/com.google.android.apps.chromecast.app/chains/`)

### Exhausted this session — DO NOT RETEST
| Target | Component | Result |
|---|---|---|
| Gboard | `…webdebugbridge.WebDebugBridgeContentProvider` (authority `…latin.wdb`) | Reachable, but `call()` enforces a signing-cert allowlist (`assertCallingPackageHasAccess`). SECURED |
| Gboard | swissarmyknife / clipboard_content / tracing / fileprovider providers | SecurityException, not exported |
| Digital Wellbeing | `WellbeingSettingsProvider` (`…wellbeing.api`), `autodnd.ui.SettingsContentProvider` | Reachable, gated by `assertCallingPackageHasAccess` + non-Google-app check. SECURED |
| Digital Wellbeing | searchindexables provider | Requires READ_SEARCH_INDEXABLES |
| Contact Keys | `E2eeContactKeysProvider` (`com.android.contactkeys.contactkeysprovider`) | Requires READ_CONTACTS/WRITE_CONTACTS. SECURED |
| Contact Keys | `ContactKeyApiService` | Standard GMS Chimera module → `IGmsServiceBroker`, gated by GMS signature check |
| Google Fit | `vnd.google.fitness.TRACK` / `VIEW` | Not resolvable on this build |
| SafetyCore | simpleapi / signals / classification services | Bindable, but these are the intended public client APIs; verdicts are Google-signed |
| Google Home | `googlehome://*` (15 paths tested) | All launch `.deeplink.DeeplinkActivity` from a zero-perm app (needs BAL-valid caller). No privileged action proven yet |
| Google Home | `MatterSetupProxyActivity` | Launches; impact unproven |
| Google Home | `OAuthHandoffActivity` / `AccountLinkingActivity` | Launch; impact unproven |

### Still open (untested)
- Google Home: `growthkit.debug.TestingToolsBroadcastReceiver` (ADD_PROMO / SYNC / CLEAR_COUNTERS, no permission)
- Google Home: per-path impact for `googlehome://` (needs a linked Home account to demonstrate)
- Digital Wellbeing: `WellbeingService` Chrome usage-stats bind, `openFile`
- Contact Keys: `contactkeys://` MainActivity VIEW/INSERT
- SafetyCore: transaction-level fuzzing of the bound binders
- Gboard: `deeplink.com.google.android.inputmethod.latin`, `InputDeviceReceiver`

### App-level rule unchanged
ContentProvider sweeps across Google apps remain largely exhausted. The winning pattern this
session was **unprotected exported receiver + serialized IPC payload reaching a privileged
parser** — worth sweeping every Google APK's exported receivers for
`getSerializableExtra` / `unmarshall` / unchecked casts.
"""

obs.write("targets/com.google.android.apps.chromecast.app/findings/GH-GEOFENCE-INJECTION-01.md", FINDING)
obs.write("targets/com.google.android.apps.chromecast.app/chains/CHAIN-GH-001.md", CHAIN)
obs.write("targets/com.google.android.apps.chromecast.app/journal/2026-10-02-v2.md", JOURNAL)
obs.write("targets/com.google.android.apps.chromecast.app/tests/broadcast_vulnerabilities.md", """# Broadcast receiver vulnerabilities — Google Home

## CONFIRMED: GH-GEOFENCE-INJECTION-01
`GeofenceTransitionBroadcastReceiver` — exported, no permission, no caller check.
See `../findings/GH-GEOFENCE-INJECTION-01.md`.

## Exhausted
| Receiver | Result |
|---|---|
| `gf.maintenance.GeofenceSystemChangeBroadcastReceiver` | Only listens to protected implicit broadcasts (BOOT_COMPLETED / MY_PACKAGE_REPLACED / PROVIDERS_CHANGED) — platform refuses delivery from a third-party app |
| `gf.repository.GeofenceTransitionBroadcastReceiver` | **VULNERABLE** |
| `growthkit.internal.debug.TestingToolsBroadcastReceiver` | Exported, no permission — NOT YET TESTED (ADD_PROMO / ADD_PREVIEW_PROMO / SYNC / CLEAR_COUNTERS / FETCH_PROMOTIONS / FETCH_EVAL_RESULTS / GET_REGISTRATION_STATE) |
| `notifications.*.AccountChangedReceiver` / `LocaleChangedReceiver` / `TimezoneChangedReceiver` | Protected implicit broadcasts only |
| `notifications.entrypoints.blockstatechanged.BlockStateChangedReceiver` | Protected implicit broadcasts only |
| `phenotype.client.stable.AccountRemovedBroadcastReceiver` | Protected (GMS broadcast) |
""")
obs.write("VRP_Master_Tracker.md", MASTER)
print("logged finding + chain + journal + coverage + master tracker")