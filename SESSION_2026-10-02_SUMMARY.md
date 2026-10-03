# Session Summary — 2026-10-02 — Google VRP / Android 17 virgin-target sweep

**Device:** Pixel 6a (bluejay) · Android 17 (API 37) · build CP41.260814.003.A2
**Working dir:** `/Users/sandiyochristan/Downloads/ExtractedApks/`
**Obsidian:** all results logged under `Android-Security-Research/`

---

## 1. Outcome

**One confirmed finding + one exploit chain**, dynamically proven on-device from an app with
**zero Android permissions**. Severity was revised **High -> Low** after a triage-risk review — see
§7. Do not resubmit as High.

> **`GH-GEOFENCE-INJECTION-01`** — Google Home
> (`.gf.repository.GeofenceTransitionBroadcastReceiver`) is `exported=true` with **no
> `android:permission`** and **no caller check of any kind** (no `Binder.getCallingUid()`, no
> `getCallingPackage()`, no signature comparison).
>
> - **Integrity:** a byte-exact forged `ParcelableGeofence` (156 B) was accepted and executed by
>   Google Home's own pipeline — `E/HomeApp|GeofenceTransitionReportingWorker: Gf event error: 0`.
>   Attacker controls geofence ID, transition type and trigger coordinates. Google Home presence
>   drives lock/camera/alarm arming → physical-security integrity.
> - **Availability:** one wrong-typed element in the serialized list →
>   `FATAL EXCEPTION … ClassCastException: java.lang.String cannot be cast to byte[]` at
>   `onReceive(PG:127)`. Google Home is killed and re-killed on every restart.

Report: `reports/VRP_REPORT_GoogleHome_GeofenceInjection.md`
Evidence: `evidence/GH_GEOFENCE_FINAL_EVIDENCE.txt` (+ 121 other captured logs)
Reproduce: `python3 probe/final_evidence.py`

---

## 2. Reusable harness — `com.vrp.probe`

Universal **zero-permission** attacker app (UID 10362, **0 `uses-permission` entries verified with
aapt2**). Prior sessions used `adb shell` (UID 2000), which cannot model an unprivileged attacker.

Command channel: JSON pushed to `/sdcard/Android/data/com.vrp.probe/files/cmd.json`
(the earlier `--es json` channel was mangled by shell quoting).
Operations: `query · insert · update · delete · call · getType · openFile · start · broadcast ·
bindService · startService · resolve · multi · forgeGeo`.

Drivers: `probe/probe.py`, `probe/capture.py` (target-side logcat capture), `probe/final_evidence.py`.

---

## 3. Methodology defects found and fixed (important for future sessions)

1. **BAL (Background Activity Launch).** On Android 14+, `startActivity()` from a background
   receiver is **silently refused while still returning normally**. Every `START_OK` without an
   `ActivityTaskManager: START …(BAL_ALLOW_VISIBLE_WINDOW)` line is worthless. All intent tests must
   run from a visible foreground Activity.
2. **Intent-stealing PoC apps on the device.** `com.vrp.zeroperm/.OAuthInterceptActivity` intercepts
   `comgooglecast://` and produces false positives. Disable with `pm disable-user`.
3. **Component-name double-prefixing.** `pkg/.pkg.sub.Foo` silently made every explicit broadcast a
   no-op and produced false negatives. Always verify the resolved component in `Intent.toUri()`.
4. **aapt2 xmltree parsing** needs indent-aware stack handling *and* traversal into
   `<application>`. A naive parser reports **0 exported components** and hides the whole surface.
5. **Unparcelled Bundles.** `ContentResolver.call()` results must be forced through `b.size()` /
   `b.keySet()`; `Bundle.toString()` prints only `mParcelledData`.

---

## 4. Targets attacked (all previously untested — 0 prior work in Obsidian)

`com.google.android.inputmethod.latin` · `…apps.wellbeing` · `…apps.chromecast.app` ·
`…contactkeys` · `…apps.fitness` · `…safetycore` · `…apps.deviceusagestudy` · `…apps.adwords` ·
`…apps.cloudconsole` · `…apps.agentspace` · `…apps.classroom` · `…apps.cultural` ·
`…apps.seekh` · `…apps.giant` · `…apps.magazines` · `com.google.android.contactkeys` ·
`com.google.android.apps.searchlite` · `com.google.android.apps.cloud.cloudbi`
(18 packages, 353 exported components mapped).

---

## 5. Exhausted — DO NOT RETEST

| Target | Component | Result |
|---|---|---|
| Gboard | `…webdebugbridge.WebDebugBridgeContentProvider` (`…latin.wdb`) | Reachable, but `call()` enforces a signing-cert allowlist. **SECURED** |
| Gboard | swissarmyknife / clipboard_content / tracing / fileprovider | SecurityException (not exported from UID 10196) |
| Digital Wellbeing | `WellbeingSettingsProvider`, `autodnd.ui.SettingsContentProvider` | Reachable, gated by `assertCallingPackageHasAccess` + non-Google-app check. **SECURED** |
| Contact Keys | `E2eeContactKeysProvider` | Requires READ/WRITE_CONTACTS. **SECURED** |
| Contact Keys | `ContactKeyApiService` | Standard GMS Chimera module → `IGmsServiceBroker`, GMS signature gate |
| Google Fit | `vnd.google.fitness.TRACK` / `VIEW` | Not resolvable on this build |
| SafetyCore | simpleapi / signals / classification | Bindable, but these are the intended public client APIs |

---

## 6. Open threads

- Google Home `growthkit.debug.TestingToolsBroadcastReceiver` — exported, no permission, untested
- `googlehome://` per-path impact (blocked on a linked Home account: `currentHome is null`)
- `MatterSetupProxyActivity` impact (needs a Matter device)
- Digital Wellbeing `WellbeingService` Chrome usage-stats bind + `openFile`
- `contactkeys://` MainActivity VIEW/INSERT
- SafetyCore transaction-level fuzzing of the bound binders

**New sweep heuristic that paid off:** exported receiver + serialized IPC payload reaching a
privileged parser (`getSerializableExtra` → unchecked cast → `Parcel.unmarshall`). Grep every
Google APK's exported receivers for this shape.

---

## 7. Severity correction and triage reality (IMPORTANT)

**Downgraded High → Low.** Do not resubmit as High or "physical security compromise".

| Factor | Reality | Effect |
|---|---|---|
| User must install an app | **Unavoidable** — only an app can send a broadcast | dominant VRP penalty, caps the rating |
| Tier-2 app | Google Home is not GMS / Android / Google account | low multiplier |
| Data theft | none | capped |
| Privilege escalation | none — writes stay in the app sandbox | capped |
| Integrity end-to-end | **not proven** — stops at `currentHome is null` | blocks any critical claim |
| Remote trigger | none found | blocks any remote claim |

**Expected: informational–Low (~$0–500), plausible rejection.**

### Remote escalation attempted — and it produced a reusable lead
`DeeplinkActivity` is `exported=true` **and** `CATEGORY_BROWSABLE` → the entire `googlehome://`
scheme is **web-reachable with no app install**. 12 paths tested: 6 render navigation only, 6 do
not resolve (`result code=-91`). None performed a privileged action, so it does not save *this*
bug — but it removes the biggest penalty for any *future* deep-link bug in Google Home.

### How to beat the "malicious app install" penalty in future work
The trigger must be one of:
1. a **BROWSABLE** exported component (web-reachable) — `googlehome://`, `comgooglecast://`
2. a **network-reachable** service (local socket / listening port)
3. a **media / USB / NSD** ingestion path

Plain exported components will keep getting downgraded to 25%, no matter how good the analysis is.
