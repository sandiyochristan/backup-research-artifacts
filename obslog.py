#!/usr/bin/env python3
"""Obsidian tracker writes for this session."""
import os
import sys
sys.path.insert(0, "/Users/sandiyochristan/Downloads/ExtractedApks")
import obs

BASE = "targets"

# ---------------------------------------------------------------- methodology
METHOD = """# Methodology — Universal Zero-Permission Probe (com.vrp.probe)

## Why
Previous sessions used adb shell and ad-hoc PoC apps. `adb shell` runs as UID 2000 with
broad privileges and **cannot model an unprivileged attacker** — permission checks differ
completely. This session introduces a purpose-built harness so every result reflects what a
real third-party app with **zero Android permissions** can actually do.

## Harness
- Package: `com.vrp.probe` (UID 10362 on Pixel 6a / Android 17)
- **Declares 0 `uses-permission` entries** — verified via aapt2 on the built APK
- Command channel: JSON pushed to `/sdcard/Android/data/com.vrp.probe/files/cmd.json`
  (no shell-quoting or size limits; the old `--es json` channel mangled quotes)
- Operations: `query`, `insert`, `update`, `delete`, `call`, `getType`, `openFile`,
  `start`, `broadcast`, `bindService`, `startService`, `resolve`, `multi` (ordered chains)
- All results tagged `VRPPROBE` in logcat; evidence archived under `evidence/`

## CRITICAL METHODOLOGY CORRECTION (this session)
Android 14+ enforces **BAL — Background Activity Launch**. A zero-permission app whose only
entry point is a BroadcastReceiver cannot `startActivity()` at all. Early results in this
session returned `START_OK` from `startActivity()` while the framework silently refused:

```
E/ActivityTaskManager: Background activity launch blocked! goo.gle/android-bal
  [callingPackage: com.vrp.probe; callingUid: 10362;
   callingUidHasVisibleActivity: false; appSwitchState: 2]
I/ActivityTaskManager: START u0 {…} (BAL_BLOCK) result code=102
```

`startActivity()` returns normally, so **"START_OK" alone is not evidence of anything**.
Every intent test in this session is therefore executed from a visible foreground Activity
(`com.vrp.probe/.UiActivity`), which is a realistic attacker capability (show your own UI,
then pivot). Reports must show the `ActivityTaskManager: START …` line with
`(BAL_ALLOW_VISIBLE_WINDOW)` **and** the target's own log lines.

## Other methodology notes
- Pre-existing PoC apps on the device (`com.vrp.zeroperm`, `com.poc.confused_deputy`,
  `com.vrp.testonly*`) **steal intents** via their own exported filters. They were disabled
  (`pm disable-user`) during testing or they silently intercept `comgooglecast://` URIs and
  invalidate results.
- Evidence of impact requires the **target app's** log lines / state change, not the probe's.
- `dumpsys package providers` shows authorities; provider existence != reachability. Always
  confirm with a real query from the probe.
"""


def put(path, content):
    obs.write(path, content)
    print("WROTE", path)


def app(pkg, title, surface):
    return f"""# {title}

- Package: `{pkg}`
- Device: Pixel 6a (bluejay), Android 17 (API 37), build CP41.260814.003.A2
- Session: 2026-10-02 — first time this package has been tested in this project

## Attack surface (from aapt2 manifest analysis)
{surface}

## Testing status
See `coverage.md` for the per-technique matrix and `tests/` for detailed logs.
"""


def coverage(pkg, rows):
    t = f"""# Coverage — `{pkg}`

Device: Pixel 6a / Android 17. Attacker model: app with **zero permissions** (`com.vrp.probe`).

| Class | Technique | Component | Result | Evidence |
|-------|-----------|-----------|--------|----------|
"""
    t += "\n".join(rows) + "\n"
    put(f"{BASE}/{pkg}/coverage.md", t)


def testlog(pkg, cls, body):
    put(f"{BASE}/{pkg}/tests/{cls}.md", body)


def journal(pkg, body):
    put(f"{BASE}/{pkg}/journal/2026-10-02.md", body)


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"

    if which in ("all", "method"):
        put("METHODOLOGY_probe_harness.md", METHOD)

    if which in ("all", "apps"):
        put(f"{BASE}/com.google.android.inputmethod.latin/index.md", app(
            "com.google.android.inputmethod.latin", "Gboard (Google Keyboard)",
            """- 5 APK splits, base v18.2.8.969776716, targetSdk 37
- 72 components, **18 exported**
- Sensitive perms held: READ_CONTACTS, RECORD_AUDIO, CAMERA, GET_ACCOUNTS,
  READ_USER_DICTIONARY, WRITE_USER_DICTIONARY, READ_MEDIA_IMAGES
- Notable exported surface:
  - `com.google.android.libraries.inputmethod.webdebugbridge.WebDebugBridgeContentProvider`
    authority `com.google.android.inputmethod.latin.wdb` — **exported, NO permission**
  - `…latin.sharing.LinkReceivingLauncherActivity` (https://deeplink.com.google.android.inputmethod.latin)
  - `…libs.kcm.InputDeviceReceiver` (QUERY_KEYBOARD_LAYOUTS, no permission)
  - `…preference.SettingsSearchIndexablesProvider` (grantUriPermissions=true)
  - Non-exported providers: swissarmyknife, clipboard_content, tracing, fileprovider"""))

        put(f"{BASE}/com.google.android.apps.wellbeing/index.md", app(
            "com.google.android.apps.wellbeing", "Digital Wellbeing",
            """- 2 splits, 194 components
- Exported providers with **NO permission guard**:
  - `WellbeingSettingsProvider` → authority `com.google.android.apps.wellbeing.api`
  - `autodnd.ui.SettingsContentProvider` → `com.google.android.apps.wellbeing.autodnd.ui.provider`
- Exported `WellbeingService` bound by Chrome action
  `org.chromium.chrome.browser.usage_stats.service.WELLBEING` (no permission)"""))

        put(f"{BASE}/com.google.android.apps.chromecast.app/index.md", app(
            "com.google.android.apps.chromecast.app", "Google Home / Cast",
            """- 4 splits, 289 components — largest untested Google surface
- Fully open custom scheme `googlehome://` with 60+ exported deep-link paths including
  `/share-password`, `/safety`, `/device`, `/structures`, `/invite-to-structure`,
  `/homeagent`, `/wifi`, `/controller`, `/automations`
- Smart-home control surface: Matter commissioning proxy, geofence presence transitions,
  Cast OAuth handoff, account-linking redirect"""))

        put(f"{BASE}/com.google.android.contactkeys/index.md", app(
            "com.google.android.contactkeys", "Contact Keys (GMS proximity contact exchange)",
            """- Exported, no permission: `ContactKeyApiService`
  (action `com.google.android.gms.contactkeys.service.ContactKeyApiService.START`)
- Exported MainActivity: actions VIEW + INSERT, scheme `contactkeys`, mime
  `vnd.android.cursor.item/contactkeys`
- Backing privileged provider `com.android.providers.contactkeys/.E2eeContactKeysProvider`
  authority `com.android.contactkeys.contactkeysprovider` — confirmed guarded by
  READ_CONTACTS/WRITE_CONTACTS"""))

        put(f"{BASE}/com.google.android.apps.fitness/index.md", app(
            "com.google.android.apps.fitness", "Google Fit",
            """- 4 splits, 78 components
- Exported `FitGateway` activity-alias, no permission, handles
  `vnd.google.fitness.TRACK`, `vnd.google.fitness.sleep`, `vnd.google.fitness.VIEW`"""))

        put(f"{BASE}/com.google.android.safetycore/index.md", app(
            "com.google.android.safetycore", "SafetyCore (Play Integrity / Safety Signals)",
            """- 11 splits, 22 components
- Exported services with **no permission guard**, bindable actions:
  - `ClassificationApiService` — `com.google.android.apps.safetycore.classification.BIND`
  - `SignalStorageApiService` — `com.google.android.apps.safetycore.signals.BIND`
  - `SimpleApiService` — `com.google.android.apps.safetycore.simpleapi.BIND`"""))

COV = {
 "com.google.android.inputmethod.latin": [
  ("ContentProvider","exported no-permission provider reachability","WebDebugBridgeContentProvider","**SECURED** — `call()` enforces signing-cert allowlist","evidence/gboard_*.txt"),
  ("ContentProvider","non-exported providers (sakf/clipboard/tracing/fileprovider)","4 authorities","**BLOCKED** — SecurityException, not exported from UID 10196","evidence/gboard_sakf.txt"),
  ("ContentProvider","openFile traversal on wdb authority","wdb","Reached provider; returns FileNotFoundException (path not supported) — no traversal found","evidence/gboard_wdb_open.txt"),
  ("ContentProvider","insert/update/delete on wdb authority","wdb","delete() executes in Gboard UID returning 0; insert N/A — no state change","evidence/gboard_wdb_delete.txt"),
  ("ContentProvider","call() method fuzzing","wdb","16 method names, all return a denial Bundle; cert check blocks before dispatch","evidence/call_wdb_*.txt"),
  ("Intent","deeplink https://deeplink.com.google.android.inputmethod.latin","LinkReceivingLauncherActivity","NOT YET TESTED",""),
  ("Broadcast","QUERY_KEYBOARD_LAYOUTS","InputDeviceReceiver","NOT YET TESTED",""),
 ],
 "com.google.android.apps.wellbeing": [
  ("ContentProvider","exported no-permission WellbeingSettingsProvider query","com.google.android.apps.wellbeing.api","Reached; UnsupportedOperationException — no permission denial","evidence/wellbeing_api.txt"),
  ("ContentProvider","call() fuzzing on wellbeing.api","WellbeingSettingsProvider","Reached; guarded by `assertCallingPackageHasAccess` + non-Google-app check (smali strings: \"Access not allowed for app: \", \"Access not allowed for non-Google app: \")","evidence/call_wbapi_*.txt"),
  ("ContentProvider","autodnd.ui.provider query/call","SettingsContentProvider","Reached; same assertCallingPackageHasAccess guard","evidence/wellbeing_autodnd.txt"),
  ("ContentProvider","searchindexables provider","com.google.android.apps.wellbeing","**BLOCKED** — requires READ_SEARCH_INDEXABLES","evidence/wellbeing_root.txt"),
  ("ContentProvider","openFile on wellbeing.api","WellbeingSettingsProvider","NOT YET TESTED (expects an internal content-type URI; access-gated)",""),
  ("Service","WellbeingService bind via Chrome usage-stats action","com.google.android.apps.wellbeing.web.wellbeing.impl.WellbeingService","NOT YET TESTED",""),
 ],
 "com.google.android.apps.chromecast.app": [
  ("Deeplink","googlehome:// 60+ paths","DiscoveryActivity + many activity-aliases","PARTIAL — launches confirmed; impact not yet proven",""),
  ("Deeplink","OAuthHandoffActivity comgooglecast://chromecast.auth.com/done","mediaapps.OAuthHandoffActivity","Exported, no permission, autoVerify, singleTask, excludeFromRecents. Uri form confirmed from manifest",""),
  ("Deeplink","AccountLinkingActivity oauth-redirect.googleusercontent.com/a/<pkg>","com.google.android.libraries.accountlinking.activity.AccountLinkingActivity","Exported, no permission, launchMode singleTop. START_OK observed — impact unproven",""),
  ("Intent","Matter commissioning proxy ACTION_COMMISSION_DEVICE","setup.discovery.packages.matter.proxy.MatterSetupProxyActivity","Exported, no permission. Launches — impact unproven",""),
  ("Broadcast","GF_TRANSITION geofence presence injection","gf.repository.GeofenceTransitionBroadcastReceiver","Exported, NO permission, broadcast SENT — receiver response unproven","evidence/geo_transition.txt"),
  ("Broadcast","protected implicit broadcasts","BootReceiver et al","**BLOCKED** — platform rejects BOOT_COMPLETED/MY_PACKAGE_REPLACED from app","evidence/geo_boot.txt"),
  ("Activity","DevelopmentToolsBroadcastReceiver (growthkit debug)","growth.growthkit.internal.debug.TestingToolsBroadcastReceiver","Exported, NO permission, actions ADD_PROMO/SYNC/CLEAR_COUNTERS — NOT YET TESTED",""),
 ],
 "com.google.android.contactkeys": [
  ("ContentProvider","E2eeContactKeysProvider query","com.android.contactkeys.contactkeysprovider","**BLOCKED** — requires READ_CONTACTS or WRITE_CONTACTS","evidence/ck_root.txt"),
  ("Service","ContactKeyApiService bind","contactkeys.service.ContactKeyApiService.START","Exported, NO permission — NOT YET TESTED from Activity context",""),
  ("Intent","contactkeys:// scheme MainActivity VIEW+INSERT","contactkeys.MainActivity","Exported, no permission — NOT YET TESTED",""),
 ],
 "com.google.android.apps.fitness": [
  ("Intent","vnd.google.fitness.TRACK","FitGateway activity-alias","**NOT RESOLVABLE** — ActivityNotFoundException on this build","evidence/fit_track.txt"),
  ("Intent","vnd.google.fitness.VIEW","FitGateway activity-alias","**NOT RESOLVABLE** — ActivityNotFoundException on this build","evidence/fit_view.txt"),
  ("Intent","vnd.google.fitness.sleep","FitGateway activity-alias","START_OK — impact unproven","evidence/fit_sleep.txt"),
  ("ContentProvider","shared.fileprovider","androidx FileProvider","**BLOCKED** — not exported","evidence/fit_shared.txt"),
 ],
 "com.google.android.safetycore": [
  ("Service","simpleapi.BIND bind","SimpleApiService","Exported, no permission — bind blocked from receiver context (ReceiverCallNotAllowedException); NOT YET TESTED from Activity",""),
  ("Service","signals.BIND bind","SignalStorageApiService","Same — NOT YET TESTED from Activity",""),
  ("Service","classification.BIND bind","ClassificationApiService","Same — NOT YET TESTED from Activity",""),
 ],
}

NEG = {
 "com.google.android.inputmethod.latin": """# WebDebugBridgeContentProvider — SECURED (do not retest)

Authority `com.google.android.inputmethod.latin.wdb`, `exported=true`, **no permission**.
Reachable from `com.vrp.probe` (UID 10362, zero permissions) — confirmed, but the
`call()` entry point enforces caller authorization before any dispatch.

## Authorization logic (smali, `WebDebugBridgeContentProvider.call`, 2609 insns)
1. `Binder.getCallingUid()` / `getCallingPid()` vs `Process.myUid()` / `myPid()`
   - same UID + `rsh.b` flag → allowed (internal/debug path only)
2. `PackageManager.getPackagesForUid(callingUid)` → caller package list
3. `PackageManager.checkSignatures(myUid, callingUid)`
4. **Signing-certificate allowlist** over `SigningInfo.getApkContentsSigners()` and
   `getSigningCertificateHistory()` — compared against a hardcoded trusted set (OEM/carrier
   packages: `com.google.android.inputmethod.oemconfig`, `…keyboarddevutils` seen in the
   provider's static init)
5. Logs `"The caller (uid=%d, packageName=%s) is an allowed app."` on success, else
   `"Permission denied. The caller process is not allowed or the device needs to be rooted."`

## Dynamic confirmation
16 `ContentResolver.call()` method names (`""`, `null`, `ping`, `getWebView`, `list`, `open`,
`get`, `run`, `enable`, `debug`, `getWebViewList`, `attach`, `webview`, `load`, `eval`,
`setUrl`) all returned the **same denial Bundle** — proof the cert check runs before method
dispatch. `query()` returns null, `delete()` returns 0, `insert()` returns null,
`openFile()` raises `FileNotFoundException: No files supported by provider` — all reached
Gboard's own UID (10196) with no security exception, but no data and no state change.

## Verdict
Missing manifest permission is real, but authorization is enforced in code by signature.
A third-party app cannot satisfy it. **Not reportable.** Do not retest without a Google- or
OEM-signed caller (i.e. never, for third-party research).
""",
 "com.google.android.apps.wellbeing": """# Wellbeing exported providers — SECURED (do not retest)

`WellbeingSettingsProvider` (`content://com.google.android.apps.wellbeing.api`) and
`autodnd.ui.SettingsContentProvider` (`…autodnd.ui.provider`) are `exported=true` with no
permission guard and are reachable from a zero-permission app, but authorization is enforced
in code.

Evidence from smali of `WellbeingSettingsProvider.call()`:
- `"assertCallingPackageHasAccess"` — gate name
- `"<DWB> Allowing app to access api: %s"`
- `"Access not allowed for app: "` — per-package allowlist miss
- `"Access not allowed for non-Google app: "` — second gate
- allowlist obtained from `gbb.aG()` returning a `Set<String>`

`query()` on both raises `UnsupportedOperationException: query not supported`, so the data
surface is `call()`/`openFile()` only, and both are behind the gate.

**Verdict:** Not reportable. Do not retest `query`/`call` on these two authorities.
The unchecked remainder is the `WellbeingService` Chrome-usage-stats bind and `openFile`.
""",
}

for pkg, rows in COV.items():
    coverage(pkg, [f"| {a} | {b} | {c} | {d} | {e} |" for (a,b,c,d,e) in rows])

for pkg, body in NEG.items():
    testlog(pkg, "content_provider_vulnerabilities", body)

journal("com.google.android.inputmethod.latin", """# 2026-10-02

- Built `com.vrp.probe`, a **zero-permission** universal probe app (UID 10362). Confirmed 0
  `uses-permission` entries in the built APK via aapt2.
- Pulled Gboard (5 splits), parsed manifest: 72 components / 18 exported.
- **CONFIRMED reachable**: `com.google.android.inputmethod.latin.wdb`
  (`WebDebugBridgeContentProvider`, exported, no permission) — query/delete/openFile all
  execute inside Gboard's UID 10196.
- **CONFIRMED SECURED**: `call()` enforces a signing-certificate allowlist. 16 method-name
  fuzz returned identical denial Bundle. Not reportable.
- **BLOCKED**: swissarmyknife / clipboard_content / tracing / fileprovider providers all
  SecurityException (not exported from UID 10196).
- Discovered and corrected a methodology flaw in this session: Android BAL blocks
  `startActivity()` from a background receiver while still returning normally. All intent
  tests must now run from a foreground Activity.
""")

journal("com.google.android.apps.wellbeing", """# 2026-10-02

- Parsed manifest: 194 components.
- **CONFIRMED reachable, no permission denial**: `com.google.android.apps.wellbeing.api`
  (WellbeingSettingsProvider) and `…autodnd.ui.provider` (SettingsContentProvider).
- **CONFIRMED SECURED**: `call()` gated by `assertCallingPackageHasAccess` +
  "Access not allowed for non-Google app" package allowlist.
- **BLOCKED**: searchindexables provider requires READ_SEARCH_INDEXABLES.
- Remaining untested: `WellbeingService` Chrome usage-stats bind, `openFile` path handling.
""")

journal("com.google.android.apps.chromecast.app", """# 2026-10-02

- Largest untested Google surface so far: 289 components, fully open `googlehome://` scheme
  with 60+ deep-link paths (`/share-password`, `/safety`, `/structures`,
  `/invite-to-structure`, `/device`, `/wifi`, `/controller`, `/automations`, `/homeagent`).
- Exported, no permission, impact still to be proven:
  - `MatterSetupProxyActivity` — Matter smart-home commissioning proxy
  - `GeofenceTransitionBroadcastReceiver` — home/away presence transitions drive locks/cameras
  - `OAuthHandoffActivity` — `comgooglecast://chromecast.auth.com/done`, autoVerify,
    singleTask, excludeFromRecents
  - `AccountLinkingActivity` — `https://oauth-redirect.googleusercontent.com/a/<pkg>`
  - `growthkit.debug.TestingToolsBroadcastReceiver` — ADD_PROMO / CLEAR_COUNTERS, no permission
- `vnd.google.fitness.*` actions do NOT resolve on this build.
- Note: `com.vrp.zeroperm` on this device registers an `OAuthInterceptActivity` that steals
  `comgooglecast://` URIs. It was disabled before capture, otherwise every OAuth test gives a
  false positive.
""")

journal("com.google.android.safetycore", """# 2026-10-02

- 3 exported services with BIND actions and no permission guard (simpleapi / signals /
  classification). Binding was not yet possible from a BroadcastReceiver
  (`ReceiverCallNotAllowedException`) — must be retried from the probe's foreground Activity.
""")

journal("com.google.android.contactkeys", """# 2026-10-02

- `E2eeContactKeysProvider` (privileged `/system/priv-app`) is properly guarded by
  READ_CONTACTS/WRITE_CONTACTS — confirmed SecurityException from the zero-perm probe.
- Still open: exported unprotected `ContactKeyApiService` and the `contactkeys://` MainActivity.
""")

journal("com.google.android.apps.fitness", """# 2026-10-02

- `vnd.google.fitness.TRACK` and `vnd.google.fitness.VIEW` do not resolve to any activity on
  this build despite the exported `FitGateway` alias declaring those filters
  (ActivityNotFoundException). `vnd.google.fitness.sleep` does launch.
""")
print("coverage + journals written")
