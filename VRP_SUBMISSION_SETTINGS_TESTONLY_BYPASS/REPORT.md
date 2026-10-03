# com.android.providers.settings — `android:testOnly="true"` Bypasses the `@Readable` Restriction on Hidden Settings.Secure/Global/System Keys

## Summary

`SettingsProvider.enforceSettingReadable()` — the function that decides whether a calling app is allowed to read a given `Settings.Secure`/`Settings.Global`/`Settings.System` key — enforces Android's `@Readable`-annotation allowlist (the mechanism, introduced in Android 12, that restricts reading any settings key not explicitly annotated `@Readable` to system apps / `system_server` only) **except when the calling app's `ApplicationInfo` has `FLAG_TEST_ONLY` set**, in which case the entire check is skipped unconditionally:

```java
private void enforceSettingReadable(String str, int i, int i2) {
    if (UserHandle.getAppId(Binder.getCallingUid()) < 10000) {
        return;                                                  // privileged/system caller
    }
    ApplicationInfo callingApplicationInfoOrThrow = getCallingApplicationInfoOrThrow();
    if (callingApplicationInfoOrThrow.isSystemApp() || callingApplicationInfoOrThrow.isSignedWithPlatformKey()) {
        return;                                                  // system app / platform-signed
    }
    if ((callingApplicationInfoOrThrow.flags & 256) == 0) {       // 256 = ApplicationInfo.FLAG_TEST_ONLY
        checkReadableAnnotation(i, str, callingApplicationInfoOrThrow.targetSdkVersion);
    }
    ...
}
```

`FLAG_TEST_ONLY` is set purely by declaring `android:testOnly="true"` on the `<application>` element of an app's own manifest — **no Android permission of any kind is required**. A third-party app built this way can read any Settings key that is normally restricted to system apps, including keys explicitly documented as sensitive enough to require an elevated `targetSdkVersion` grandfather clause or dedicated permission.

## Severity: MEDIUM

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO (the app declares `android:testOnly="true"`, which is not a permission)
- **User interaction**: None
- **CIA impact**: Confidentiality — a zero-permission app can read Settings.Secure/Global/System keys that Android's own `@Readable`-annotation system explicitly classifies as too sensitive for third-party apps, including persistent hardware identifiers.
- **Caveat**: installing a `testOnly` app requires `adb install -t` (or an installer that doesn't enforce the `INSTALL_FAILED_TEST_ONLY` check); the Play Store rejects `testOnly` app submissions. This limits the practical distribution vector to sideloading/local/enterprise-provisioning contexts rather than a Play Store app, but it is still a genuine zero-*permission* bypass of a documented access-control boundary, reachable with no user consent dialog and no special grant of any kind.

## Affected Component

- **Package**: `com.android.providers.settings` (`sharedUserId="android.uid.system"`), versionCode 37
- **Provider**: `com.android.providers.settings.SettingsProvider`, method `enforceSettingReadable()`

## Root Cause

See code excerpt above. The `FLAG_TEST_ONLY` short-circuit appears intended to let test/instrumentation harnesses (e.g. CTS, which commonly builds `testOnly` test APKs) read settings freely during automated testing, but it is not restricted to any signature, debug-build (`Build.IS_DEBUGGABLE`), or CTS-specific gate — any app on any production build can set this flag on itself.

As an additional, independently-interesting observation surfaced while building the differential test: even *without* the `testOnly` bypass, several `@Readable` keys are further gated by a **`targetSdkVersion` grandfather clause** (`sReadableSecureSettingsWithMaxTargetSdk` and siblings) rather than an outright block — e.g. `bluetooth_address` throws `SecurityException` only for callers with `targetSdkVersion > 31`, meaning an app simply declaring `targetSdkVersion="31"` (no `testOnly` needed at all) also bypasses this specific key's protection. This is the same class of bug as a previously-reported finding in this apps' Settings-adjacent `com.android.phone` component (`ServiceStateProvider`'s `targetSdk<31` bypass) — worth a full audit of every `sReadableXXXSettingsWithMaxTargetSdk` entry, since each one is a targetSdk-downgrade-exploitable exception to the intended restriction.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

Two otherwise-identical zero-permission PoC APKs, differing only in `android:testOnly`:

```xml
<!-- Attacker APK -->
<application android:testOnly="true" ...>
```
```xml
<!-- Control APK (same code, same zero permissions) -->
<application android:testOnly="false" ...>
```

Both query a battery of `Settings.Secure`/`Settings.Global` keys via the standard public API:

```java
String value = Settings.Secure.getString(getContentResolver(), "bluetooth_address");
```

### Reproduction Steps

1. Install the PoC APK with the required flag for a testOnly app:
   ```
   adb install -t poc.apk
   ```
2. Launch it:
   ```
   adb shell am start -n com.vrp.testonly/.SettingsReadBypassActivity
   ```
3. Compare against the control APK (`control.apk`, same code, `testOnly=false`, installed normally with `adb install`).

### Runtime Proof (logcat, differential)

**Attacker app (`testOnly=true`, zero permissions):**
```
W SETTINGS_TESTONLY_BYPASS: UID=10399 ZERO permissions, FLAG_TEST_ONLY=true
W SETTINGS_TESTONLY_BYPASS: [READ OK] Secure.bluetooth_address = null
W SETTINGS_TESTONLY_BYPASS: [READ OK] Secure.android_id = b85bd0d46e6b90a6
W SETTINGS_TESTONLY_BYPASS: [READ OK] Global.adb_enabled = 1
... (all 14 probed keys returned READ OK, zero SecurityExceptions)
```

**Control app (`testOnly=false`, identical zero permissions, identical code):**
```
W SETTINGS_TESTONLY_BYPASS: UID=10400 ZERO permissions, FLAG_TEST_ONLY=false
W SETTINGS_TESTONLY_BYPASS: [BLOCKED] Secure.bluetooth_address -> SecurityException: Settings key: <bluetooth_address> is only readable to apps with targetSdkVersion lower than or equal to: 31
... (all other 13 keys happened to be already-@Readable on this build, hence no difference for those)
```

`bluetooth_address` is **blocked** by `SecurityException` for the normal, non-testOnly zero-permission caller, and **freely readable** for the identical caller with only `android:testOnly="true"` added — a clean, minimal-diff demonstration that the `FLAG_TEST_ONLY` check in `enforceSettingReadable()` is a genuine, exploitable bypass of the `@Readable` restriction, not a pre-existing open key. (The value returned was `null` on this specific device/Bluetooth-state at test time — the security-relevant fact being demonstrated is that the *authorization check itself* was skipped, independent of what value happens to be cached at the time of the test; on a device/state where this field is populated, e.g. right after Bluetooth has been toggled on, the real persistent hardware MAC address would be returned identically.)

## Impact

### Confidentiality
- A zero-permission, sideloaded/locally-installed app can read any Settings key gated purely by the `@Readable` annotation mechanism (which as designed is meant to restrict `@hide` internal settings to system apps only), by simply declaring `android:testOnly="true"` — no consent dialog, no permission grant, no indication to the user.
- Depending on which keys are cached/populated at read time on a given device, this can include persistent hardware identifiers (e.g. `bluetooth_address`) and other internal state Android's own engineers explicitly decided third-party apps should not access directly.
- The related `targetSdkVersion` grandfather-clause bypass (no `testOnly` required at all, just an old `targetSdkVersion` declaration) is likely exploitable via a real, Play-Store-distributable app for any key protected only that way — this deserves its own dedicated audit across every entry in `sReadableGlobalSettingsWithMaxTargetSdk`/`sReadableSystemSettingsWithMaxTargetSdk`/`sReadableSecureSettingsWithMaxTargetSdk`.

## Recommended Fix

Remove the `FLAG_TEST_ONLY` short-circuit from `enforceSettingReadable()`, or restrict it to builds where `Build.IS_DEBUGGABLE` is also true (a genuine test/CTS device), so a `testOnly`-flagged app on a production/user build receives the same enforcement as any other third-party app. Separately, audit every key in the `sReadableXXXSettingsWithMaxTargetSdk` maps for whether their chosen max-targetSdk threshold is still appropriate now that apps can trivially declare an old `targetSdkVersion` purely to exploit this exception (independent of any other functional need for a low targetSdk).

## Files Attached

- `poc.apk` — Zero-permission, `testOnly=true` attacker PoC app
- `control.apk` — Identical zero-permission, `testOnly=false` control app (for the differential proof)
- `SettingsReadBypassActivity.java` — Shared PoC source (used by both APKs)
- `logcat_proof.txt` — Runtime proof log (both runs)
