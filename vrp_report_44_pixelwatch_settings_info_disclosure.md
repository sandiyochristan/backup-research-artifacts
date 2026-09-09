# VRP Report #44: PixelWatchSettingsProvider Missing readPermission — Zero-Permission System Settings Disclosure

## Vulnerability Summary
PixelWatchSettingsProvider (`com.google.android.wearable.pixel.settings.provider`) runs as UID 1000 (system) and exports a ContentProvider with `android:writePermission="android.permission.WRITE_SECURE_SETTINGS"` but **no `android:readPermission`**. Any app on the device can read system configuration settings via `ContentResolver.call()` without any permission.

## Affected Component
- **Package**: `com.google.android.wearable.pixel.settings.provider`
- **APK**: `/system_ext/priv-app/PixelWatchSettingsProvider/PixelWatchSettingsProvider.apk`
- **Provider Authority**: `com.google.android.wearable.pixel.settings`
- **UID**: 1000 (system)
- **Device**: Pixel Watch 2 (eos, CP2A.260603.001, June 2026 patches)

## Root Cause
In `AndroidManifest.xml`:
```xml
<provider android:authorities="com.google.android.wearable.pixel.settings"
    android:exported="true"
    android:initOrder="100"
    android:multiprocess="false"
    android:name=".PixelWatchSettingsProvider"
    android:singleUser="true"
    android:visibleToInstantApps="true"
    android:writePermission="android.permission.WRITE_SECURE_SETTINGS"/>
```

The provider declares `writePermission` but omits `readPermission`. Android's ContentProvider framework allows reads (including `call()`) without any permission when `readPermission` is not set, even though the provider runs as system (UID 1000).

## Exposed Settings (Confirmed via Dynamic Test)
| Setting ID | Name | Value Read |
|---|---|---|
| 1001 | raise_to_talk | 1 (enabled) |
| 1002 | raise_to_talk_mediated | 0 |
| 1003 | raise_to_talk_supported | 0 |
| 1004 | raise_to_talk_gemini_enabled | 0 |
| 1007 | raise_to_talk_indicator | not set |
| 1008 | raise_to_talk_triggered | not set |
| 2001 | adaptive_charging | 1 (enabled) |
| 3001 | smart_reply_ai_enabled | 0 |
| 4004 | auto_bedtime_mode_supported | 1 |
| 1006 | raise_to_talk_sensitivity | not set |

## Attack Scenario
1. Malicious zero-permission app installed on Wear OS device
2. App calls `ContentResolver.call(uri, "get", settingId, null)` for each setting
3. Receives Bundle with `value` key containing the setting value
4. Extracts device configuration: which AI features are enabled (Gemini, smart reply), charging behavior, assistant configuration
5. This enables device fingerprinting and behavioral profiling

## Dynamic Proof
```
09-10 05:15:07.069 VRP_PWSP: Authority: com.google.android.wearable.pixel.settings
09-10 05:15:07.069 VRP_PWSP: Provider UID: 1000 (system)
09-10 05:15:07.069 VRP_PWSP: PoC app UID: 10156
09-10 05:15:07.073 VRP_PWSP:   READ raise_to_talk (1001) = 1
09-10 05:15:07.076 VRP_PWSP:   READ raise_to_talk_gemini_enabled (1004) = 0
09-10 05:15:07.079 VRP_PWSP:   READ adaptive_charging (2001) = 1
09-10 05:15:07.080 VRP_PWSP:   READ smart_reply_ai_enabled (3001) = 0
09-10 05:15:07.081 VRP_PWSP:   READ auto_bedtime_mode_supported (4004) = 1
09-10 05:15:07.086 VRP_PWSP:   WRITE raise_to_talk_gemini_enabled BLOCKED: Missing write permission: uid 10156 does not have android.permission.WRITE_SECURE_SETTINGS.
```

Write correctly requires WRITE_SECURE_SETTINGS. Read has zero protection.

## Impact
- **Confidentiality**: LOW — Device configuration feature flags disclosed
- **Integrity**: NONE — Writes properly protected
- **Availability**: NONE

## Recommended Fix
Add `android:readPermission` to the provider declaration:
```xml
<provider android:authorities="com.google.android.wearable.pixel.settings"
    android:exported="true"
    android:readPermission="android.permission.READ_SECURE_SETTINGS"
    android:writePermission="android.permission.WRITE_SECURE_SETTINGS"
    .../>
```

## PoC Files
- `poc_app/src/com/vrp/poc/PixelWatchSettingsActivity.java`
- `dynamic_evidence/pwsp_zero_perm_read.log`
