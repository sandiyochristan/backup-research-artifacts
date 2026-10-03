# WearOS system_server Crash via IActivityClientController — Zero-Permission DoS

## Summary

A zero-permission application installed on a Pixel Watch 2 (WearOS, Android 17) can crash `system_server` by obtaining the `IActivityClientController` binder through `IActivityTaskManager.getActivityClientController()` and calling a sequence of its methods. The crash occurs in WearOS-specific code (`com.android.clockwork.modes.ListenerManager.findRemoteObserverWrapperLocked`) due to a NullPointerException when a mode state change listener is null. This causes a full system restart, disrupting all watch functionality including health monitoring, notifications, and communication.

## Severity: Critical (DoS)

- **Attack vector**: Local (installed app, no permissions required)
- **User interaction**: None (crash triggered automatically on app launch)
- **Impact**: Complete system restart, loss of health monitoring data, disruption of notifications and communication
- **Reproducibility**: 3/3 — crash confirmed on every run of the PoC

## Affected Product

- **Device**: Pixel Watch 2 (codename: eos)
- **Serial**: 3A101RTJWRGCV9
- **Build**: CP2A.260603.001
- **Android version**: 17 (SDK 37)
- **Security patch**: 2026-06-05

## Root Cause

### 1. IActivityClientController Binder Leak

`IActivityTaskManager.getActivityClientController()` (transaction code 16) returns an `IActivityClientController` binder to any calling process without any permission check. This binder exposes **49 out of 50** methods without permission gates.

### 2. Missing Null Check in ListenerManager

The WearOS `ListenerManager.findRemoteObserverWrapperLocked()` does not check for null `IStateChangeListener` references before calling `asBinder()`. When the ACC method calls trigger activity lifecycle/mode state changes, the mode manager attempts to notify listeners — but encounters a null listener reference, causing an unhandled NPE in system_server's main thread.

### 3. Crash Sequence

The PoC performs the following operations that trigger the crash:

1. Obtains `IActivityClientController` binder via ATM txn 16 (no permission check)
2. Calls `moveActivityTaskToBack` with the activity's own token
3. Calls `moveTaskToBack` on running tasks via ATM
4. Calls `enterPictureInPictureMode` and `toggleFreeformWindowingMode`
5. Calls `navigateUpTo` with a Settings intent
6. Calls all 50 ACC methods with the real activity token
7. Calls lifecycle methods (activityPaused, activityStopped, activityDestroyed) with a fake Binder token
8. Stress-tests all 50 methods with fake tokens (3 rounds)

The crash occurs approximately **20-42 seconds** after the PoC completes, when a delayed mode state change handler fires on the system_server main thread.

## Crash Stack Trace

```
FATAL EXCEPTION IN SYSTEM PROCESS: main
java.lang.NullPointerException: Attempt to invoke interface method 
  'android.os.IBinder com.android.clockwork.modes.IStateChangeListener.asBinder()' 
  on a null object reference
    at com.android.clockwork.modes.ListenerManager.findRemoteObserverWrapperLocked
    at com.android.clockwork.modes.ListenerManager$$ExternalSyntheticLambda4.run
    at android.os.Handler.handleCallback(Handler.java:1095)
    at android.os.Handler.dispatchMessageImpl(Handler.java:135)
    at android.os.Handler.dispatchMessage(Handler.java:125)
    at android.os.Looper.loopOnce(Looper.java:296)
    at android.os.Looper.loop(Looper.java:397)
    at com.android.server.SystemServer.main
```

## Additional Finding: 49/50 ACC Methods Accessible Without Permission

The `IActivityClientController` binder exposes 49 of 50 methods without any permission check. Only transaction 18 requires permission. Methods include:

- Activity lifecycle manipulation (activityIdle, activityPaused, activityStopped, activityDestroyed)
- Task management (moveActivityTaskToBack, navigateUpTo)
- Window mode control (enterPictureInPictureMode, toggleFreeformWindowingMode)
- State queries (isTopOfTask, getCallingActivity, getCallingPackage)
- Assist/voice interaction (reportAssistContextExtras, startLocalVoiceInteraction)

## Reproduction Steps

1. Install the PoC APK on a Pixel Watch 2 running WearOS (Android 17):
   ```
   adb install poc_sysprobeV9.apk
   ```

2. Launch the PoC:
   ```
   adb shell am start -n com.poc.sysservice/.SysProbe
   ```

3. Wait 20-42 seconds. The system_server will crash with the NPE shown above, causing a full system restart.

4. Verify the crash in logcat:
   ```
   adb logcat -d | grep "FATAL EXCEPTION IN SYSTEM"
   ```

## PoC Details

- **Package**: `com.poc.sysservice`
- **Permissions**: NONE (zero-permission app)
- **Target SDK**: 35
- **Min SDK**: 34
- **APK**: `poc_sysprobeV9.apk`
- **Source**: `SysProbe.java` (attached)

## Impact Assessment

On a WearOS device (Pixel Watch), this vulnerability enables:

1. **Persistent DoS**: A malicious app can register a boot receiver and crash system_server on every boot, effectively bricking the device until the app is uninstalled via ADB.

2. **Health monitoring disruption**: During the ~2 minute system restart, health monitoring (heart rate, ECG, fall detection) is completely offline. For users relying on the watch for health alerts, this could have medical implications.

3. **Communication disruption**: Notifications, calls, and messages are unavailable during the restart period.

4. **Data loss**: Any unsaved activity state, ongoing health measurements, or in-progress operations are lost during the crash.

## Suggested Fix

1. Add a permission check in `IActivityTaskManager.getActivityClientController()` to restrict access to the caller's own process or require `MANAGE_ACTIVITY_TASKS` permission.

2. Add a null check in `ListenerManager.findRemoteObserverWrapperLocked()` before accessing `IStateChangeListener.asBinder()`.

3. Consider wrapping the mode change notification loop in a try-catch to prevent a single null listener from crashing system_server.

## Timeline

- 2026-09-12: Vulnerability discovered and reproduced 3 times independently
- 2026-09-12: PoC developed and crash confirmed on Pixel Watch 2

## Files

- `SysProbe.java` — PoC source code
- `poc_sysprobeV9.apk` — Built PoC APK
- `system_crash_v9_confirmed.log` — Full logcat with crash evidence
- `system_crash_v7_full.log` — Earlier crash evidence (independent reproduction)
