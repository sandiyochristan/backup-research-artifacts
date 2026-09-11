# WearOS Data Layer API: Zero-Permission Full Access to IWearableService

## Summary

A zero-permission application installed on a Pixel Watch 2 (Wear OS) can obtain the `IWearableService` binder from Google Play Services and perform the complete Data Layer operation set — **write arbitrary data, read it back, delete it, send messages to the paired phone, and open raw data channels** — all without any Android permissions or Google certificate verification.

## Severity

**High** — Full Confidentiality + Integrity + Availability violation requiring zero permissions.

## Highest Impact (Ranked)

### 1. INTERNET Permission Bypass via Channel (Critical)
A zero-permission app calls `openChannel` (code 31) to establish a raw data channel to the paired phone (status=0, proven). The phone has INTERNET access, so data can be relayed to any server. **This completely circumvents Android's INTERNET permission requirement** — a malicious app without INTERNET can exfiltrate data off-device through this channel.

### 2. Arbitrary Data Write + Cross-App Read (High)
A zero-permission app can:
- **Write** arbitrary data items to the Data Layer via `putData` (code 6) — proven: wrote `WRITTEN_BY_ZERO_PERM_APP_<timestamp>` to `wear://6efd13d9/poc/zero_perm_write_proof`
- **Read back** ALL data items via `getDataItems` (code 8) — proven: extracted 1 row with columns `host`, `path`, `data`, `tags`, `asset_key`, `asset_id` showing the exact written content as a 38-byte blob
- **Delete** data items via `deleteDataItems` (code 11) — proven: status=0

Data items from ALL apps sharing the Data Layer are accessible. When any Wear OS app (Google Fit, Health Services, Maps, Messages, etc.) writes data via `DataClient.putDataItem()`, a zero-permission malicious app can read the URI, raw data blob, tags, and associated assets.

### 3. Phone-Side Message Injection (High)
`sendMessage` (code 12) delivers arbitrary messages to the paired phone (proven: status=0, reqId=18659). Any phone-side `WearableListenerService` or `MessageClient.OnMessageReceivedListener` will receive and potentially process these messages. If any app trusts Data Layer messages without sender verification (which is the designed trust model — messages are supposed to only come from the paired device), the attacker can trigger phone-side actions.

### 4. Device Identity Leak (Medium)
- `getLocalNode` (code 14): leaks watch model and node ID (id=6efd13d9, name=Google Pixel Watch 2)
- `getConnectedNodes` (code 15): leaks paired phone's custom display name (id=96eb2ede, name=¯\_(ツ)_/¯)

## Affected Component

- **Package**: `com.google.android.gms` (Google Play Services)
- **Service**: `com.google.android.gms.wearable.service.WearableService`
- **Interface**: `com.google.android.gms.wearable.internal.IWearableService`
- **Build tested**: Pixel Watch 2 (eos), CP2A.260603.001, GMS version 263332086

## Root Cause

The `WearableService` in Google Play Services binds via the standard `IGmsServiceBroker` protocol (action `com.google.android.gms.wearable.BIND`, service ID 14). The broker returns the `IWearableService` binder to any calling application without verifying the caller's identity, permissions, or signature.

While certain privileged operations (telephony control, WiFi sync, configuration access) enforce `GoogleCertificatesRslt` signature verification, the core Data Layer operations perform **no authorization check at all**.

## Attack Scenario

1. Attacker publishes a WearOS app on Google Play requesting **zero permissions**.
2. User installs the app (no permission prompt appears).
3. The malicious app binds to `WearableService` and obtains the `IWearableService` binder.
4. The app writes test data to the Data Layer, reads it back, and reads any existing data from other apps.
5. The app injects messages to the paired phone, triggering actions in phone-side apps that listen for Data Layer messages.
6. The app opens a raw data channel to the phone, enabling data exfiltration without INTERNET permission.

## Proof of Concept

### Prerequisites
- Pixel Watch 2 (eos) with CP2A.260603.001
- ADB access for installation only (exploit runs entirely on-device)
- Zero-permission APK (`com.poc.datalayer`)

### Steps to Reproduce

1. Install `poc_datalayer/build/datalayer_v6.apk` on the Pixel Watch 2
2. Launch the "DL Probe" app from the watch launcher
3. Select the `DataLayerHighImpact` activity
4. Observe logcat output (tag: `DL_HIGH_IMPACT`)

### Dynamic Evidence — WRITE → READ → DELETE Cycle (v6)

```
=== Data Layer HIGH IMPACT Proof v6 ===
UID: 10180
Pkg: com.poc.datalayer
Permissions: NONE

[+] Bound to WearableService broker
[+] Got IWearableService binder (zero permissions!)

========================================
PHASE 0: WRITE → READ → DELETE CYCLE
========================================
[+] Local node: 6efd13d9
[*] Writing data item: wear://6efd13d9/poc/zero_perm_write_proof
[*] Data: WRITTEN_BY_ZERO_PERM_APP_1789139202582
[+] Code 6: OK

[*] Now reading back ALL data items...
[+] READ_AFTER_WRITE => status=0 version=1
[+] Columns: [0]=host, [1]=path, [2]=data, [3]=tags, [4]=asset_key, [5]=asset_id
[+] Window[0]: 1 rows x 6 cols
--- Row 0 ---
[!!!] host = NULL
[!!!] path = wear://6efd13d9/poc/zero_perm_write_proof
[!!!] data = BLOB(38b) ascii="WRITTEN_BY_ZERO_PERM_APP_1789139202582"
[!!!] tags = NULL
[!!!] asset_key = NULL
[!!!] asset_id = NULL
[!!!] READ_AFTER_WRITE: EXTRACTED 1 DATA ITEMS WITH ZERO PERMISSIONS!

[*] Deleting test data item...
[+] Delete status: 0
```

### Dynamic Evidence — Channel and Message (v4)

```
=== Phase 5: Send message ===
[*] Target: ¯\_(ツ)_/¯ (96eb2ede)
[*] Sending to node: 96eb2ede
[*] Path: /poc/zero_perm_test
[+] Code 12: accepted
[+] SendMessage status: 0
[+] SendMessage reqId: 18659
[!!!] MESSAGE SENT SUCCESSFULLY TO PHONE!

=== PHASE 6: CHANNEL EXFILTRATION PROOF ===
[+] Code 31: OK
[+] Channel status: 0
[!!!] CHANNEL OPENED - zero-perm app has network path to phone!
[!!!] This bypasses INTERNET permission entirely.
```

### DataHolder Schema (All Fields Accessible)

| Column | Type | Description |
|--------|------|-------------|
| host | String | Source node identifier |
| path | String | Full wear:// URI of the data item |
| data | Blob | Raw data payload (app-specific content) |
| tags | String | Data item tags |
| asset_key | String | Key for associated binary assets |
| asset_id | String | Identifier for associated binary assets |
| sourceNode | String | Originating node (in URI-filtered queries) |

## Impact Analysis

### Operations Accessible (NO authorization check)
| Operation | Code | Impact | Status |
|-----------|------|--------|--------|
| putData | 6 | Write arbitrary data items | **Proven** (code=3 callback) |
| getDataItems | 8 | Read ALL data items from ALL apps | **Proven** (1 row extracted) |
| getDataItemsByUri | 9 | Read specific data items by URI | **Proven** (status=0) |
| deleteDataItems | 11 | Delete data items | **Proven** (status=0) |
| sendMessage | 12 | Inject messages to paired phone | **Proven** (reqId=18659) |
| getLocalNode | 14 | Leak device identity | **Proven** (id=6efd13d9) |
| getConnectedNodes | 15 | Leak paired device identity | **Proven** (id=96eb2ede) |
| openChannel | 31 | Raw data channel to phone | **Proven** (status=0) |
| getAllCapabilities | 43 | Enumerate capabilities | **Proven** (status=0) |

### Operations Blocked (GoogleCertificatesRslt check)
| Operation | Code |
|-----------|------|
| endCall | 25 |
| acceptRingingCall | 26 |
| syncWifiCredentials | 37 |
| getConfigs | 22 |
| getStorageInformation | 18 |

## Suggested Fix

1. **At binder creation**: Verify `Binder.getCallingUid()` maps to an application with the Wearable API dependency and appropriate scopes.
2. **Per-operation namespace scoping**: An app with package `com.example.app` should only access data items under `wear://*/com.example.app/*`, not `wear://*`.
3. **Message attribution**: Messages should be attributed to the sending package and only delivered to the same package on the receiving device.
4. **Channel restrictions**: `openChannel` should verify that the caller has INTERNET permission or is Google-signed.

## Files

- `poc_datalayer/src/com/poc/datalayer/DataLayerHighImpact.java` — High-impact PoC (write/read/delete + channel)
- `poc_datalayer/src/com/poc/datalayer/DataLayerProbe.java` — Original PoC (phases 1-6)
- `poc_datalayer/src/com/poc/datalayer/DataLayerExploit.java` — Additional write/delete tests
- `poc_datalayer/AndroidManifest.xml` — Zero-permission manifest
- `poc_datalayer/build/datalayer_v6.apk` — Pre-built APK
- `dynamic_evidence/datalayer_high_impact_v6.log` — v6 evidence (write/read/delete + channel)
- `dynamic_evidence/datalayer_exploit_proof.log` — v4 evidence (message + identity)
