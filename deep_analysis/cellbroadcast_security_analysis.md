# CellBroadcastReceiver Security Analysis
## Package: com.google.android.cellbroadcastreceiver (Android 17, Pixel 6a)

**Date:** 2026-09-10
**Analyst:** sandiyo.antony@zeb.co
**Target APK:** com.google.android.cellbroadcastreceiver (platformBuildVersionCode=36, compileSdkVersionCodename=16)

---

## 1. Manifest Summary

### Permissions Held (Privileged)
- `RECEIVE_EMERGENCY_BROADCAST` (signature|privileged)
- `MODIFY_PHONE_STATE` (signature|privileged)
- `MODIFY_CELL_BROADCASTS` (signature|privileged)
- `DISABLE_KEYGUARD` (normal -> dangerous on some OEMs)
- `READ_PRIVILEGED_PHONE_STATE` (signature|privileged)
- `STATUS_BAR` (signature|privileged)
- `DEVICE_POWER` (signature|privileged)
- `START_ACTIVITIES_FROM_BACKGROUND` (signature|privileged)
- `INTERACT_ACROSS_USERS` (signature|privileged)
- `MANAGE_USERS` (signature|privileged)
- `READ_CELL_BROADCASTS`
- `READ_SMS`
- `HIDE_NON_SYSTEM_OVERLAY_WINDOWS`

### Exported Components

| Component | Type | Protection | Notes |
|-----------|------|------------|-------|
| `CellBroadcastContentProvider` | Provider (authority: `cellbroadcasts-app`) | `readPermission="android.permission.READ_CELL_BROADCASTS"` | Exported, read-protected |
| `CellBroadcastSearchIndexableProvider` | Provider (authority: `com.android.cellbroadcastreceiver`) | `permission="android.permission.READ_SEARCH_INDEXABLES"` | Exported, protected by signature perm |
| `CellBroadcastListActivity` | Activity | None (intent-filter only) | Exported, no permission |
| `CellBroadcastSettings` | Activity | None | Exported, no permission |
| `CellBroadcastReceiver` | Receiver | None (intent-filter only) | Exported, handles multiple telephony actions |
| `CellBroadcastAlertDialog` | Activity | **exported="false"** | Not exported, internal only |
| `CellBroadcastInternalReceiver` | Receiver | **exported="false"** | Not exported |
| `ProfileInstallReceiver` | Receiver | `permission="android.permission.DUMP"` | AndroidX library artifact |

---

## 2. Finding: SQL Injection in CellBroadcastContentProvider

### Severity: Medium-Low (permission-gated)
### Location: `CellBroadcastContentProvider.query()` (line 97)

```java
sQLiteQueryBuilder.appendWhere("(_id=" + uri.getPathSegments().get(0) + ')');
```

The `query()` method handles URI pattern `#` (match code 1) by directly concatenating the first URI path segment into a SQL WHERE clause via `appendWhere()`. The URI matcher uses `#` which only matches numeric path segments, but the `appendWhere` pattern itself is a textbook SQL injection vector.

**However**, the UriMatcher with `#` pattern restricts the path segment to digits only. If Android's UriMatcher `#` pattern is bypassed (historically possible in certain edge cases), the concatenation would allow injection.

Additionally, the `query()` method passes through the caller-supplied `selection` (parameter `str`) and `selectionArgs` (parameter `strArr2`) directly to `SQLiteQueryBuilder.query()` without any validation or `setStrict(true)`:

```java
Cursor cursorQuery = sQLiteQueryBuilder.query(awaitInitAndGetReadableDatabase(),
    strArr, str, strArr2, null, null, str2);
```

**The builder never calls `setStrict(true)`**, which means:
- The caller can inject UNION SELECT in the selection parameter
- The caller can use subqueries in projection columns
- The sortOrder parameter is also caller-controlled

**Access Control:** This provider requires `android.permission.READ_CELL_BROADCASTS` for reads. On AOSP, this permission is `dangerous` (runtime permission in the SMS group). However, any app with the SMS permission group can read emergency broadcast history including message bodies, timestamps, cell location data (PLMN, LAC, CID), and service categories.

**Impact Assessment:** An app with READ_CELL_BROADCASTS (or READ_SMS which is in the same group) can:
1. Read the entire emergency alert history
2. Extract cell tower location data (PLMN, LAC, CID) to derive coarse user locations
3. Use projection-based SQL injection to extract data if `setStrict()` is not enforced
4. The insert/delete/update methods throw `UnsupportedOperationException` so data modification is not possible externally

**VRP Verdict:** Low-to-moderate severity. The permission gate means this requires a cooperating app with SMS-group permissions, which lowers the bar but does not eliminate it entirely. The cell location data (LAC/CID) in the database represents a privacy leak for location history to any SMS-permission-holding app.

---

## 3. Finding: CellBroadcastSettings Exported Without Permission

### Severity: Low (UI DoS / Nuisance)
### Location: AndroidManifest.xml line 66

```xml
<activity android:exported="true" android:label="@string/sms_cb_settings"
    android:name="com.android.cellbroadcastreceiver.CellBroadcastSettings"
    android:theme="@style/CellBroadcastSettingsTheme"/>
```

CellBroadcastSettings is exported with **no permission** and **no intent-filter**. Any app can launch it:

```
adb shell am start -n com.google.android.cellbroadcastreceiver/com.android.cellbroadcastreceiver.CellBroadcastSettings
```

**Impact:** Any third-party app can open the emergency alert settings screen. While the user still must interact with the UI to change settings, a malicious app could:
- Repeatedly launch this activity as a DoS/annoyance
- Social-engineer the user ("Tap here to fix...") into disabling critical alerts like presidential/AMBER/extreme threat alerts

The `CellBroadcastSettings.onCreate()` does check `UserManager.hasUserRestriction("no_config_cell_broadcasts")` but has no caller-permission check.

**VRP Verdict:** Low severity. Design choice for Settings integration, but the lack of any permission allows any installed app to launch emergency alert configuration UI.

---

## 4. Finding: CellBroadcastListActivity Exported Without Permission

### Severity: Low (Information Disclosure of Alert History via UI)
### Location: AndroidManifest.xml lines 49-58

```xml
<activity android:exported="true" ...
    android:name="com.android.cellbroadcastreceiver.CellBroadcastListActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.cellbroadcastreceiver.UPDATE_LIST_VIEW"/>
    </intent-filter>
</activity>
```

The alert history activity is exported with no permission protection. It loads data from two sources:
1. Loader ID 1: `CellBroadcastContentProvider.CONTENT_URI` ("cellbroadcasts-app") -- the app's local database
2. Loader ID 2: `Uri.parse("content://cellbroadcasts")` -- the system CellBroadcastService provider

**Interesting detail:** When in "testing mode" (activated via secret code `*#*#2627#*#*` or `TESTING_MODE` preference), loader ID 2 shows full debug info including:
- Data coding scheme
- Location check time
- Maximum waiting time
- Whether message was displayed
- Geometry/coordinates strings

This is gated by testing mode however, which requires `ro.debuggable=1` or resource bool `allow_testing_mode_on_user_build`.

**VRP Verdict:** Low severity. The activity shows UI that the user would see through the launcher anyway, and the CursorLoader respects the provider's permission model.

---

## 5. Finding: CellBroadcastReceiver Handles Sensitive Broadcasts Without Sender Verification

### Severity: Medium (Intent Spoofing / Alert Suppression)
### Location: `CellBroadcastReceiver.onReceive()` lines 56-157

The receiver handles the following actions with no explicit caller verification:

```java
"android.provider.action.SMS_EMERGENCY_CB_RECEIVED"
"android.provider.Telephony.SMS_CB_RECEIVED"
"android.provider.Telephony.SMS_SERVICE_CATEGORY_PROGRAM_DATA_RECEIVED"
"com.android.cellbroadcastservice.action.USER_SWITCHED"
```

**Critical analysis:**

For `SMS_CB_RECEIVED` and `SMS_EMERGENCY_CB_RECEIVED`:
- These intents are forwarded directly to `CellBroadcastAlertService` via `startService()`:
  ```java
  intent.setClass(this.mContext, CellBroadcastAlertService.class);
  this.mContext.startService(intent);
  ```
- The service then extracts a `SmsCbMessage` parcelable from the "message" extra

**However**, these broadcast actions are protected by:
1. `android.provider.action.SMS_EMERGENCY_CB_RECEIVED` -- protected by `android.permission.RECEIVE_EMERGENCY_BROADCAST` (signature|privileged), the telephony framework only sends this to privileged receivers
2. `android.provider.Telephony.SMS_CB_RECEIVED` -- similarly protected by the framework
3. `SMS_SERVICE_CATEGORY_PROGRAM_DATA_RECEIVED` -- protected by `RECEIVE_SMS`

The protection is at the **broadcast sender side** (the telephony framework restricts who can send these), not at the receiver side. A third-party app without these permissions cannot send these protected broadcasts.

**For `MARK_AS_READ`:** Line 64 shows this is handled with only an `EventLog.writeEvent` (CVE tracking marker `162741784`) and immediately returns without processing. This was a previously patched vulnerability where arbitrary apps could mark alerts as read.

**For `USER_SWITCHED`:** This resets channel ranges and re-initializes preferences. Any app can send this broadcast:
```
adb shell am broadcast -a com.android.cellbroadcastservice.action.USER_SWITCHED -n com.google.android.cellbroadcastreceiver/com.android.cellbroadcastreceiver.CellBroadcastReceiver
```
This would trigger `resetCellBroadcastChannelRanges()`, `initializeSharedPreference()`, and `startConfigServiceToEnableChannels()`. While not a direct security issue, it causes unnecessary re-initialization.

**VRP Verdict:** The framework-protected broadcasts cannot be spoofed. The USER_SWITCHED action is a minor DoS vector causing unnecessary config service restarts.

---

## 6. Finding: CellBroadcastAlertDialog NOT Exported (Negative Finding)

### Location: AndroidManifest.xml line 67

```xml
<activity android:exported="false" ... android:name="com.android.cellbroadcastreceiver.CellBroadcastAlertDialog">
```

Despite having an intent-filter for `SMS_CB_RECEIVED`, the alert dialog is **not exported**. This means:
- Third-party apps **cannot** directly launch the alert dialog
- The alert flow goes: Framework -> CellBroadcastReceiver (broadcast) -> CellBroadcastAlertService (service) -> CellBroadcastAlertDialog (internal intent)
- The SmsCbMessage parcelable passed via intent extras cannot be spoofed from outside the app

**VRP Verdict:** No vulnerability. Properly not exported.

---

## 7. Finding: No createPackageContext with Dangerous Flags

### Severity: None (Negative Finding)

Searched all decompiled sources for `createPackageContext`, `INCLUDE_CODE`, `IGNORE_SECURITY`, and `Context.CONTEXT_` patterns. **None found.**

The app uses `createConfigurationContext()` in two places (both in `CellBroadcastSettings.getResourcesByOperator()` and `CellBroadcastResources.overrideTranslation()`) but only with `Configuration` objects for locale/MCC/MNC changes -- no package context creation with code loading flags.

**VRP Verdict:** Not vulnerable to this pattern.

---

## 8. Finding: CellBroadcastSearchIndexableProvider Protected but Information Leakage

### Severity: Low
### Location: AndroidManifest.xml line 91

```xml
<provider android:authorities="com.android.cellbroadcastreceiver"
    android:exported="true" android:grantUriPermissions="true"
    android:permission="android.permission.READ_SEARCH_INDEXABLES"
    android:name="com.android.cellbroadcastreceiver.CellBroadcastSearchIndexableProvider">
```

Protected by `android.permission.READ_SEARCH_INDEXABLES` (signature-level permission). The provider only returns:
- XML resource references for settings preferences
- Non-indexable keys (setting key names, not values)
- Raw indexable data (setting titles and keywords)

No sensitive user data is exposed through this provider.

**VRP Verdict:** No vulnerability. Properly protected.

---

## 9. Finding: `call()` Method Allows Legacy Data Migration Trigger

### Severity: Low (permission-gated)
### Location: `CellBroadcastContentProvider.call()` line 141

```java
public Bundle call(String str, String str2, Bundle bundle) {
    Log.d("CellBroadcastContentProvider", "call: method=" + str + " name=" + str2 + " args=" + bundle);
    if (!"migrate-legacy-data".equals(str)) {
        return null;
    }
    this.mOpenHelper.migrateFromLegacyIfNeeded(awaitInitAndGetReadableDatabase());
    return null;
}
```

The `call()` method accepts the "migrate-legacy-data" method name and triggers migration from the legacy content provider (`cellbroadcast-legacy`). However:
- The `call()` method inherits the `readPermission` from the provider declaration (`READ_CELL_BROADCASTS`)
- The migration has a SharedPreferences guard (`legacy_data_migration` flag) preventing re-execution
- All method arguments are logged to logcat (method, name, args bundle)

**VRP Verdict:** Low severity. The logcat logging of the full bundle is a minor info-leak concern but mitigated by logcat access restrictions on modern Android.

---

## 10. Finding: Alert History Contains Cell Location Data (Privacy)

### Severity: Medium (Information Disclosure -- Location History)
### Location: Database schema in `CellBroadcastDatabaseHelper` line 28

The `broadcasts` table stores:
```sql
plmn TEXT, lac INTEGER, cid INTEGER
```

These fields store the PLMN (network operator code), LAC (Location Area Code), and CID (Cell ID) for each received cell broadcast. Combined, these provide coarse-to-fine location data for each emergency alert the user received.

Any app with `READ_CELL_BROADCASTS` permission can query this via the exported `CellBroadcastContentProvider` (authority `cellbroadcasts-app`) and extract a location history tied to emergency broadcast timestamps.

**PoC:**
```
adb shell content query --uri content://cellbroadcasts-app/ --projection "plmn:lac:cid:date:body"
```
(Requires shell UID or an app with READ_CELL_BROADCASTS)

**VRP Verdict:** Medium severity. Cell location data (LAC/CID) persisted alongside timestamps creates a location history accessible to SMS-permission-holding apps. On Pixel devices, this permission is grantable at runtime.

---

## 11. Finding: Lack of setStrict(true) on SQLiteQueryBuilder

### Severity: Low-Medium (SQL Injection via projection/selection when permission-gated)
### Location: `CellBroadcastContentProvider.query()` lines 92-106

The `SQLiteQueryBuilder` used in `query()` never calls `setStrict(true)`. This means:
1. **Projection injection**: A caller can pass arbitrary SQL expressions in the projection array (column names), enabling subquery-based data extraction
2. **Selection injection**: The selection parameter is passed directly without sanitization
3. **Sort order injection**: The sort order parameter is caller-controlled (with only a default fallback for empty/null)

Without `setStrict(true)`, the following attacks are possible from an app with `READ_CELL_BROADCASTS`:

```java
// Projection injection - extract arbitrary data
String[] projection = {"* FROM broadcasts WHERE 1=1 UNION SELECT sql,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21 FROM sqlite_master--"};
Cursor c = resolver.query(uri, projection, null, null, null);
```

Modern Android (API 30+) `SQLiteQueryBuilder` has some built-in protections, but without `setStrict(true)` the protection is incomplete.

**VRP Verdict:** Low-medium. Gated by READ_CELL_BROADCASTS permission, but the lack of strict mode is a defense-in-depth failure.

---

## 12. Finding: MARK_AS_READ EventLog-Only Handler (Previously Patched CVE)

### Severity: Informational (Previously Patched)
### Location: `CellBroadcastReceiver.onReceive()` line 64

```java
if ("com.android.cellbroadcastreceiver.intent.action.MARK_AS_READ".equals(action)) {
    EventLog.writeEvent(1397638484, "162741784", -1, null);
    return;
}
```

The `MARK_AS_READ` action in the exported `CellBroadcastReceiver` is handled by writing an event log entry and immediately returning. The event tag `162741784` corresponds to a previously patched Android vulnerability where third-party apps could mark emergency alerts as read, suppressing them. The current code is a no-op stub that logs the attempt for security monitoring.

The actual mark-as-read functionality is now only in `CellBroadcastInternalReceiver` which is **not exported** (line 90 of manifest).

**VRP Verdict:** Informational. Properly patched, the EventLog call serves as a security monitoring marker.

---

## Summary of Findings

| # | Finding | Severity | VRP-Reportable |
|---|---------|----------|----------------|
| 2 | SQL injection vector in ContentProvider (appendWhere + no setStrict) | Medium-Low | Possibly, if projection injection bypasses modern protections |
| 3 | CellBroadcastSettings exported without permission | Low | Unlikely -- design choice for Settings integration |
| 4 | CellBroadcastListActivity exported without permission | Low | Unlikely -- launcher activity by design |
| 5 | USER_SWITCHED broadcast can be spoofed | Low | Possibly -- causes unnecessary config restarts |
| 6 | CellBroadcastAlertDialog NOT exported | N/A | Negative finding -- properly secured |
| 7 | No createPackageContext with dangerous flags | N/A | Negative finding |
| 8 | SearchIndexableProvider properly protected | N/A | Negative finding |
| 9 | call() method migration trigger | Low | Unlikely |
| 10 | Cell location data (LAC/CID) in alert history | Medium | **Yes** -- location history leak to SMS-perm apps |
| 11 | Missing setStrict(true) on SQLiteQueryBuilder | Low-Medium | **Yes** -- defense-in-depth failure |
| 12 | MARK_AS_READ previously patched | Info | No -- already patched |

### Top VRP Candidates:
1. **Finding #10+#11 combined**: An app with `READ_CELL_BROADCASTS` (SMS group) can query the exported ContentProvider to extract cell location data (PLMN/LAC/CID) constituting a location history, and the lack of `setStrict(true)` on the SQLiteQueryBuilder may enable projection injection to extract additional database metadata.

2. **Finding #5**: The `USER_SWITCHED` custom action can be sent by any app to the exported receiver, triggering full re-initialization of cell broadcast channel configuration, potentially causing temporary disruption to emergency alert reception.
