package com.vrp.zeroperm;

import android.app.Activity;
import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.ContentResolver;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;

public class SystemInfoProbeActivity extends Activity {
    private static final String T = "SYSPROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== System Info Probe — Zero Permission ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());

        probeAccounts();
        probeSettings();
        probeProviders();
        probeSystemProperties();

        Log.w(T, "=== PROBE COMPLETE ===");
    }

    private void probeAccounts() {
        Log.w(T, "--- Account Enumeration ---");
        try {
            AccountManager am = AccountManager.get(this);
            Account[] all = am.getAccounts();
            Log.w(T, "getAccounts(): " + all.length);
            for (Account a : all) {
                Log.w(T, "[!!!] ACCOUNT: type=" + a.type + " name=" + a.name);
            }

            Account[] google = am.getAccountsByType("com.google");
            Log.w(T, "getAccountsByType(com.google): " + google.length);
            for (Account a : google) {
                Log.w(T, "[!!!] GOOGLE ACCOUNT: " + a.name);
            }

            String[] types = {"com.google", "com.google.android.gms", "com.google.android.gm.exchange",
                              "com.android.email", "com.google.work", "com.google.android.legacyimsp",
                              "com.samsung.account"};
            for (String type : types) {
                Account[] accts = am.getAccountsByType(type);
                if (accts.length > 0) {
                    Log.w(T, "[!!!] " + type + " => " + accts.length + " accounts");
                    for (Account a : accts) {
                        Log.w(T, "  [!!!] " + a.name);
                    }
                }
            }
        } catch (SecurityException e) {
            Log.w(T, "AccountManager SECURITY: " + trunc(e.getMessage(), 100));
        } catch (Exception e) {
            Log.w(T, "AccountManager err: " + trunc(e.getMessage(), 100));
        }
    }

    private void probeSettings() {
        Log.w(T, "--- Settings Probe ---");
        ContentResolver cr = getContentResolver();

        String[] secureKeys = {
            "android_id", "bluetooth_address", "bluetooth_name",
            "lock_screen_owner_info", "lock_screen_owner_info_enabled",
            "enabled_notification_listeners", "enabled_accessibility_services",
            "default_input_method", "assistant", "voice_interaction_service",
            "device_name", "user_setup_complete", "install_non_market_apps"
        };

        for (String key : secureKeys) {
            try {
                String val = Settings.Secure.getString(cr, key);
                if (val != null && val.length() > 0) {
                    Log.w(T, "Secure." + key + " = " + trunc(val, 200));
                    if (key.equals("bluetooth_address") || key.equals("bluetooth_name") ||
                        key.equals("lock_screen_owner_info") || key.equals("enabled_notification_listeners")) {
                        Log.w(T, "[!!!] SENSITIVE: " + key + " = " + val);
                    }
                }
            } catch (Exception e) {}
        }

        String[] globalKeys = {
            "device_name", "airplane_mode_on", "wifi_on",
            "bluetooth_on", "mobile_data", "data_roaming",
            "adb_enabled", "development_settings_enabled",
            "package_verifier_enable", "install_non_market_apps"
        };

        for (String key : globalKeys) {
            try {
                String val = Settings.Global.getString(cr, key);
                if (val != null && val.length() > 0) {
                    Log.w(T, "Global." + key + " = " + val);
                    if (key.equals("device_name") || key.equals("adb_enabled") ||
                        key.equals("development_settings_enabled")) {
                        Log.w(T, "[!!!] DEVICE INFO: " + key + " = " + val);
                    }
                }
            } catch (Exception e) {}
        }
    }

    private void probeProviders() {
        Log.w(T, "--- ContentProvider Probe ---");
        ContentResolver cr = getContentResolver();

        Object[][] uris = {
            {"contacts_profile", "content://com.android.contacts/profile"},
            {"contacts_profile_data", "content://com.android.contacts/profile/data"},
            {"call_log", "content://call_log/calls"},
            {"sms", "content://sms"},
            {"mms", "content://mms"},
            {"telephony_carriers", "content://telephony/carriers"},
            {"media_external", "content://media/external/file"},
            {"downloads", "content://downloads/my_downloads"},
            {"calendar_events", "content://com.android.calendar/events"},
            {"calendar_calendars", "content://com.android.calendar/calendars"},
            {"gmail_conversations", "content://com.google.android.gm/conversations"},
            {"gmail_labels", "content://com.google.android.gm/labels"},
            {"gm_email", "content://com.google.android.gm.email.provider/account"},
            {"gms_people", "content://com.google.android.gms.people/contacts"},
            {"gms_auth", "content://com.google.android.gsf.gservices"},
            {"gsf_id", "content://com.google.android.gsf.gservices/prefix/android_id"},
            {"wellbeing_events", "content://com.google.android.apps.wellbeing.provider/events"},
            {"launcher_favorites", "content://com.google.android.apps.nexuslauncher.settings/favorites"},
        };

        for (Object[] entry : uris) {
            String label = (String) entry[0];
            String uri = (String) entry[1];
            try {
                Cursor c = cr.query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    String[] cols = c.getColumnNames();
                    Log.w(T, "[!!!] " + label + " ACCESSIBLE: " + count + " rows, cols=" + join(cols));
                    if (count > 0 && c.moveToFirst()) {
                        for (int i = 0; i < Math.min(cols.length, 10); i++) {
                            try {
                                String val = c.getString(i);
                                if (val != null && val.length() > 0) {
                                    Log.w(T, "  [!!!] " + cols[i] + " = " + trunc(val, 150));
                                }
                            } catch (Exception e) {}
                        }
                    }
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + label + " SECURITY: " + trunc(se.getMessage(), 80));
            } catch (Exception e) {
                Log.w(T, "[-] " + label + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void probeSystemProperties() {
        Log.w(T, "--- System Properties ---");

        Log.w(T, "Build.SERIAL=" + Build.SERIAL);
        Log.w(T, "Build.DEVICE=" + Build.DEVICE);
        Log.w(T, "Build.MODEL=" + Build.MODEL);
        Log.w(T, "Build.MANUFACTURER=" + Build.MANUFACTURER);
        Log.w(T, "Build.FINGERPRINT=" + Build.FINGERPRINT);
        Log.w(T, "Build.DISPLAY=" + Build.DISPLAY);
        Log.w(T, "Build.VERSION.SDK_INT=" + Build.VERSION.SDK_INT);
        Log.w(T, "Build.VERSION.SECURITY_PATCH=" + Build.VERSION.SECURITY_PATCH);

        try {
            PackageManager pm = getPackageManager();
            for (PackageInfo pi : pm.getInstalledPackages(0)) {
                if (pi.packageName.startsWith("com.google.android.apps.") ||
                    pi.packageName.equals("com.google.android.gm") ||
                    pi.packageName.equals("com.google.android.youtube")) {
                    // Just count, don't spam
                }
            }
            Log.w(T, "Installed packages visible: " + pm.getInstalledPackages(0).size());
        } catch (Exception e) {}

        try {
            android.telephony.TelephonyManager tm = (android.telephony.TelephonyManager) getSystemService(TELEPHONY_SERVICE);
            Log.w(T, "NetworkOperator=" + tm.getNetworkOperator());
            Log.w(T, "NetworkOperatorName=" + tm.getNetworkOperatorName());
            Log.w(T, "SimOperator=" + tm.getSimOperator());
            Log.w(T, "SimOperatorName=" + tm.getSimOperatorName());
            Log.w(T, "PhoneType=" + tm.getPhoneType());
            try {
                String imei = tm.getImei();
                if (imei != null) Log.w(T, "[!!!] IMEI LEAKED: " + imei);
            } catch (SecurityException e) {
                Log.w(T, "IMEI: requires READ_PHONE_STATE");
            }
            try {
                String sub = tm.getSubscriberId();
                if (sub != null) Log.w(T, "[!!!] IMSI LEAKED: " + sub);
            } catch (SecurityException e) {}
            try {
                String line = tm.getLine1Number();
                if (line != null && line.length() > 0) Log.w(T, "[!!!] PHONE NUMBER LEAKED: " + line);
            } catch (SecurityException e) {}
        } catch (Exception e) {
            Log.w(T, "TelephonyManager err: " + trunc(e.getMessage(), 100));
        }

        try {
            android.net.wifi.WifiManager wm = (android.net.wifi.WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
            android.net.wifi.WifiInfo wi = wm.getConnectionInfo();
            if (wi != null) {
                Log.w(T, "WiFi SSID=" + wi.getSSID());
                Log.w(T, "WiFi BSSID=" + wi.getBSSID());
                String mac = wi.getMacAddress();
                if (mac != null && !mac.equals("02:00:00:00:00:00")) {
                    Log.w(T, "[!!!] REAL MAC LEAKED: " + mac);
                }
            }
        } catch (Exception e) {}
    }

    private String join(String[] arr) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(arr.length, 10); i++) {
            if (i > 0) sb.append(",");
            sb.append(arr[i]);
        }
        if (arr.length > 10) sb.append("...(+" + (arr.length - 10) + ")");
        return sb.toString();
    }

    private String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
