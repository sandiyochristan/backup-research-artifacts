package com.vrp.zeroperm;

import android.app.Activity;
import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.ContentResolver;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import java.util.List;

public class SysProbe3Activity extends Activity {
    private static final String T = "SYS_PROBE3";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== System Probe v3 — Permission Gap Hunter ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        probeAccounts();
        probeUsageStats();
        probeSettings();
        probeSystemProviders();
        probeTelephony();
        probePackageInfo();

        Log.w(T, "=== Probe complete ===");
    }

    private void probeAccounts() {
        try {
            AccountManager am = AccountManager.get(this);
            Account[] accounts = am.getAccounts();
            Log.w(T, "[ACCOUNTS] getAccounts(): " + accounts.length + " accounts");
            for (Account a : accounts) {
                Log.w(T, "[!!!] ACCOUNT: name=" + a.name + " type=" + a.type);
            }
        } catch (Exception e) {
            Log.w(T, "[-] getAccounts failed: " + e.getMessage());
        }

        try {
            AccountManager am = AccountManager.get(this);
            Account[] accounts = am.getAccountsByType("com.google");
            Log.w(T, "[ACCOUNTS] getAccountsByType(google): " + accounts.length);
            for (Account a : accounts) {
                Log.w(T, "[!!!] GOOGLE ACCOUNT: " + a.name);
            }
        } catch (Exception e) {
            Log.w(T, "[-] getAccountsByType failed: " + e.getMessage());
        }
    }

    private void probeUsageStats() {
        try {
            UsageStatsManager usm = (UsageStatsManager) getSystemService("usagestats");
            long now = System.currentTimeMillis();
            List<UsageStats> stats = usm.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY, now - 86400000, now);
            if (stats != null && !stats.isEmpty()) {
                Log.w(T, "[!!!] USAGE_STATS: " + stats.size() + " entries!");
                for (int i = 0; i < Math.min(5, stats.size()); i++) {
                    UsageStats s = stats.get(i);
                    Log.w(T, "[!!!] APP: " + s.getPackageName() +
                        " lastUsed=" + s.getLastTimeUsed() +
                        " totalFg=" + s.getTotalTimeInForeground());
                }
            } else {
                Log.w(T, "[-] USAGE_STATS: empty/null (permission denied)");
            }
        } catch (Exception e) {
            Log.w(T, "[-] UsageStats error: " + e.getMessage());
        }
    }

    private void probeSettings() {
        String[] secureKeys = {
            "android_id", "bluetooth_address", "lock_screen_owner_info",
            "enabled_accessibility_services", "enabled_notification_listeners",
            "default_input_method", "selected_input_method_subtype",
            "mock_location", "install_non_market_apps",
            "location_providers_allowed", "device_name"
        };
        for (String key : secureKeys) {
            try {
                String val = Settings.Secure.getString(getContentResolver(), key);
                if (val != null && !val.isEmpty()) {
                    Log.w(T, "[SETTINGS.SECURE] " + key + "=" + val);
                }
            } catch (Exception e) {}
        }

        String[] globalKeys = {
            "device_name", "wifi_on", "bluetooth_on", "airplane_mode_on",
            "mobile_data", "data_roaming", "adb_enabled",
            "development_settings_enabled", "package_verifier_enable",
            "wifi_networks_available_notification_on"
        };
        for (String key : globalKeys) {
            try {
                String val = Settings.Global.getString(getContentResolver(), key);
                if (val != null && !val.isEmpty()) {
                    Log.w(T, "[SETTINGS.GLOBAL] " + key + "=" + val);
                }
            } catch (Exception e) {}
        }
    }

    private void probeSystemProviders() {
        String[][] uris = {
            {"content://com.android.contacts/profile", "display_name"},
            {"content://com.android.contacts/contacts", "_id"},
            {"content://call_log/calls", "_id,number,date"},
            {"content://sms", "_id,address,body"},
            {"content://mms", "_id"},
            {"content://com.android.calendar/events", "_id,title"},
            {"content://com.android.calendar/calendars", "_id,name"},
            {"content://user_dictionary/words", "_id,word"},
            {"content://com.android.browser/bookmarks", "_id,title"},
            {"content://downloads/all_downloads", "_id"},
            {"content://com.android.providers.downloads.documents/root", "_id"},
            {"content://com.google.android.gms.phenotype/", "_id"},
        };

        for (String[] entry : uris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(entry[0]),
                    null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    if (count > 0) {
                        Log.w(T, "[!!!] PROVIDER " + entry[0] + ": " + count + " rows!");
                        if (c.moveToFirst()) {
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < Math.min(5, c.getColumnCount()); i++) {
                                if (i > 0) sb.append(", ");
                                sb.append(c.getColumnName(i) + "=" + c.getString(i));
                            }
                            Log.w(T, "[!!!] ROW: " + sb.toString());
                        }
                    } else {
                        Log.w(T, "[*] " + entry[0] + ": 0 rows");
                    }
                    c.close();
                }
            } catch (Exception e) {
                Log.w(T, "[-] " + entry[0] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void probeTelephony() {
        try {
            android.telephony.TelephonyManager tm =
                (android.telephony.TelephonyManager) getSystemService(TELEPHONY_SERVICE);

            try {
                String networkOp = tm.getNetworkOperatorName();
                Log.w(T, "[TELEPHONY] networkOperatorName=" + networkOp);
            } catch (Exception e) {}

            try {
                String simOp = tm.getSimOperatorName();
                Log.w(T, "[TELEPHONY] simOperatorName=" + simOp);
            } catch (Exception e) {}

            try {
                String networkCountry = tm.getNetworkCountryIso();
                Log.w(T, "[TELEPHONY] networkCountryIso=" + networkCountry);
            } catch (Exception e) {}

            try {
                int phoneType = tm.getPhoneType();
                Log.w(T, "[TELEPHONY] phoneType=" + phoneType);
            } catch (Exception e) {}

            try {
                int simState = tm.getSimState();
                Log.w(T, "[TELEPHONY] simState=" + simState);
            } catch (Exception e) {}

            try {
                String mccmnc = tm.getNetworkOperator();
                Log.w(T, "[TELEPHONY] networkOperator(MCC+MNC)=" + mccmnc);
            } catch (Exception e) {}

            try {
                String line1 = tm.getLine1Number();
                if (line1 != null && !line1.isEmpty()) {
                    Log.w(T, "[!!!] PHONE NUMBER: " + line1);
                }
            } catch (Exception e) {
                Log.w(T, "[-] getLine1Number: " + e.getMessage());
            }

            try {
                String subId = tm.getSubscriberId();
                if (subId != null) {
                    Log.w(T, "[!!!] SUBSCRIBER ID (IMSI): " + subId);
                }
            } catch (Exception e) {
                Log.w(T, "[-] getSubscriberId: " + e.getMessage());
            }
        } catch (Exception e) {
            Log.w(T, "[-] TelephonyManager error: " + e.getMessage());
        }
    }

    private void probePackageInfo() {
        try {
            PackageManager pm = getPackageManager();
            PackageInfo pi = pm.getPackageInfo("com.google.android.gms",
                PackageManager.GET_PERMISSIONS);
            if (pi.requestedPermissions != null) {
                Log.w(T, "[PKG] GMS permissions: " + pi.requestedPermissions.length);
                int dangerous = 0;
                for (String p : pi.requestedPermissions) {
                    try {
                        int protLevel = pm.getPermissionInfo(p, 0).protectionLevel;
                        if ((protLevel & 1) != 0) dangerous++;
                    } catch (Exception e) {}
                }
                Log.w(T, "[PKG] GMS dangerous perms: " + dangerous);
            }
        } catch (Exception e) {
            Log.w(T, "[-] PackageInfo error: " + e.getMessage());
        }
    }
}
