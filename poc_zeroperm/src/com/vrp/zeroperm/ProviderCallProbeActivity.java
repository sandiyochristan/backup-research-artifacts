package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class ProviderCallProbeActivity extends Activity {
    private static final String T = "PROVCALL";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Provider Call() Bypass Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        testDirectQueries();
        testCallMethods();
        testPartnerSettings();
        testGsfGservices();
        testTelephonyProviders();
        testCredentialManager();
        testPrintSpooler();

        Log.w(T, "=== PROVIDER CALL PROBE COMPLETE ===");
    }

    private void testDirectQueries() {
        Log.w(T, "--- Direct Provider Queries (zero-perm check) ---");

        String[][] queries = {
            {"content://call_log/calls", "Call log"},
            {"content://com.android.contacts/contacts", "Contacts"},
            {"content://com.android.contacts/profile", "Profile"},
            {"content://com.android.calendar/events", "Calendar events"},
            {"content://sms/inbox", "SMS inbox"},
            {"content://com.android.contacts/data/emails", "Contact emails"},
            {"content://com.android.contacts/data/phones", "Contact phones"},
        };

        ContentResolver cr = getContentResolver();
        for (String[] q : queries) {
            try {
                Cursor c = cr.query(Uri.parse(q[0]), null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    if (count > 0) {
                        Log.w(T, "[!!!] " + q[1] + ": " + count + " rows ACCESSIBLE from zero-perm!");
                        c.moveToFirst();
                        String[] cols = c.getColumnNames();
                        for (int i = 0; i < Math.min(cols.length, 5); i++) {
                            try {
                                String val = c.getString(i);
                                if (val != null && val.length() > 0) {
                                    Log.w(T, "  " + cols[i] + "=" + val.substring(0, Math.min(val.length(), 80)));
                                }
                            } catch (Exception ex) {}
                        }
                    } else {
                        Log.w(T, "[.] " + q[1] + ": 0 rows");
                    }
                    c.close();
                } else {
                    Log.w(T, "[-] " + q[1] + ": null cursor");
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + q[1] + " SECURITY: " + shortMsg(se));
            } catch (Exception e) {
                Log.w(T, "[-] " + q[1] + ": " + e.getClass().getSimpleName() + ": " + shortMsg(e));
            }
        }
    }

    private void testCallMethods() {
        Log.w(T, "--- Provider call() Method Attacks ---");
        ContentResolver cr = getContentResolver();

        Object[][] callTests = {
            {"content://call_log/calls", "get_last_outgoing_call", null, "Call log last outgoing"},
            {"content://com.android.contacts/contacts", "search_suggestion_query", "test", "Contacts search"},
            {"content://com.android.contacts/contacts", "get_multiple_sim_accounts", null, "SIM accounts"},
            {"content://com.android.contacts/profile", "get_sim_accounts", null, "Profile SIM"},
            {"content://com.android.calendar/events", "CalendarAlerts", null, "Calendar alerts"},
            {"content://com.android.providers.contacts/contacts", "search_suggestion_query", "a", "Contacts search2"},
            {"content://telephony/siminfo", "get_active_sim", null, "Active SIM info"},
            {"content://settings/system", "GET_system", "device_name", "Device name"},
            {"content://settings/global", "GET_global", "device_name", "Device name global"},
            {"content://settings/secure", "GET_secure", "android_id", "Android ID"},
            {"content://settings/secure", "GET_secure", "bluetooth_name", "BT name"},
            {"content://settings/secure", "GET_secure", "lock_screen_owner_info", "Lock screen info"},
        };

        for (Object[] test : callTests) {
            String uri = (String) test[0];
            String method = (String) test[1];
            String arg = (String) test[2];
            String label = (String) test[3];

            try {
                Bundle result = cr.call(Uri.parse(uri), method, arg, null);
                if (result != null && !result.isEmpty()) {
                    Log.w(T, "[!!!] " + label + " call() returned data!");
                    for (String key : result.keySet()) {
                        Object val = result.get(key);
                        if (val != null) {
                            String valStr = val.toString();
                            Log.w(T, "  " + key + "=" + valStr.substring(0, Math.min(valStr.length(), 150)));
                        }
                    }
                } else {
                    Log.w(T, "[.] " + label + ": empty result");
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + label + " SECURITY: " + shortMsg(se));
            } catch (Exception e) {
                Log.w(T, "[-] " + label + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testPartnerSettings() {
        Log.w(T, "--- Google Partner Settings ---");
        ContentResolver cr = getContentResolver();

        try {
            Cursor c = cr.query(Uri.parse("content://com.google.settings/partner"),
                null, null, null, null);
            if (c != null) {
                Log.w(T, "[+] Partner settings: " + c.getCount() + " rows");
                while (c.moveToNext()) {
                    try {
                        String name = c.getString(c.getColumnIndex("name"));
                        String value = c.getString(c.getColumnIndex("value"));
                        Log.w(T, "  " + name + "=" + (value != null ? value.substring(0, Math.min(value.length(), 100)) : "null"));
                    } catch (Exception ex) {}
                }
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] Partner settings: " + e.getClass().getSimpleName());
        }
    }

    private void testGsfGservices() {
        Log.w(T, "--- GSF GServices ---");
        ContentResolver cr = getContentResolver();

        String[] gserviceKeys = {
            "android_id", "device_country", "checkin_device_id",
            "gmail_account_id", "logging_id2", "gms_debug",
        };

        for (String key : gserviceKeys) {
            try {
                Cursor c = cr.query(
                    Uri.parse("content://com.google.android.gsf.gservices"),
                    null, null, new String[]{key}, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(1);
                    Log.w(T, "[!!!] GServices " + key + "=" + (val != null ? val : "null"));
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] GServices " + key + " SECURITY");
            } catch (Exception e) {
                Log.w(T, "[-] GServices " + key + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testTelephonyProviders() {
        Log.w(T, "--- Telephony Providers ---");
        ContentResolver cr = getContentResolver();

        String[][] telQueries = {
            {"content://telephony/siminfo", "SIM info"},
            {"content://telephony/carriers/current", "Current carrier"},
            {"content://telephony/cellbroadcasts", "Cell broadcasts"},
        };

        for (String[] q : telQueries) {
            try {
                Cursor c = cr.query(Uri.parse(q[0]), null, null, null, null);
                if (c != null) {
                    Log.w(T, "[!!!] " + q[1] + ": " + c.getCount() + " rows");
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        String[] cols = c.getColumnNames();
                        StringBuilder sb = new StringBuilder();
                        for (String col : cols) sb.append(col).append(",");
                        Log.w(T, "  cols: " + sb.toString().substring(0, Math.min(sb.length(), 200)));
                    }
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + q[1] + " SECURITY: " + shortMsg(se));
            } catch (Exception e) {
                Log.w(T, "[-] " + q[1] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testCredentialManager() {
        Log.w(T, "--- Credential Manager ---");
        ContentResolver cr = getContentResolver();

        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.apps.credentialmanager/credentials"),
                null, null, null, null);
            if (c != null) {
                Log.w(T, "[!!!] CredentialManager: " + c.getCount() + " credentials!");
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] CredentialManager: " + e.getClass().getSimpleName());
        }

        try {
            android.accounts.AccountManager am = android.accounts.AccountManager.get(this);
            android.accounts.Account[] accounts = am.getAccounts();
            Log.w(T, "[*] AccountManager.getAccounts(): " + accounts.length);
            for (android.accounts.Account acc : accounts) {
                Log.w(T, "[!!!] Account: " + acc.name + " type=" + acc.type);
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] AccountManager SECURITY: " + shortMsg(se));
        } catch (Exception e) {
            Log.w(T, "[-] AccountManager: " + e.getClass().getSimpleName());
        }

        try {
            android.accounts.AccountManager am = android.accounts.AccountManager.get(this);
            android.accounts.Account[] gAccounts = am.getAccountsByType("com.google");
            Log.w(T, "[*] Google accounts: " + gAccounts.length);
            for (android.accounts.Account acc : gAccounts) {
                Log.w(T, "[!!!] Google Account: " + acc.name);
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] Google accounts SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] Google accounts: " + e.getClass().getSimpleName());
        }
    }

    private void testPrintSpooler() {
        Log.w(T, "--- Print/Misc Providers ---");
        ContentResolver cr = getContentResolver();

        try {
            Cursor c = cr.query(
                Uri.parse("content://com.android.printspooler/print_jobs"),
                null, null, null, null);
            if (c != null) {
                Log.w(T, "[!!!] Print jobs: " + c.getCount());
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] Print spooler: " + e.getClass().getSimpleName());
        }

        try {
            android.app.usage.StorageStatsManager ssm = (android.app.usage.StorageStatsManager)
                getSystemService("storagestats");
            java.util.UUID uuid = android.os.storage.StorageManager.UUID_DEFAULT;
            android.app.usage.StorageStats stats = ssm.queryStatsForPackage(
                uuid, "com.google.android.gms", android.os.Process.myUserHandle());
            Log.w(T, "[!!!] GMS storage: app=" + stats.getAppBytes() +
                " data=" + stats.getDataBytes() + " cache=" + stats.getCacheBytes());
        } catch (SecurityException se) {
            Log.w(T, "[-] StorageStats SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] StorageStats: " + e.getClass().getSimpleName());
        }
    }

    private String shortMsg(Exception e) {
        String msg = e.getMessage();
        if (msg == null) return "";
        return msg.substring(0, Math.min(msg.length(), 120));
    }
}
