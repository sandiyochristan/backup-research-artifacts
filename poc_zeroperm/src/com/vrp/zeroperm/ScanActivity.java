package com.vrp.zeroperm;

import android.app.Activity;
import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.provider.Settings;
import android.util.Log;

public class ScanActivity extends Activity {
    private static final String T = "ZEROPERM";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== ZERO-PERMISSION VULNERABILITY SCANNER ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " PID=" + android.os.Process.myPid());

        new Thread(new Runnable() {
            public void run() {
                testContentProviders();
                testAccountManager();
                testSettingsProvider();
                testGmsServices();
                testDirectContentUris();
                Log.w(T, "=== SCAN COMPLETE ===");
            }
        }).start();
    }

    private void testContentProviders() {
        Log.w(T, "--- CONTENT PROVIDER SCAN ---");
        ContentResolver cr = getContentResolver();

        String[][] providers = {
            {"content://com.google.android.gms.phenotype/", "Phenotype flags"},
            {"content://com.google.android.gms.chimera/", "Chimera modules"},
            {"content://com.google.android.gsf.gservices", "GServices"},
            {"content://com.google.android.gsf.gservices/prefix", "GServices prefix"},
            {"content://com.google.settings/partner", "Partner settings"},
            {"content://com.google.android.gms.icing.INDEX_CORPUS_PROVIDER/", "Icing search index"},
            {"content://com.google.android.gms.auth.accounts/", "GMS auth accounts"},
            {"content://com.google.android.gms.people/", "People/contacts"},
            {"content://com.google.android.gms.fonts", "GMS fonts"},
            {"content://com.google.android.gms.auth.api.credentials/", "Credentials API"},
            {"content://com.google.android.apps.docs.storage/", "Drive storage"},
            {"content://com.google.android.apps.docs.storage/document", "Drive documents"},
            {"content://com.google.android.apps.photos.contentprovider/", "Photos provider"},
            {"content://com.google.android.apps.messaging/", "Messages provider"},
            {"content://com.android.providers.contacts/contacts", "System contacts"},
            {"content://com.android.calendar/events", "Calendar events"},
            {"content://com.android.providers.media.documents/root", "Media documents"},
            {"content://com.google.android.dialer/", "Dialer provider"},
            {"content://com.google.android.apps.wellbeing/", "Wellbeing provider"},
            {"content://com.google.android.as/", "Device Personalization"},
            {"content://com.google.android.gms.nearby.exposurenotification/", "Exposure notifications"},
            {"content://com.google.android.gms.tapandpay/", "Tap and pay"},
            {"content://com.google.android.gms.car/", "Android Auto"},
            {"content://com.google.android.apps.turbo/", "Battery stats"},
            {"content://com.android.vending/", "Play Store"},
            {"content://com.android.vending/updates", "Play Store updates"},
        };

        for (String[] p : providers) {
            try {
                Cursor c = cr.query(Uri.parse(p[0]), null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    String[] cols = c.getColumnNames();
                    Log.w(T, "ACCESSIBLE: " + p[1] + " (" + p[0] + ") rows=" + count + " cols=" + java.util.Arrays.toString(cols));
                    if (count > 0 && c.moveToFirst()) {
                        for (int i = 0; i < Math.min(3, count); i++) {
                            StringBuilder row = new StringBuilder("  ROW " + i + ": ");
                            for (int j = 0; j < Math.min(cols.length, 5); j++) {
                                try {
                                    row.append(cols[j]).append("=").append(c.getString(j)).append(" | ");
                                } catch (Exception ex) {
                                    row.append(cols[j]).append("=<blob> | ");
                                }
                            }
                            Log.w(T, row.toString());
                            if (!c.moveToNext()) break;
                        }
                    }
                    c.close();
                } else {
                    Log.d(T, "NULL: " + p[1]);
                }
            } catch (SecurityException se) {
                Log.d(T, "DENIED: " + p[1] + " - " + se.getMessage().substring(0, Math.min(80, se.getMessage().length())));
            } catch (Exception e) {
                Log.d(T, "ERROR: " + p[1] + " - " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        // Test call() method on providers
        Log.w(T, "--- CALL() METHOD TESTS ---");
        String[][] callTests = {
            {"content://com.google.android.gms.phenotype", "register", "com.google.android.gms"},
            {"content://com.google.android.gsf.gservices", "getAndroidId", null},
            {"content://com.google.settings/partner", "get_value", "use_location_for_services"},
            {"content://com.google.android.gms.auth.accounts", "getAccounts", null},
            {"content://com.google.android.gms.fonts", "getFont", null},
        };

        for (String[] ct : callTests) {
            try {
                Bundle result = cr.call(Uri.parse(ct[0]), ct[1], ct[2], null);
                if (result != null) {
                    Log.w(T, "CALL SUCCESS: " + ct[0] + "#" + ct[1] + " keys=" + result.keySet());
                    for (String key : result.keySet()) {
                        Object val = result.get(key);
                        Log.w(T, "  " + key + "=" + (val != null ? val.toString().substring(0, Math.min(100, val.toString().length())) : "null"));
                    }
                }
            } catch (SecurityException se) {
                Log.d(T, "CALL DENIED: " + ct[0] + "#" + ct[1]);
            } catch (Exception e) {
                Log.d(T, "CALL ERROR: " + ct[0] + "#" + ct[1] + " - " + e.getClass().getSimpleName());
            }
        }
    }

    private void testAccountManager() {
        Log.w(T, "--- ACCOUNT MANAGER TESTS ---");
        try {
            AccountManager am = AccountManager.get(this);
            Account[] accounts = am.getAccounts();
            Log.w(T, "getAccounts() returned " + accounts.length + " accounts");
            for (Account a : accounts) {
                Log.w(T, "  Account: " + a.name + " type=" + a.type);
            }

            Account[] googleAccounts = am.getAccountsByType("com.google");
            Log.w(T, "Google accounts: " + googleAccounts.length);
            for (Account a : googleAccounts) {
                Log.w(T, "  Google: " + a.name);
                // Try to peek at auth token
                try {
                    String token = am.peekAuthToken(a, "oauth2:email");
                    Log.w(T, "  peekAuthToken(oauth2:email)=" + (token != null ? "TOKEN_FOUND:" + token.substring(0, Math.min(20, token.length())) : "null"));
                } catch (Exception e) {
                    Log.d(T, "  peekAuthToken failed: " + e.getMessage());
                }
                // Try getUserData
                try {
                    String ud = am.getUserData(a, "SID");
                    Log.w(T, "  getUserData(SID)=" + ud);
                } catch (Exception e) {
                    Log.d(T, "  getUserData failed: " + e.getMessage());
                }
            }
        } catch (SecurityException se) {
            Log.d(T, "AccountManager DENIED: " + se.getMessage());
        } catch (Exception e) {
            Log.d(T, "AccountManager ERROR: " + e.getMessage());
        }
    }

    private void testSettingsProvider() {
        Log.w(T, "--- SETTINGS PROVIDER (SENSITIVE VALUES) ---");
        ContentResolver cr = getContentResolver();

        String[] secureKeys = {
            "android_id", "bluetooth_address", "bluetooth_name",
            "lock_screen_owner_info", "lock_screen_owner_info_enabled",
            "enabled_accessibility_services", "enabled_notification_listeners",
            "default_input_method", "selected_spell_checker",
            "last_setup_shown", "user_setup_complete",
            "location_providers_allowed", "mock_location",
            "install_non_market_apps", "adb_enabled",
            "development_settings_enabled", "wifi_on",
        };

        for (String key : secureKeys) {
            try {
                String val = Settings.Secure.getString(cr, key);
                if (val != null && !val.isEmpty()) {
                    Log.w(T, "Settings.Secure." + key + "=" + val);
                }
            } catch (Exception e) {}
        }

        String[] globalKeys = {
            "device_name", "wifi_networks_available_notification_on",
            "airplane_mode_on", "mobile_data", "data_roaming",
            "usb_mass_storage_enabled", "stay_on_while_plugged_in",
        };

        for (String key : globalKeys) {
            try {
                String val = Settings.Global.getString(cr, key);
                if (val != null && !val.isEmpty()) {
                    Log.w(T, "Settings.Global." + key + "=" + val);
                }
            } catch (Exception e) {}
        }
    }

    private void testGmsServices() {
        Log.w(T, "--- GMS SERVICE BINDING TESTS ---");
        String[][] services = {
            {"com.google.android.gms", "com.google.android.gms.people.service.START"},
            {"com.google.android.gms", "com.google.android.gms.auth.service.START"},
            {"com.google.android.gms", "com.google.android.gms.auth.api.credentials.service.START"},
            {"com.google.android.gms", "com.google.android.gms.drive.ApiService.START"},
            {"com.google.android.gms", "com.google.android.gms.backup.BackupTransportService"},
            {"com.google.android.gms", "com.google.android.gms.auth.api.phone.service.SmsRetrieverApiService"},
            {"com.google.android.gms", "com.google.android.gms.location.internal.EXTRA_LOCATION_PROVIDER"},
            {"com.google.android.gms", "com.google.android.gms.nearby.connection.SERVICE"},
            {"com.google.android.gms", "com.google.android.gms.wallet.service.BIND"},
            {"com.google.android.gms", "com.google.android.gms.fitness.GoogleFitnessService.START"},
        };

        for (String[] svc : services) {
            try {
                Intent intent = new Intent(svc[1]);
                intent.setPackage(svc[0]);
                boolean bound = bindService(intent, new ServiceConnection() {
                    @Override
                    public void onServiceConnected(ComponentName name, IBinder service) {
                        Log.w(T, "BOUND: " + name.flattenToString() + " binder=" + service.getClass().getName());
                        // Dump the binder interface descriptor
                        try {
                            String desc = service.getInterfaceDescriptor();
                            Log.w(T, "  InterfaceDescriptor=" + desc);
                        } catch (Exception e) {
                            Log.w(T, "  No descriptor: " + e.getMessage());
                        }
                        unbindService(this);
                    }
                    @Override
                    public void onServiceDisconnected(ComponentName name) {}
                }, Context.BIND_AUTO_CREATE);
                Log.d(T, "bindService(" + svc[1] + ")=" + bound);
            } catch (SecurityException se) {
                Log.d(T, "BIND DENIED: " + svc[1]);
            } catch (Exception e) {
                Log.d(T, "BIND ERROR: " + svc[1] + " - " + e.getMessage());
            }
        }
    }

    private void testDirectContentUris() {
        Log.w(T, "--- DIRECT CONTENT URI TESTS ---");
        ContentResolver cr = getContentResolver();

        // Try file-based access through content providers
        String[] fileUris = {
            "content://com.google.android.gms.chimera/module/com.google.android.gms.growth",
            "content://com.google.android.apps.photos.contentprovider/0/1/mediakey",
            "content://com.google.android.apps.docs.storage/document/root",
        };

        for (String uri : fileUris) {
            try {
                android.os.ParcelFileDescriptor pfd = cr.openFileDescriptor(Uri.parse(uri), "r");
                if (pfd != null) {
                    Log.w(T, "FILE OPENED: " + uri + " fd=" + pfd.getFd() + " size=" + pfd.getStatSize());
                    pfd.close();
                }
            } catch (SecurityException se) {
                Log.d(T, "FILE DENIED: " + uri);
            } catch (Exception e) {
                Log.d(T, "FILE ERROR: " + uri + " - " + e.getClass().getSimpleName());
            }
        }

        // Try to get a cursor from specific content URIs that might not need permissions
        String[][] specialUris = {
            {"content://com.google.android.gms.phenotype/com.google.android.gms.growth", "Growth phenotype flags"},
            {"content://com.google.android.gms.phenotype/com.google.android.gms", "GMS phenotype flags"},
            {"content://com.google.android.gms.phenotype/com.google.android.apps.photos", "Photos phenotype flags"},
            {"content://com.google.android.gms.auth.login/", "Auth login"},
            {"content://com.android.providers.contacts/profile", "User profile"},
            {"content://com.android.providers.contacts/profile/data", "User profile data"},
            {"content://call_log/calls", "Call log"},
            {"content://sms", "SMS messages"},
            {"content://com.android.externalstorage.documents/root", "External storage"},
        };

        for (String[] su : specialUris) {
            try {
                Cursor c = cr.query(Uri.parse(su[0]), null, null, null, null);
                if (c != null) {
                    Log.w(T, "ACCESSIBLE: " + su[1] + " rows=" + c.getCount() + " cols=" + java.util.Arrays.toString(c.getColumnNames()));
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        StringBuilder row = new StringBuilder("  SAMPLE: ");
                        String[] cols = c.getColumnNames();
                        for (int j = 0; j < Math.min(cols.length, 6); j++) {
                            try {
                                String val = c.getString(j);
                                row.append(cols[j]).append("=").append(val != null ? val.substring(0, Math.min(50, val.length())) : "null").append(" | ");
                            } catch (Exception ex) {
                                row.append(cols[j]).append("=<blob> | ");
                            }
                        }
                        Log.w(T, row.toString());
                    }
                    c.close();
                }
            } catch (SecurityException se) {
                Log.d(T, "DENIED: " + su[1]);
            } catch (Exception e) {
                Log.d(T, "ERROR: " + su[1] + " - " + e.getClass().getSimpleName());
            }
        }
    }
}
