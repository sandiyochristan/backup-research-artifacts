package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ZeroPermScanActivity extends Activity {
    private static final String TAG = "ZeroPermScan";
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
        logView.setText("ZERO PERMISSION Content Provider Scan\n");
        logView.append("ALL runtime permissions REVOKED\n");
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
        // Test ALL Google content providers accessible without permissions
        String[][] providers = {
            // Calendar
            {"content://com.android.calendar/events", "Calendar Events"},
            {"content://com.android.calendar/calendars", "Calendars"},
            {"content://com.android.calendar/attendees", "Calendar Attendees"},
            {"content://com.android.calendar/reminders", "Calendar Reminders"},
            {"content://com.android.calendar/instances/when/0/9999999999999", "Calendar Instances"},

            // Contacts
            {"content://com.android.contacts/contacts", "Contacts"},
            {"content://com.android.contacts/raw_contacts", "Raw Contacts"},
            {"content://com.android.contacts/data", "Contact Data"},
            {"content://com.android.contacts/profile", "Contact Profile"},

            // Call Log
            {"content://call_log/calls", "Call Log"},

            // SMS/MMS
            {"content://sms", "SMS"},
            {"content://sms/inbox", "SMS Inbox"},
            {"content://mms", "MMS"},
            {"content://mms-sms/conversations", "MMS-SMS Conversations"},

            // Telephony
            {"content://telephony/carriers", "Telephony Carriers/APN"},
            {"content://telephony/siminfo", "SIM Info"},

            // Settings
            {"content://settings/system", "Settings System"},
            {"content://settings/secure", "Settings Secure"},
            {"content://settings/global", "Settings Global"},

            // Media
            {"content://media/external/images/media", "External Images"},
            {"content://media/external/video/media", "External Videos"},
            {"content://media/external/audio/media", "External Audio"},
            {"content://media/external/file", "External Files"},
            {"content://media/external/downloads", "Downloads"},

            // User Dictionary
            {"content://user_dictionary/words", "User Dictionary"},

            // Blocked Numbers
            {"content://com.android.blockednumber/blocked", "Blocked Numbers"},

            // Device specific
            {"content://com.google.settings/partner", "Google Settings Partner"},
            {"content://com.google.android.gsf.gservices", "GServices"},
            {"content://com.google.android.gsf.gservices/prefix", "GServices Prefix"},

            // Google app providers
            {"content://com.google.android.gms.thunderbird.settings", "GMS Thunderbird Settings"},
            {"content://com.google.android.gm.provider", "Gmail Provider"},
            {"content://com.google.android.gm.provider.eml.attachment", "Gmail EML"},
            {"content://com.google.android.gm.email.provider", "Gmail Email Provider"},
            {"content://com.google.android.apps.messaging.shared.datamodel.provider", "Messages Provider"},
            {"content://com.google.android.apps.nbu.files.provider", "Files Provider"},
            {"content://com.google.android.apps.docs.storage", "Drive Storage"},

            // Browser/Chrome
            {"content://com.android.chrome.browser/bookmarks", "Chrome Bookmarks"},
            {"content://com.android.chrome.browser/history", "Chrome History"},
            {"content://com.android.browser/bookmarks", "Browser Bookmarks"},

            // Voicemail
            {"content://com.android.voicemail/voicemail", "Voicemail"},

            // Clipboard (Android 10+)
            {"content://clipboard/clip", "Clipboard"},
        };

        int accessible = 0;
        for (String[] p : providers) {
            String result = queryProvider(p[0]);
            if (result != null) {
                log("[ACCESSIBLE!] " + p[1] + " (" + p[0] + ")");
                log("  " + result);
                accessible++;
            }
        }

        log("\n=== ZERO-PERM: " + accessible + "/" + providers.length + " providers accessible ===\n");

        // Phase 2: Deep dive into accessible providers
        log("=== Phase 2: Deep dive accessible providers ===\n");

        // Test Settings.Secure for sensitive data
        testSettingsSecure();

        // Test GServices for device data
        testGServices();

        // Test Google Settings Partner
        testGooglePartner();

        // Test Media providers
        testMediaProviders();

        log("\n=== ALL ZERO-PERMISSION TESTS COMPLETE ===");
    }

    private String queryProvider(String uriStr) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(uriStr), null, null, null, null);
            if (c != null) {
                int count = c.getCount();
                int cols = c.getColumnCount();
                String[] colNames = c.getColumnNames();
                StringBuilder sb = new StringBuilder();
                sb.append("rows=").append(count).append(" cols=").append(cols);
                sb.append(" [");
                for (int i = 0; i < Math.min(cols, 5); i++) {
                    if (i > 0) sb.append(",");
                    sb.append(colNames[i]);
                }
                if (cols > 5) sb.append(",...");
                sb.append("]");

                if (count > 0 && c.moveToFirst()) {
                    sb.append(" first_row=[");
                    for (int i = 0; i < Math.min(cols, 3); i++) {
                        if (i > 0) sb.append("|");
                        try {
                            String val = c.getString(i);
                            sb.append(colNames[i]).append("=").append(shorten(val, 40));
                        } catch (Exception e) {
                            sb.append(colNames[i]).append("=(err)");
                        }
                    }
                    sb.append("]");
                }
                c.close();
                return sb.toString();
            }
        } catch (SecurityException e) {
            return null; // Permission denied — expected
        } catch (Exception e) {
            // Not a security issue, just provider doesn't exist or doesn't support query
            return null;
        }
        return null;
    }

    private void testSettingsSecure() {
        log("--- Settings.Secure sensitive values ---");
        String[] keys = {"android_id", "bluetooth_name", "device_name",
            "lock_screen_owner_info", "enabled_accessibility_services",
            "default_input_method", "enabled_notification_listeners",
            "backup_transport", "install_non_market_apps"};
        for (String key : keys) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://settings/secure/" + key),
                    null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(c.getColumnIndex("value"));
                    log("  " + key + "=" + shorten(val, 80));
                    c.close();
                }
            } catch (Exception e) {}
        }
    }

    private void testGServices() {
        log("\n--- GServices device data ---");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.android.gsf.gservices"),
                null, null, new String[]{"android_id"}, null);
            if (c != null && c.moveToFirst()) {
                for (int i = 0; i < c.getColumnCount(); i++) {
                    try {
                        log("  " + c.getColumnName(i) + "=" + shorten(c.getString(i), 60));
                    } catch (Exception e) {}
                }
                c.close();
            }
        } catch (Exception e) {
            log("  GServices: " + e.getClass().getSimpleName());
        }

        // Try specific GServices keys
        String[] gkeys = {"device_country", "youtube:api_key", "checkin_device_id",
            "google_services_framework_id", "digest", "android_id"};
        for (String key : gkeys) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.google.android.gsf.gservices"),
                    null, null, new String[]{key}, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(1);
                    if (val != null && !val.isEmpty()) {
                        log("  gservices[" + key + "]=" + shorten(val, 60));
                    }
                    c.close();
                }
            } catch (Exception e) {}
        }
    }

    private void testGooglePartner() {
        log("\n--- Google Settings Partner ---");
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.settings/partner"),
                null, null, null, null);
            if (c != null) {
                log("  rows=" + c.getCount() + " cols=" + c.getColumnCount());
                while (c.moveToNext()) {
                    try {
                        String name = c.getString(c.getColumnIndex("name"));
                        String val = c.getString(c.getColumnIndex("value"));
                        log("  " + name + "=" + shorten(val, 60));
                    } catch (Exception e) {}
                }
                c.close();
            }
        } catch (Exception e) {
            log("  Partner: " + e.getClass().getSimpleName());
        }
    }

    private void testMediaProviders() {
        log("\n--- Media provider access (no READ_MEDIA_*) ---");
        String[] mediaUris = {
            "content://media/external/images/media",
            "content://media/external/video/media",
            "content://media/external/audio/media",
            "content://media/external/file",
        };
        for (String uri : mediaUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri),
                    new String[]{"_id", "_display_name", "_data"}, null, null, "_id DESC LIMIT 5");
                if (c != null) {
                    log("  " + uri + ": rows=" + c.getCount());
                    while (c.moveToNext()) {
                        try {
                            String name = c.getString(1);
                            String path = c.getString(2);
                            log("    " + name + " @ " + shorten(path, 50));
                        } catch (Exception e) {}
                    }
                    c.close();
                }
            } catch (Exception e) {}
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
