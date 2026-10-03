package com.android.omadm.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.telephony.SubscriptionManager;
import android.util.Log;
import java.io.IOException;

/* loaded from: classes.dex */
public class TelephonyBroadcastReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) throws Resources.NotFoundException, IOException {
        String action = intent.getAction();
        logd("action intent: " + action + ", subId: " + intent.getIntExtra("android.telephony.extra.SUBSCRIPTION_INDEX", SubscriptionManager.getDefaultSubscriptionId()));
        if ("com.android.phone.settings.CARRIER_PROVISIONING".equals(action) || "com.android.phone.settings.TRIGGER_CARRIER_PROVISIONING".equals(action) || "android.intent.action.BOOT_COMPLETED".equals(action)) {
            new DMIntentReceiver().onReceive(context, intent);
        } else if ("com.google.android.carrier.action.APP_ENABLED".equals(action)) {
            new DMIntentReceiver().onReceive(context, intent);
        }
    }

    private static void logd(String str) {
        Log.d("DMTelephonyReceiver", str);
    }
}
