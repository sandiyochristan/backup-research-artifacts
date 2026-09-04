package com.research.binderleak;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

/**
 * Target service that runs in a separate process (:target).
 * When this process is frozen by AMS, transactions with TF_UPDATE_TXN
 * queue up in the binder node's async_todo list.
 *
 * This service intentionally does NOT process transactions quickly —
 * it acts as the "frozen" target for the PoC.
 */
public class LeakTargetService extends Service {
    private static final String TAG = "LeakTarget";

    private final Binder mBinder = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws android.os.RemoteException {
            Log.d(TAG, "onTransact code=" + code + " flags=" + flags);
            return super.onTransact(code, data, reply, flags);
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "onBind — PID=" + android.os.Process.myPid());
        return mBinder;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "Service created in PID=" + android.os.Process.myPid());
    }
}
