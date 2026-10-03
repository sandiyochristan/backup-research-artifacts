package com.vrp.zeroperm;

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

public class ServiceProbeActivity extends Activity {
    private static final String T = "SVCPROBE";

    private static final String[][] SERVICES = {
        {"com.google.android.gms.people.service.START", "com.google.android.gms.people.internal.IPeopleService"},
        {"com.google.android.gms.auth.service.START", "com.google.android.gms.auth.internal.IAuthService"},
        {"com.google.android.gms.auth.api.accounttransfer.service.START", "com.google.android.gms.auth.api.accounttransfer.IAccountTransferService"},
        {"com.google.android.gms.people.contactssync.service.START", "com.google.android.gms.people.contactssync.internal.IContactsSyncService"},
    };

    private int serviceIndex = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== GMS Service Probe PoC ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());
        tryNextService();
    }

    private void tryNextService() {
        if (serviceIndex >= SERVICES.length) {
            Log.w(T, "=== ALL SERVICE PROBES COMPLETE ===");
            return;
        }

        String action = SERVICES[serviceIndex][0];
        String iface = SERVICES[serviceIndex][1];
        Log.w(T, "--- Probing service: " + action + " ---");

        Intent intent = new Intent(action);
        intent.setPackage("com.google.android.gms");

        try {
            boolean bound = bindService(intent, new ProbeConnection(action, iface), Context.BIND_AUTO_CREATE);
            Log.w(T, "Bind result: " + bound);
            if (!bound) {
                Log.w(T, "BIND FAILED for " + action);
                serviceIndex++;
                tryNextService();
            }
        } catch (Exception e) {
            Log.e(T, "Bind exception: " + e.getMessage());
            serviceIndex++;
            tryNextService();
        }
    }

    private class ProbeConnection implements ServiceConnection {
        private final String action;
        private final String iface;

        ProbeConnection(String action, String iface) {
            this.action = action;
            this.iface = iface;
        }

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Log.w(T, "*** SERVICE CONNECTED: " + name + " ***");
            Log.w(T, "Binder class: " + service.getClass().getName());
            Log.w(T, "Is binder alive: " + service.isBinderAlive());

            try {
                String desc = service.getInterfaceDescriptor();
                Log.w(T, "Interface descriptor: " + desc);
            } catch (RemoteException e) {
                Log.w(T, "Cannot get descriptor: " + e.getMessage());
            }

            probeTransactions(service, iface);

            try { unbindService(this); } catch (Exception e) {}
            serviceIndex++;
            tryNextService();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.w(T, "Service disconnected: " + name);
        }
    }

    private void probeTransactions(IBinder service, String iface) {
        for (int txCode = 1; txCode <= 15; txCode++) {
            try {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(iface);

                boolean result = service.transact(txCode, data, reply, 0);

                int replySize = reply.dataSize();
                reply.setDataPosition(0);

                Log.w(T, "TX " + txCode + ": result=" + result + " replySize=" + replySize);

                if (replySize > 0) {
                    int exceptionCode = reply.readInt();
                    if (exceptionCode != 0) {
                        String exMsg = reply.readString();
                        Log.w(T, "TX " + txCode + " EXCEPTION: code=" + exceptionCode + " msg=" + exMsg);
                    } else {
                        int remaining = reply.dataAvail();
                        Log.w(T, "TX " + txCode + " SUCCESS! remaining=" + remaining);
                        if (remaining > 0 && remaining < 4096) {
                            byte[] replyBytes = reply.marshall();
                            StringBuilder hex = new StringBuilder();
                            for (int i = 0; i < Math.min(replyBytes.length, 128); i++) {
                                hex.append(String.format("%02x", replyBytes[i]));
                                if ((i + 1) % 4 == 0) hex.append(" ");
                            }
                            Log.w(T, "TX " + txCode + " REPLY HEX: " + hex.toString());

                            StringBuilder ascii = new StringBuilder();
                            for (byte b : replyBytes) {
                                if (b >= 32 && b < 127) ascii.append((char) b);
                            }
                            if (ascii.length() > 0) {
                                Log.w(T, "TX " + txCode + " REPLY ASCII: " + ascii.toString());
                            }
                        }
                    }
                }

                data.recycle();
                reply.recycle();
            } catch (Exception e) {
                Log.w(T, "TX " + txCode + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }
}
