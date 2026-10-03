package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

// Probes com.android.server.telecom/.components.TelecomService (exported, no manifest
// permission, action "android.telecom.TelecomService"). The real ITelecomService.Stub
// implementation is loaded dynamically from a mainline module (not in this shim APK),
// so cannot be statically audited the way KeyChainService was. Same technique: bind
// with zero permissions, brute-force AIDL transaction codes, log which succeed.
public class TelecomServiceProbeActivity extends Activity {
    private static final String T = "TELECOM_PROBE";
    private static final String IFACE_ACTION = "android.telecom.TelecomService";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== TelecomService unauthenticated AIDL method probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        Intent intent = new Intent(IFACE_ACTION);
        intent.setComponent(new ComponentName("com.android.server.telecom", "com.android.server.telecom.components.TelecomService"));

        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.w(T, "[!!!] BOUND to TelecomService with ZERO permissions: " + name);
                String desc = null;
                try {
                    desc = service.getInterfaceDescriptor();
                    Log.w(T, "  interface desc=" + desc);
                } catch (Exception e) {
                    Log.w(T, "  desc error: " + e);
                }

                for (int tx = 1; tx <= 90; tx++) {
                    tryZeroArgCall(service, tx, desc);
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

    private void tryZeroArgCall(IBinder service, int tx, String desc) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc != null ? desc : "com.android.internal.telecom.ITelecomService");
            // Some methods take a String callingPackage as the first arg; write one
            // speculatively too in a second pass if this pass finds nothing.
            boolean ok = service.transact(tx, data, reply, 0);
            reply.setDataPosition(0);
            if (reply.dataAvail() < 4) {
                Log.w(T, "[?] TX" + tx + " ok=" + ok + " empty reply (avail=" + reply.dataAvail() + ")");
                return;
            }
            int exc = reply.readInt();
            if (exc == 0) {
                int avail = reply.dataAvail();
                int posAfterExc = reply.dataPosition();
                Log.w(T, "[+] TX" + tx + " returned WITHOUT exception, avail=" + avail);
                if (avail == 4) {
                    reply.setDataPosition(posAfterExc);
                    int v = reply.readInt();
                    Log.w(T, "  [INT/BOOL] TX" + tx + " = " + v);
                } else if (avail == 8) {
                    reply.setDataPosition(posAfterExc);
                    long v = reply.readLong();
                    Log.w(T, "  [LONG] TX" + tx + " = " + v);
                } else if (avail > 0) {
                    dumpUtf16(tx, reply);
                }
            }
        } catch (Throwable e) {
            // expected for permission-guarded methods
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private void dumpUtf16(int tx, Parcel reply) {
        int startPos = reply.dataPosition();
        try {
            byte[] raw = reply.marshall();
            StringBuilder cur = new StringBuilder();
            StringBuilder out = new StringBuilder();
            int i = startPos;
            while (i + 1 < raw.length) {
                int lo = raw[i] & 0xFF;
                int hi = raw[i + 1] & 0xFF;
                if (hi == 0 && lo >= 32 && lo < 127) {
                    cur.append((char) lo);
                    i += 2;
                } else {
                    if (cur.length() >= 2) out.append(cur).append(" | ");
                    cur.setLength(0);
                    i += 1;
                }
            }
            if (cur.length() >= 2) out.append(cur);
            Log.w(T, "  [DATA] TX" + tx + ": " + out + " | rawlen=" + raw.length);
        } catch (Exception e) {
            Log.w(T, "  marshall failed: " + e);
        }
        reply.setDataPosition(startPos);
    }
}
