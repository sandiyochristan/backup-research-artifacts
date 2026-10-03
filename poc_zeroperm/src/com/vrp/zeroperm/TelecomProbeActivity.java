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

public class TelecomProbeActivity extends Activity {
    private static final String T = "TELECOM_PROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Telecom & SE Service Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " PID=" + android.os.Process.myPid());

        // Bind to TelecomService
        Intent ti = new Intent();
        ti.setComponent(new ComponentName("com.android.server.telecom",
            "com.android.server.telecom.components.TelecomService"));
        bindService(ti, new TelecomConnection(), Context.BIND_AUTO_CREATE);

        // Bind to SecureElementService
        Intent sei = new Intent();
        sei.setComponent(new ComponentName("com.android.se",
            "com.android.se.SecureElementService"));
        bindService(sei, new SEConnection(), Context.BIND_AUTO_CREATE);

        // Bind to HBM DisplayService
        Intent di = new Intent();
        di.setComponent(new ComponentName("com.android.hbmsvmanager",
            "com.android.hbmsvmanager.DisplayService"));
        bindService(di, new DisplayConnection(), Context.BIND_AUTO_CREATE);

        // Bind to KeyChainService
        Intent ki = new Intent();
        ki.setComponent(new ComponentName("com.android.keychain",
            "com.android.keychain.KeyChainService"));
        bindService(ki, new KeyChainConnection(), Context.BIND_AUTO_CREATE);
    }

    private class TelecomConnection implements ServiceConnection {
        @Override
        public void onServiceConnected(ComponentName cn, IBinder binder) {
            Log.w(T, "[+] TELECOM CONNECTED");
            String desc = "com.android.internal.telecom.ITelecomService";

            // ITelecomService methods (AIDL transaction codes):
            // 1=showInCallScreen, 2=getDefaultOutgoingPhoneAccount,
            // 3=getUserSelectedOutgoingPhoneAccount, 4=setUserSelectedOutgoingPhoneAccount,
            // 5=getCallCapablePhoneAccounts, 6=getSelfManagedPhoneAccounts,
            // 7=getOwnSelfManagedPhoneAccounts, 8=getPhoneAccountsSupportingScheme,
            // 9=getPhoneAccountsForPackage, 10=getPhoneAccount,
            // 11=getAllPhoneAccountsCount, 12=getAllPhoneAccounts

            for (int txn = 1; txn <= 20; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    data.writeInterfaceToken(desc);
                    // For methods that take String: write calling package
                    if (txn == 2 || txn == 5 || txn == 6 || txn == 8) {
                        data.writeString("tel"); // uriScheme for some methods
                    }
                    if (txn == 9) {
                        data.writeString("com.vrp.zeroperm");
                    }
                    binder.transact(txn, data, reply, 0);
                    int avail = reply.dataAvail();
                    reply.setDataPosition(0);
                    if (avail > 0) {
                        Log.w(T, "[TELECOM] txn=" + txn + " response=" + avail + " bytes");
                        try {
                            int ex = reply.readInt(); // exception code
                            if (ex == 0) {
                                // Try to read the result
                                int resultAvail = reply.dataAvail();
                                if (resultAvail > 0) {
                                    byte[] raw = new byte[Math.min(resultAvail, 512)];
                                    reply.readByteArray(raw);
                                    StringBuilder sb = new StringBuilder();
                                    for (byte bb : raw) {
                                        if (bb >= 32 && bb < 127) sb.append((char)bb);
                                        else if (bb != 0) sb.append('.');
                                    }
                                    String readable = sb.toString().trim();
                                    if (readable.length() > 0) {
                                        Log.w(T, "[TELECOM] txn=" + txn + " DATA: " + readable.substring(0, Math.min(readable.length(), 300)));
                                    }
                                }
                            } else {
                                // Read exception message
                                String msg = reply.readString();
                                Log.w(T, "[TELECOM] txn=" + txn + " EXCEPTION(" + ex + "): " + (msg != null ? msg.substring(0, Math.min(msg.length(), 200)) : "null"));
                            }
                        } catch (Exception pe) {
                            Log.w(T, "[TELECOM] txn=" + txn + " parse error: " + pe.getMessage());
                        }
                    }
                    data.recycle();
                    reply.recycle();
                } catch (Exception e) {
                    Log.w(T, "[TELECOM] txn=" + txn + " error: " + e.getMessage());
                }
            }

            // Also try to get phone account list count
            try {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(desc);
                binder.transact(11, data, reply, 0); // getAllPhoneAccountsCount
                reply.setDataPosition(0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int count = reply.readInt();
                    Log.w(T, "[TELECOM] PHONE ACCOUNTS COUNT: " + count);
                }
                data.recycle();
                reply.recycle();
            } catch (Exception e) {
                Log.w(T, "[TELECOM] count error: " + e.getMessage());
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName cn) {}
    }

    private class SEConnection implements ServiceConnection {
        @Override
        public void onServiceConnected(ComponentName cn, IBinder binder) {
            Log.w(T, "[+] SECURE ELEMENT CONNECTED");
            // ISecureElementService
            // Try INTERFACE_TRANSACTION
            String desc = getDesc(binder);
            Log.w(T, "[SE] Interface: " + desc);

            // Try various transaction codes
            for (int txn = 1; txn <= 10; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    if (desc != null) data.writeInterfaceToken(desc);
                    binder.transact(txn, data, reply, 0);
                    int avail = reply.dataAvail();
                    if (avail > 0) {
                        reply.setDataPosition(0);
                        Log.w(T, "[SE] txn=" + txn + " response=" + avail + " bytes");
                        try {
                            int ex = reply.readInt();
                            if (ex == 0) {
                                int remaining = reply.dataAvail();
                                if (remaining > 0) {
                                    byte[] raw = new byte[Math.min(remaining, 256)];
                                    reply.readByteArray(raw);
                                    StringBuilder sb = new StringBuilder();
                                    for (byte bb : raw) sb.append(String.format("%02x", bb));
                                    Log.w(T, "[SE] txn=" + txn + " HEX: " + sb.toString().substring(0, Math.min(sb.length(), 200)));
                                }
                            } else {
                                String msg = reply.readString();
                                Log.w(T, "[SE] txn=" + txn + " EXCEPTION: " + msg);
                            }
                        } catch (Exception pe) { /* ignore */ }
                    }
                    data.recycle();
                    reply.recycle();
                } catch (Exception e) {
                    Log.w(T, "[SE] txn=" + txn + " error: " + e.getMessage());
                }
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName cn) {}
    }

    private class DisplayConnection implements ServiceConnection {
        @Override
        public void onServiceConnected(ComponentName cn, IBinder binder) {
            Log.w(T, "[+] DISPLAY SERVICE CONNECTED");
            String desc = getDesc(binder);
            Log.w(T, "[DISPLAY] Interface: " + desc);
            for (int txn = 1; txn <= 5; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    if (desc != null) data.writeInterfaceToken(desc);
                    binder.transact(txn, data, reply, 0);
                    int avail = reply.dataAvail();
                    Log.w(T, "[DISPLAY] txn=" + txn + " response=" + avail + " bytes");
                    data.recycle();
                    reply.recycle();
                } catch (Exception e) {
                    Log.w(T, "[DISPLAY] txn=" + txn + " error: " + e.getMessage());
                }
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName cn) {}
    }

    private class KeyChainConnection implements ServiceConnection {
        @Override
        public void onServiceConnected(ComponentName cn, IBinder binder) {
            Log.w(T, "[+] KEYCHAIN CONNECTED");
            String desc = getDesc(binder);
            Log.w(T, "[KEYCHAIN] Interface: " + desc);
            for (int txn = 1; txn <= 15; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    if (desc != null) data.writeInterfaceToken(desc);
                    binder.transact(txn, data, reply, 0);
                    int avail = reply.dataAvail();
                    if (avail > 0) {
                        reply.setDataPosition(0);
                        Log.w(T, "[KEYCHAIN] txn=" + txn + " response=" + avail + " bytes");
                        try {
                            int ex = reply.readInt();
                            if (ex == 0) {
                                int remaining = reply.dataAvail();
                                if (remaining > 4) {
                                    byte[] raw = new byte[Math.min(remaining, 256)];
                                    reply.readByteArray(raw);
                                    StringBuilder sb = new StringBuilder();
                                    for (byte bb : raw) {
                                        if (bb >= 32 && bb < 127) sb.append((char)bb);
                                        else if (bb != 0) sb.append('.');
                                    }
                                    Log.w(T, "[KEYCHAIN] txn=" + txn + " DATA: " + sb.toString().substring(0, Math.min(sb.length(), 200)));
                                }
                            }
                        } catch (Exception pe) { /* ignore */ }
                    }
                    data.recycle();
                    reply.recycle();
                } catch (Exception e) {
                    Log.w(T, "[KEYCHAIN] txn=" + txn + " error: " + e.getMessage());
                }
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName cn) {}
    }

    private String getDesc(IBinder binder) {
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            binder.transact(IBinder.INTERFACE_TRANSACTION, data, reply, 0);
            String d = reply.readString();
            data.recycle();
            reply.recycle();
            return d;
        } catch (Exception e) { return null; }
    }
}
