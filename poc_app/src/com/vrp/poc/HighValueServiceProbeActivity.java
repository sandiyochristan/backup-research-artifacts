package com.vrp.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class HighValueServiceProbeActivity extends Activity {
    private static final String TAG = "HVServiceProbe";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(6);
        logView.setText("High-Value Service Probe — Credential/Payment/Location/Backup\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void runTests() {
        probeIdentityCredentials();
        probePaymentService();
        probeLocationSharing();
        probeBackupService();
        probeFitnessHistory();
        probeCheckinService();
        probeMdmService();
        probeAuthenticatorMigration();
        log("\n=== ALL HIGH-VALUE SERVICE PROBES COMPLETE ===");
    }

    private IBinder bindToService(String pkg, String cls, String label) {
        final CountDownLatch latch = new CountDownLatch(1);
        final IBinder[] holder = new IBinder[1];
        ServiceConnection conn = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder service) {
                holder[0] = service;
                latch.countDown();
            }
            @Override public void onServiceDisconnected(ComponentName name) {}
        };
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName(pkg, cls));
            boolean bound = bindService(intent, conn, Context.BIND_AUTO_CREATE);
            if (!bound) { log("[" + label + "] bindService returned false"); return null; }
            if (!latch.await(5, TimeUnit.SECONDS)) { log("[" + label + "] TIMEOUT"); return null; }
        } catch (SecurityException e) {
            log("[" + label + "] DENIED: " + shorten(e.getMessage(), 60));
            return null;
        } catch (Exception e) {
            log("[" + label + "] ERROR: " + e.getClass().getSimpleName());
            return null;
        }
        return holder[0];
    }

    private void probeIdentityCredentials() {
        log("=== IdentityCredentialApiService ===\n");
        IBinder binder = bindToService("com.google.android.gms",
            "com.google.android.gms.identitycredentials.service.IdentityCredentialApiService", "IDCRED");
        if (binder == null) return;
        try {
            String desc = binder.getInterfaceDescriptor();
            log("[BOUND] descriptor=" + desc);
            probeAllTx(binder, desc, "IDCRED", 10);
        } catch (Exception e) { log("[IDCRED] " + e.getMessage()); }
    }

    private void probePaymentService() {
        log("\n=== PaymentService (Google Wallet) ===\n");
        IBinder binder = bindToService("com.google.android.gms",
            "com.google.android.gms.wallet.service.PaymentService", "PAY");
        if (binder == null) return;
        try {
            String desc = binder.getInterfaceDescriptor();
            log("[BOUND] descriptor=" + desc);
            probeAllTx(binder, desc, "PAY", 10);

            // Try with package name in data
            for (int tx = 1; tx <= 5; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString(getPackageName());
                    data.writeInt(0);
                    binder.transact(tx, data, reply, 0);
                    if (reply.dataSize() > 4) dumpReply("PAY-PKG-TX" + tx, reply);
                } catch (Exception e) {}
                data.recycle(); reply.recycle();
            }
        } catch (Exception e) { log("[PAY] " + e.getMessage()); }
    }

    private void probeLocationSharing() {
        log("\n=== LocationSharingService ===\n");
        IBinder binder = bindToService("com.google.android.gms",
            "com.google.android.gms.locationsharing.service.LocationSharingService", "LOCSHARE");
        if (binder == null) return;
        try {
            String desc = binder.getInterfaceDescriptor();
            log("[BOUND] descriptor=" + desc);
            probeAllTx(binder, desc, "LOCSHARE", 10);
        } catch (Exception e) { log("[LOCSHARE] " + e.getMessage()); }
    }

    private void probeBackupService() {
        log("\n=== BackupAccountManagerService ===\n");
        IBinder binder = bindToService("com.google.android.gms",
            "com.google.android.gms.backup.BackupAccountManagerService", "BACKUP");
        if (binder == null) return;
        try {
            String desc = binder.getInterfaceDescriptor();
            log("[BOUND] descriptor=" + desc);
            probeAllTx(binder, desc, "BACKUP", 10);

            // Try listing backup accounts
            for (int tx = 1; tx <= 3; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString("com.vrp.poc"); // calling package
                    binder.transact(tx, data, reply, 0);
                    if (reply.dataSize() > 4) dumpReply("BACKUP-STR-TX" + tx, reply);
                } catch (Exception e) {}
                data.recycle(); reply.recycle();
            }
        } catch (Exception e) { log("[BACKUP] " + e.getMessage()); }
    }

    private void probeFitnessHistory() {
        log("\n=== FitHistoryBroker (Health/Fitness Data) ===\n");
        IBinder binder = bindToService("com.google.android.gms",
            "com.google.android.gms.fitness.service.history.FitHistoryBroker", "FIT");
        if (binder == null) return;
        try {
            String desc = binder.getInterfaceDescriptor();
            log("[BOUND] descriptor=" + desc);
            probeAllTx(binder, desc, "FIT", 10);
        } catch (Exception e) { log("[FIT] " + e.getMessage()); }
    }

    private void probeCheckinService() {
        log("\n=== CheckinApiService (Device Registration) ===\n");
        IBinder binder = bindToService("com.google.android.gms",
            "com.google.android.gms.checkin.CheckinApiService", "CHECKIN");
        if (binder == null) return;
        try {
            String desc = binder.getInterfaceDescriptor();
            log("[BOUND] descriptor=" + desc);
            probeAllTx(binder, desc, "CHECKIN", 10);
        } catch (Exception e) { log("[CHECKIN] " + e.getMessage()); }
    }

    private void probeMdmService() {
        log("\n=== DeviceManagerApiService (MDM) ===\n");
        IBinder binder = bindToService("com.google.android.gms",
            "com.google.android.gms.mdm.services.DeviceManagerApiService", "MDM");
        if (binder == null) return;
        try {
            String desc = binder.getInterfaceDescriptor();
            log("[BOUND] descriptor=" + desc);
            probeAllTx(binder, desc, "MDM", 10);
        } catch (Exception e) { log("[MDM] " + e.getMessage()); }
    }

    private void probeAuthenticatorMigration() {
        log("\n=== Authenticator OS Migration Service ===\n");
        IBinder binder = bindToService("com.google.android.apps.authenticator2",
            "com.google.android.apps.authenticator2.osmigrationtargetservice.TargetEndpointService", "AUTHMIG");
        if (binder == null) return;
        try {
            String desc = binder.getInterfaceDescriptor();
            log("[BOUND] descriptor=" + desc);
            probeAllTx(binder, desc, "AUTHMIG", 10);
        } catch (Exception e) { log("[AUTHMIG] " + e.getMessage()); }
    }

    private void probeAllTx(IBinder binder, String descriptor, String label, int maxTx) {
        for (int tx = 1; tx <= maxTx; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(descriptor);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result && reply.dataSize() > 0) {
                    dumpReply(label + "-TX" + tx, reply);
                }
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && (msg.contains("SecurityException") || msg.contains("Permission"))) {
                    log("[" + label + "-TX" + tx + "] PERMISSION DENIED: " + shorten(msg, 60));
                }
            }
            data.recycle(); reply.recycle();
        }
    }

    private void dumpReply(String label, Parcel reply) {
        reply.setDataPosition(0);
        int size = reply.dataSize();

        reply.setDataPosition(0);
        byte[] raw = new byte[Math.min(size, 128)];
        for (int i = 0; i < raw.length && reply.dataAvail() > 0; i++) {
            raw[i] = reply.readByte();
        }
        String hex = bytesToHex(raw);
        String txt = bytesToText(raw);

        reply.setDataPosition(0);
        int exCode = -999;
        try { exCode = reply.readInt(); } catch (Exception e) {}

        if (exCode == 0 && size > 4) {
            log("[" + label + "] size=" + size + " exCode=0 DATA_RETURNED");
            log("  hex: " + hex);
            if (txt.length() > 4) log("  txt: " + txt);

            // Try to read structured data
            try {
                if (reply.dataAvail() >= 4) {
                    int v1 = reply.readInt();
                    log("  val1=" + v1);
                    if (reply.dataAvail() >= 4) {
                        int v2 = reply.readInt();
                        log("  val2=" + v2);
                    }
                    if (reply.dataAvail() > 0) {
                        try {
                            String s = reply.readString();
                            if (s != null && !s.isEmpty()) log("  str: " + shorten(s, 100));
                        } catch (Exception e) {}
                    }
                }
            } catch (Exception e) {}
        } else if (exCode != 0 && size > 8) {
            // Exception with data — might contain error message with info leak
            log("[" + label + "] size=" + size + " exCode=" + exCode);
            try {
                String errMsg = reply.readString();
                if (errMsg != null) log("  err: " + shorten(errMsg, 120));
            } catch (Exception e) {}
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i] & 0xff));
            if (i % 4 == 3) sb.append(' ');
        }
        return sb.toString();
    }

    private String bytesToText(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            if (b >= 32 && b < 127) sb.append((char) b);
            else sb.append('.');
        }
        return sb.toString();
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
