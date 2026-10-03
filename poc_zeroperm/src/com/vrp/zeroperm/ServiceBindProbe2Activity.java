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

public class ServiceBindProbe2Activity extends Activity {
    private static final String T = "SVC_BIND_PROBE2";
    private int bound = 0;
    private int failed = 0;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Service Bind Probe v2 ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " PID=" + android.os.Process.myPid());
        Log.w(T, "ZERO PERMISSIONS — testing service binding");

        String[][] targets = {
            {"com.android.phone", "com.android.phone.TelephonyDebugService"},
            {"com.android.se", "com.android.se.SecureElementService"},
            {"com.android.settings", "com.android.settings.SettingsService"},
            {"com.android.hbmsvmanager", "com.android.hbmsvmanager.DisplayService"},
            {"com.android.devicelockcontroller", "com.android.devicelockcontroller.DeviceLockControllerService"},
            {"com.android.keychain", "com.android.keychain.KeyChainService"},
            {"com.android.location.fused", "com.android.location.fused.FusedLocationService"},
            {"android", "android.net.ConnectivityCallListenerService"},
            {"com.android.settings", "com.android.settingslib.service.SettingsPreferenceService"},
            {"com.google.android.gms", "com.google.android.gms.auth.api.signin.RevocationBoundService"},
            {"com.google.android.gms", "com.google.android.gms.nearby.connection.service.NearbyConnectionsAndroidService"},
            {"com.google.android.gms", "com.google.android.gms.fitness.service.InternalFitnessApiService"},
            {"com.google.android.gms", "com.google.android.gms.people.service.PeopleService"},
            {"com.google.android.gms", "com.google.android.gms.auth.api.credentials.CredentialsService"},
            {"com.google.android.gms", "com.google.android.gms.auth.account.authenticator.FallbackAuthenticatorService"},
            {"com.android.server.telecom", "com.android.server.telecom.components.TelecomService"},
        };

        for (String[] t : targets) {
            tryBind(t[0], t[1]);
        }

        // Also try implicit binds for interesting services
        tryImplicitBind("com.google.android.gms.auth.service.START");
        tryImplicitBind("com.google.android.gms.people.service.START");
        tryImplicitBind("com.google.android.gms.drive.ApiService.START");
        tryImplicitBind("com.google.android.gms.fitness.InternalApi.START");
    }

    private void tryBind(String pkg, String cls) {
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName(pkg, cls));
            boolean r = bindService(i, new SC(pkg + "/" + cls), Context.BIND_AUTO_CREATE);
            Log.w(T, (r ? "[+] BIND ACCEPTED: " : "[-] Bind rejected: ") + pkg + "/" + cls);
            if (r) bound++;
        } catch (Exception e) {
            Log.w(T, "[-] Bind error " + pkg + "/" + cls + ": " + e.getMessage());
            failed++;
        }
    }

    private void tryImplicitBind(String action) {
        try {
            Intent i = new Intent(action);
            i.setPackage("com.google.android.gms");
            boolean r = bindService(i, new SC("implicit:" + action), Context.BIND_AUTO_CREATE);
            Log.w(T, (r ? "[+] IMPLICIT BIND ACCEPTED: " : "[-] Implicit bind rejected: ") + action);
            if (r) bound++;
        } catch (Exception e) {
            Log.w(T, "[-] Implicit bind error " + action + ": " + e.getMessage());
            failed++;
        }
    }

    private class SC implements ServiceConnection {
        private final String name;
        SC(String n) { this.name = n; }

        @Override
        public void onServiceConnected(ComponentName cn, IBinder binder) {
            Log.w(T, "[+++] SERVICE CONNECTED: " + name + " component=" + cn);
            Log.w(T, "[+++] Binder class: " + binder.getClass().getName());
            Log.w(T, "[+++] Interface descriptor: " + getDescriptor(binder));

            // Try to enumerate the interface by calling TRANSACTION_getVersion or similar
            try {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                // Try INTERFACE_TRANSACTION to get descriptor
                binder.transact(IBinder.INTERFACE_TRANSACTION, data, reply, 0);
                String desc = reply.readString();
                Log.w(T, "[+++] INTERFACE: " + desc);
                data.recycle();
                reply.recycle();
            } catch (Exception e) {
                Log.w(T, "[*] Interface query failed: " + e.getMessage());
            }

            // Try transaction code 1 (usually the first method)
            try {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                String desc = getDescriptor(binder);
                if (desc != null) data.writeInterfaceToken(desc);
                binder.transact(1, data, reply, 0);
                // Read whatever comes back
                int resultLen = reply.dataAvail();
                Log.w(T, "[+++] TRANSACTION 1 response: " + resultLen + " bytes");
                if (resultLen > 0 && resultLen < 4096) {
                    reply.setDataPosition(0);
                    try {
                        int exception = reply.readInt();
                        if (exception == 0) {
                            String s = reply.readString();
                            if (s != null) Log.w(T, "[+++] DATA: " + s.substring(0, Math.min(s.length(), 200)));
                        }
                    } catch (Exception ex) { /* ignore */ }
                }
                data.recycle();
                reply.recycle();
            } catch (Exception e) {
                Log.w(T, "[*] Transaction 1 failed: " + e.getMessage());
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName cn) {
            Log.w(T, "[!] Service disconnected: " + name);
        }
    }

    private String getDescriptor(IBinder binder) {
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            binder.transact(IBinder.INTERFACE_TRANSACTION, data, reply, 0);
            String d = reply.readString();
            data.recycle();
            reply.recycle();
            return d;
        } catch (Exception e) {
            return null;
        }
    }
}
