package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;

public class SystemLeakActivity extends Activity {
    private static final String T = "SYSLEAK2";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== System Info Leak Suite v2 ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        testTelephonyLeak();
        testConnectivityLeak();
        testNetworkInterfaceLeak();
        testBuildInfoLeak();
        testCrossUserContentURI();
        testInputMethodLeak();
        testPackageInstallerLeak();
        testDevicePolicyLeak();
        testAppSearchLeak();
        testSensorPrivacyLeak();
        testKeyguardLeak();
        testLocationManagerLeak();
        testPowerManagerLeak();
        testDisplayLeak();
        testStorageManagerLeak();

        Log.w(T, "=== SYSTEM LEAK v2 COMPLETE ===");
    }

    private void testTelephonyLeak() {
        Log.w(T, "--- TelephonyManager Info ---");
        try {
            TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
            Log.w(T, "phoneType=" + tm.getPhoneType());
            Log.w(T, "networkType=" + tm.getDataNetworkType());
            Log.w(T, "simState=" + tm.getSimState());
            Log.w(T, "networkOperator=" + tm.getNetworkOperator());
            Log.w(T, "networkOperatorName=" + tm.getNetworkOperatorName());
            Log.w(T, "simOperator=" + tm.getSimOperator());
            Log.w(T, "simOperatorName=" + tm.getSimOperatorName());
            Log.w(T, "networkCountryIso=" + tm.getNetworkCountryIso());
            Log.w(T, "simCountryIso=" + tm.getSimCountryIso());
            Log.w(T, "phoneCount=" + tm.getPhoneCount());
            Log.w(T, "isDataEnabled=" + tm.isDataEnabled());
            Log.w(T, "dataState=" + tm.getDataState());

            try {
                String deviceId = tm.getDeviceId();
                if (deviceId != null) Log.w(T, "[!!!] DEVICE ID LEAKED: " + deviceId);
            } catch (SecurityException se) { Log.w(T, "[-] getDeviceId SECURITY"); }

            try {
                String imei = tm.getImei();
                if (imei != null) Log.w(T, "[!!!] IMEI LEAKED: " + imei);
            } catch (SecurityException se) { Log.w(T, "[-] getImei SECURITY"); }

            try {
                String subscriberId = tm.getSubscriberId();
                if (subscriberId != null) Log.w(T, "[!!!] SUBSCRIBER ID (IMSI) LEAKED: " + subscriberId);
            } catch (SecurityException se) { Log.w(T, "[-] getSubscriberId SECURITY"); }

            try {
                String line1 = tm.getLine1Number();
                if (line1 != null && !line1.isEmpty()) Log.w(T, "[!!!] PHONE NUMBER LEAKED: " + line1);
            } catch (SecurityException se) { Log.w(T, "[-] getLine1Number SECURITY"); }

            try {
                String serial = tm.getSimSerialNumber();
                if (serial != null) Log.w(T, "[!!!] SIM SERIAL LEAKED: " + serial);
            } catch (SecurityException se) { Log.w(T, "[-] getSimSerialNumber SECURITY"); }

            try {
                String voicemail = tm.getVoiceMailNumber();
                if (voicemail != null) Log.w(T, "[!!!] VOICEMAIL NUMBER: " + voicemail);
            } catch (SecurityException se) { Log.w(T, "[-] getVoiceMailNumber SECURITY"); }

        } catch (Exception e) {
            Log.w(T, "[-] Telephony: " + e.getClass().getSimpleName());
        }
    }

    private void testConnectivityLeak() {
        Log.w(T, "--- ConnectivityManager ---");
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            Network active = cm.getActiveNetwork();
            if (active != null) {
                NetworkCapabilities nc = cm.getNetworkCapabilities(active);
                if (nc != null) {
                    Log.w(T, "Network caps: " + nc.toString().substring(0, Math.min(nc.toString().length(), 200)));
                    Log.w(T, "Has WIFI: " + nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI));
                    Log.w(T, "Has CELLULAR: " + nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
                    Log.w(T, "Has VPN: " + nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
                    Log.w(T, "BW down: " + nc.getLinkDownstreamBandwidthKbps() + " kbps");
                    Log.w(T, "BW up: " + nc.getLinkUpstreamBandwidthKbps() + " kbps");
                }
            }

            try {
                android.net.ProxyInfo proxy = cm.getDefaultProxy();
                if (proxy != null) {
                    Log.w(T, "[!!!] PROXY: " + proxy.getHost() + ":" + proxy.getPort());
                } else {
                    Log.w(T, "No proxy");
                }
            } catch (Exception e) {}

            try {
                boolean metered = cm.isActiveNetworkMetered();
                Log.w(T, "Metered: " + metered);
            } catch (Exception e) {}

        } catch (Exception e) {
            Log.w(T, "[-] Connectivity: " + e.getClass().getSimpleName());
        }
    }

    private void testNetworkInterfaceLeak() {
        Log.w(T, "--- Network Interfaces ---");
        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            while (nets.hasMoreElements()) {
                NetworkInterface ni = nets.nextElement();
                if (ni.isUp()) {
                    Enumeration<InetAddress> addrs = ni.getInetAddresses();
                    while (addrs.hasMoreElements()) {
                        InetAddress addr = addrs.nextElement();
                        if (!addr.isLoopbackAddress()) {
                            Log.w(T, "[*] " + ni.getName() + ": " + addr.getHostAddress());
                        }
                    }
                    byte[] hw = ni.getHardwareAddress();
                    if (hw != null) {
                        StringBuilder sb = new StringBuilder();
                        for (byte b : hw) sb.append(String.format("%02X:", b));
                        String mac = sb.toString();
                        if (!mac.isEmpty()) mac = mac.substring(0, mac.length() - 1);
                        if (!mac.equals("02:00:00:00:00:00")) {
                            Log.w(T, "[!!!] MAC ADDRESS: " + ni.getName() + " = " + mac);
                        } else {
                            Log.w(T, "[.] MAC " + ni.getName() + ": randomized");
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.w(T, "[-] NetworkInterface: " + e.getClass().getSimpleName());
        }
    }

    private void testBuildInfoLeak() {
        Log.w(T, "--- Build Info (intentionally public) ---");
        Log.w(T, "Model: " + Build.MODEL);
        Log.w(T, "Device: " + Build.DEVICE);
        Log.w(T, "Brand: " + Build.BRAND);
        Log.w(T, "Product: " + Build.PRODUCT);
        Log.w(T, "SDK: " + Build.VERSION.SDK_INT);
        Log.w(T, "Release: " + Build.VERSION.RELEASE);
        Log.w(T, "Security: " + Build.VERSION.SECURITY_PATCH);
        Log.w(T, "Fingerprint: " + Build.FINGERPRINT);
        Log.w(T, "Hardware: " + Build.HARDWARE);
        Log.w(T, "Board: " + Build.BOARD);
        Log.w(T, "Bootloader: " + Build.BOOTLOADER);
        try {
            String serial = Build.getSerial();
            if (serial != null && !serial.equals("unknown")) {
                Log.w(T, "[!!!] SERIAL: " + serial);
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] Build.getSerial SECURITY");
        }
    }

    private void testCrossUserContentURI() {
        Log.w(T, "--- Cross-User Content URI ---");
        ContentResolver cr = getContentResolver();

        String[][] uris = {
            {"content://0@contacts/contacts", "User 0 contacts"},
            {"content://10@contacts/contacts", "User 10 contacts"},
            {"content://0@settings/global", "User 0 settings"},
            {"content://10@settings/global", "User 10 settings"},
            {"content://0@call_log/calls", "User 0 call log"},
            {"content://0@sms", "User 0 SMS"},
            {"content://0@media/external/images/media", "User 0 media"},
        };

        for (String[] u : uris) {
            try {
                Cursor c = cr.query(Uri.parse(u[0]), null, null, null, null);
                if (c != null) {
                    if (c.getCount() > 0) {
                        Log.w(T, "[!!!] " + u[1] + ": " + c.getCount() + " rows!");
                        if (c.moveToFirst()) {
                            String[] cols = c.getColumnNames();
                            for (int i = 0; i < Math.min(cols.length, 3); i++) {
                                try {
                                    String val = c.getString(i);
                                    if (val != null) Log.w(T, "[!!!] " + cols[i] + "=" + val.substring(0, Math.min(val.length(), 80)));
                                } catch (Exception ex) {}
                            }
                        }
                    } else {
                        Log.w(T, "[.] " + u[1] + ": 0 rows");
                    }
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + u[1] + " SECURITY");
            } catch (Exception e) {
                Log.w(T, "[-] " + u[1] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testInputMethodLeak() {
        Log.w(T, "--- Input Method Manager ---");
        try {
            android.view.inputmethod.InputMethodManager imm =
                (android.view.inputmethod.InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
            java.util.List<android.view.inputmethod.InputMethodInfo> ims = imm.getInputMethodList();
            Log.w(T, "Installed IMEs: " + ims.size());
            for (android.view.inputmethod.InputMethodInfo im : ims) {
                Log.w(T, "  IME: " + im.getPackageName() + "/" + im.getServiceName());
            }
            java.util.List<android.view.inputmethod.InputMethodInfo> enabled = imm.getEnabledInputMethodList();
            Log.w(T, "Enabled IMEs: " + enabled.size());
        } catch (Exception e) {
            Log.w(T, "[-] IME: " + e.getClass().getSimpleName());
        }
    }

    private void testPackageInstallerLeak() {
        Log.w(T, "--- PackageInstaller Sessions ---");
        try {
            android.content.pm.PackageInstaller pi = getPackageManager().getPackageInstaller();
            java.util.List<android.content.pm.PackageInstaller.SessionInfo> sessions = pi.getAllSessions();
            Log.w(T, "Installer sessions: " + sessions.size());
            for (android.content.pm.PackageInstaller.SessionInfo session : sessions) {
                Log.w(T, "  Session: " + session.getAppPackageName() + " installer=" + session.getInstallerPackageName());
            }

            java.util.List<android.content.pm.PackageInstaller.SessionInfo> mySessions = pi.getMySessions();
            Log.w(T, "My sessions: " + mySessions.size());
        } catch (Exception e) {
            Log.w(T, "[-] PackageInstaller: " + e.getClass().getSimpleName());
        }
    }

    private void testDevicePolicyLeak() {
        Log.w(T, "--- DevicePolicyManager ---");
        try {
            android.app.admin.DevicePolicyManager dpm =
                (android.app.admin.DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
            Log.w(T, "storageEncryption: " + dpm.getStorageEncryptionStatus());
            try {
                java.util.List<android.content.ComponentName> admins = dpm.getActiveAdmins();
                if (admins != null) {
                    Log.w(T, "Active admins: " + admins.size());
                    for (android.content.ComponentName admin : admins) {
                        Log.w(T, "  Admin: " + admin.flattenToShortString());
                    }
                }
            } catch (Exception e) {}
        } catch (Exception e) {
            Log.w(T, "[-] DevicePolicy: " + e.getClass().getSimpleName());
        }
    }

    private void testAppSearchLeak() {
        Log.w(T, "--- AppSearch API ---");
        try {
            Class<?> appSearchClass = Class.forName("android.app.appsearch.AppSearchManager");
            Object asm = getSystemService("appsearch");
            if (asm != null) {
                Log.w(T, "[*] AppSearchManager available");
            } else {
                Log.w(T, "[-] AppSearchManager not available");
            }
        } catch (ClassNotFoundException e) {
            Log.w(T, "[-] AppSearch not on this API");
        } catch (Exception e) {
            Log.w(T, "[-] AppSearch: " + e.getClass().getSimpleName());
        }
    }

    private void testSensorPrivacyLeak() {
        Log.w(T, "--- Sensor Privacy ---");
        try {
            Object spm = getSystemService("sensor_privacy");
            if (spm != null) {
                java.lang.reflect.Method m = spm.getClass().getMethod("isSensorPrivacyEnabled");
                boolean enabled = (boolean) m.invoke(spm);
                Log.w(T, "Sensor privacy enabled: " + enabled);
            }
        } catch (Exception e) {
            Log.w(T, "[-] SensorPrivacy: " + e.getClass().getSimpleName());
        }
    }

    private void testKeyguardLeak() {
        Log.w(T, "--- Keyguard Manager ---");
        try {
            android.app.KeyguardManager km = (android.app.KeyguardManager) getSystemService(KEYGUARD_SERVICE);
            Log.w(T, "isKeyguardLocked: " + km.isKeyguardLocked());
            Log.w(T, "isKeyguardSecure: " + km.isKeyguardSecure());
            Log.w(T, "isDeviceSecure: " + km.isDeviceSecure());
            Log.w(T, "isDeviceLocked: " + km.isDeviceLocked());
        } catch (Exception e) {
            Log.w(T, "[-] Keyguard: " + e.getClass().getSimpleName());
        }
    }

    private void testLocationManagerLeak() {
        Log.w(T, "--- Location Manager ---");
        try {
            android.location.LocationManager lm =
                (android.location.LocationManager) getSystemService(LOCATION_SERVICE);
            Log.w(T, "GPS enabled: " + lm.isProviderEnabled(android.location.LocationManager.GPS_PROVIDER));
            Log.w(T, "Network enabled: " + lm.isProviderEnabled(android.location.LocationManager.NETWORK_PROVIDER));

            java.util.List<String> providers = lm.getAllProviders();
            Log.w(T, "Providers: " + providers);

            try {
                android.location.Location last = lm.getLastKnownLocation(android.location.LocationManager.GPS_PROVIDER);
                if (last != null) {
                    Log.w(T, "[!!!] LAST LOCATION: " + last.getLatitude() + "," + last.getLongitude());
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] getLastKnownLocation SECURITY");
            }
        } catch (Exception e) {
            Log.w(T, "[-] Location: " + e.getClass().getSimpleName());
        }
    }

    private void testPowerManagerLeak() {
        Log.w(T, "--- Power Manager ---");
        try {
            android.os.PowerManager pm = (android.os.PowerManager) getSystemService(POWER_SERVICE);
            Log.w(T, "isInteractive: " + pm.isInteractive());
            Log.w(T, "isPowerSaveMode: " + pm.isPowerSaveMode());
            Log.w(T, "isDeviceIdleMode: " + pm.isDeviceIdleMode());
            Log.w(T, "isSustainedPerfModeSupported: " + pm.isSustainedPerformanceModeSupported());

            try {
                float thermalStatus = pm.getCurrentThermalStatus();
                Log.w(T, "thermalStatus: " + thermalStatus);
            } catch (Exception e) {}
        } catch (Exception e) {
            Log.w(T, "[-] Power: " + e.getClass().getSimpleName());
        }
    }

    private void testDisplayLeak() {
        Log.w(T, "--- Display Manager ---");
        try {
            android.hardware.display.DisplayManager dm =
                (android.hardware.display.DisplayManager) getSystemService(DISPLAY_SERVICE);
            android.view.Display[] displays = dm.getDisplays();
            Log.w(T, "Displays: " + displays.length);
            for (android.view.Display d : displays) {
                android.util.DisplayMetrics metrics = new android.util.DisplayMetrics();
                d.getRealMetrics(metrics);
                Log.w(T, "  Display " + d.getDisplayId() + ": " +
                    metrics.widthPixels + "x" + metrics.heightPixels +
                    " density=" + metrics.density + " dpi=" + metrics.densityDpi);
            }
        } catch (Exception e) {
            Log.w(T, "[-] Display: " + e.getClass().getSimpleName());
        }
    }

    private void testStorageManagerLeak() {
        Log.w(T, "--- Storage Manager ---");
        try {
            android.os.storage.StorageManager sm =
                (android.os.storage.StorageManager) getSystemService(STORAGE_SERVICE);
            java.util.List<android.os.storage.StorageVolume> volumes = sm.getStorageVolumes();
            Log.w(T, "Storage volumes: " + volumes.size());
            for (android.os.storage.StorageVolume vol : volumes) {
                Log.w(T, "  Vol: " + vol.getDescription(this) + " state=" + vol.getState() +
                    " removable=" + vol.isRemovable() + " primary=" + vol.isPrimary());
                try {
                    java.util.UUID uuid = vol.getStorageUuid();
                    if (uuid != null) Log.w(T, "    UUID: " + uuid);
                } catch (Exception e) {}
            }
        } catch (Exception e) {
            Log.w(T, "[-] Storage: " + e.getClass().getSimpleName());
        }
    }
}
