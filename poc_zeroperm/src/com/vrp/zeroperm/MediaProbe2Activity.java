package com.vrp.zeroperm;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.MediaStore;
import android.util.Log;
import java.io.InputStream;

public class MediaProbe2Activity extends Activity {
    private static final String T = "MEDIA_PROBE2";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== MediaStore Zero-Perm Probe v2 ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " PID=" + android.os.Process.myPid());
        Log.w(T, "ZERO PERMISSIONS");

        // Test 1: Query images
        probeUri("images", MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            new String[]{"_id", "_display_name", "_size", "date_added", "relative_path"});

        // Test 2: Query video
        probeUri("video", MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
            new String[]{"_id", "_display_name", "_size", "date_added"});

        // Test 3: Query audio
        probeUri("audio", MediaStore.Audio.Media.EXTERNAL_CONTENT_URI,
            new String[]{"_id", "_display_name", "_size", "date_added"});

        // Test 4: Query downloads
        probeUri("downloads", MediaStore.Downloads.EXTERNAL_CONTENT_URI,
            new String[]{"_id", "_display_name", "_size", "date_added"});

        // Test 5: Query files (all media)
        probeUri("files", MediaStore.Files.getContentUri("external"),
            new String[]{"_id", "_display_name", "media_type", "_size"});

        // Test 6: Try to read image content by URI
        try {
            Uri imageUri = Uri.parse("content://media/external/images/media/26");
            InputStream is = getContentResolver().openInputStream(imageUri);
            if (is != null) {
                byte[] header = new byte[16];
                int read = is.read(header);
                is.close();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < read; i++) sb.append(String.format("%02x", header[i]));
                Log.w(T, "[!!!] IMAGE READ SUCCESS: id=26, header=" + sb.toString());
            }
        } catch (Exception e) {
            Log.w(T, "[-] Image read failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 7: Try MediaStore.Images.Thumbnails
        try {
            Cursor c = getContentResolver().query(
                MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI,
                new String[]{"_id", "image_id", "_data"},
                null, null, null);
            if (c != null) {
                Log.w(T, "[+] Thumbnails query: " + c.getCount() + " rows");
                while (c.moveToNext() && c.getPosition() < 3) {
                    Log.w(T, "[+] Thumbnail: id=" + c.getLong(0) + " image_id=" + c.getLong(1));
                }
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] Thumbnails failed: " + e.getMessage());
        }

        // Test 8: Query MediaStore.getVersion()
        try {
            String ver = MediaStore.getVersion(this);
            Log.w(T, "[*] MediaStore version: " + ver);
        } catch (Exception e) {
            Log.w(T, "[-] MediaStore version failed: " + e.getMessage());
        }

        Log.w(T, "=== MediaStore probe complete ===");
    }

    private void probeUri(String label, Uri uri, String[] cols) {
        try {
            Cursor c = getContentResolver().query(uri, cols, null, null, "_id ASC");
            if (c != null) {
                int count = c.getCount();
                Log.w(T, "[" + (count > 0 ? "+++" : "*") + "] " + label + ": " + count + " rows");
                int shown = 0;
                while (c.moveToNext() && shown < 5) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < c.getColumnCount(); i++) {
                        if (i > 0) sb.append(", ");
                        sb.append(c.getColumnName(i)).append("=").append(c.getString(i));
                    }
                    Log.w(T, "[+++] " + label + " row " + shown + ": " + sb.toString());
                    shown++;
                }
                c.close();
            } else {
                Log.w(T, "[-] " + label + ": null cursor");
            }
        } catch (Exception e) {
            Log.w(T, "[-] " + label + " failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
