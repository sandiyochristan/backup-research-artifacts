package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class BroadProviderScanActivity extends Activity {
    private static final String TAG = "BroadScan";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(6);
        logView.setText("Broad Provider Scan - Zero Permission Access\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void runTests() {
        String[] uris = {
            "content://com.android.chrome",
            "content://com.android.chrome.browser/bookmarks",
            "content://com.android.chrome.ChromeBrowserProvider/bookmarks",
            "content://com.android.chrome.ScreenshotContentProvider",
            "content://com.android.chrome.DropDataProvider",
            "content://com.android.chrome.PdfContentProvider",
            "content://com.android.partnerbookmarks",
            "content://com.android.browser/bookmarks",
            "content://com.android.contacts.dumpfile",
            "content://com.android.contacts.picker.sessions",
            "content://call_composer_locations",
            "content://carrier_id/all",
            "content://carrier_information",
            "content://com.android.blockednumber/blocked",
            "content://com.android.shell",
            "content://com.android.shell.documents",
            "content://com.android.shell.heapdump",
            "content://com.android.bitmapoffload",
            "content://com.android.angle",
            "content://com.android.simphonebook",
            "content://com.android.simphonebook/simphonebook",
            "content://com.google.android.gms.phenotype",
            "content://com.google.android.gms.chimera",
            "content://com.google.android.gsf.gservices",
            "content://com.google.settings/partner",
            "content://com.google.android.dialer.callscreen.impl.speechrecognition.provider",
            "content://com.android.dialer.debug.dump.dumptools",
            "content://com.android.dialer.persistentlog",
            "content://com.google.android.apps.wellbeing.autodnd.ui",
            "content://com.android.settings.slices",
            "content://android.settings.slices",
            "content://com.android.settings",
            "content://com.android.settings.homepage.CardContentProvider",
            "content://com.android.settings.spa.search.provider",
            "content://com.android.settings.suggestions.status",
            "content://com.android.settings.battery.usage.provider",
            "content://com.android.settings.biometrics.provider",
            "content://com.android.permissioncontroller",
            "content://com.android.permissioncontroller.role",
            "content://com.android.permissioncontroller.safetycenter",
            "content://com.android.healthconnect.controller",
            "content://com.android.appinteraction.history",
            "content://com.android.contactkeys.contactkeysprovider",
            "content://com.android.systemui.customization",
            "content://com.android.systemui.keyguard",
            "content://com.google.android.flipendo.api",
            "content://com.google.android.apps.recorder.audiofiles",
            "content://cellbroadcasts",
            "content://cellbroadcast-legacy",
            "content://com.android.cellbroadcastreceiver",
            "content://com.google.android.settings.intelligence",
            "content://com.google.android.contacts.yourinfo",
            "content://com.google.android.contacts.sdn.provider",
            "content://com.google.android.apps.messaging.shared.datamodel.ProxyProvider",
        };

        for (String uri : uris) {
            testProvider(uri);
        }

        log("\n=== SCAN COMPLETE ===");
    }

    private void testProvider(String uri) {
        try {
            Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
            if (c != null) {
                int rows = c.getCount();
                int cols = c.getColumnCount();
                StringBuilder colNames = new StringBuilder();
                if (cols > 0) {
                    for (String cn : c.getColumnNames()) colNames.append(cn).append(",");
                }
                log("[ACCESSIBLE] " + uri);
                log("  Rows=" + rows + " Cols=" + cols);
                if (colNames.length() > 0) log("  Columns: " + colNames);
                if (rows > 0 && c.moveToFirst()) {
                    for (int i = 0; i < Math.min(cols, 5); i++) {
                        try {
                            String val = c.getString(i);
                            if (val != null && val.length() > 200) val = val.substring(0, 200) + "...";
                            log("  [0]." + c.getColumnName(i) + " = " + val);
                        } catch (Exception ignored) {}
                    }
                }
                c.close();
            } else {
                log("[NULL] " + uri);
            }
        } catch (SecurityException e) {
            log("[DENIED] " + uri.substring(uri.lastIndexOf('/') + 1));
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.length() > 100) msg = msg.substring(0, 100);
            log("[ERROR] " + uri.substring(Math.max(0, uri.length()-40)) + ": " + e.getClass().getSimpleName());
        }
    }
}
