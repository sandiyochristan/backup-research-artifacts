package com.vrp.poc;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.InputStream;

public class ZeroPermActivity extends Activity {
    private static final String TAG = "ZeroPerm";
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
        logView.setText("Zero-Permission Provider Access Test\nUID: " + android.os.Process.myUid() + "\n\n");
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
        // Enumerate all content providers from Google packages
        log("=== Enumerating Google package providers ===");
        String[] googlePackages = {
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.google.android.providers.media.module",
            "com.android.providers.settings",
            "com.android.providers.contacts",
            "com.android.providers.telephony",
            "com.android.providers.calendar",
            "com.android.providers.downloads",
            "com.android.providers.media",
            "com.android.providers.userdictionary",
            "com.google.android.apps.messaging",
            "com.google.android.dialer",
            "com.google.android.contacts",
            "com.google.android.apps.photos",
            "com.google.android.apps.docs",
            "com.google.android.keep",
            "com.google.android.gm",
            "com.google.android.apps.tachyon",
            "com.google.android.apps.wellbeing",
            "com.google.android.apps.safety.safetycore",
            "com.google.android.feedback",
            "com.google.android.partnersetup",
            "com.google.android.setupwizard",
        };

        for (String pkg : googlePackages) {
            try {
                PackageInfo pi = getPackageManager().getPackageInfo(pkg,
                    android.content.pm.PackageManager.GET_PROVIDERS);
                if (pi.providers != null) {
                    for (ProviderInfo prov : pi.providers) {
                        if (prov.authority != null && prov.exported) {
                            // Check read/write permissions
                            String readPerm = prov.readPermission;
                            String writePerm = prov.writePermission;
                            boolean hasReadRestriction = readPerm != null && !readPerm.isEmpty();

                            if (!hasReadRestriction) {
                                log("[NO READ PERM] " + pkg + ": " + prov.authority);
                                // Try to query it
                                for (String suffix : new String[]{"", "/", "/*"}) {
                                    try {
                                        Cursor c = getContentResolver().query(
                                            Uri.parse("content://" + prov.authority + suffix),
                                            null, null, null, null);
                                        if (c != null) {
                                            log("  query(" + suffix + "): " + c.getCount() + " rows, cols=" +
                                                String.join(",", c.getColumnNames()));
                                            c.close();
                                        }
                                    } catch (Exception e) {
                                        // silently skip
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Package not installed
            }
        }

        // Test known URIs that might be accessible without permissions
        log("\n=== Known provider URIs without permissions ===");
        String[][] uris = {
            {"content://settings/system", "settings_system"},
            {"content://settings/secure", "settings_secure"},
            {"content://settings/global", "settings_global"},
            {"content://com.google.settings/partner", "google_settings"},
            {"content://com.google.android.gsf.gservices", "gservices"},
            {"content://com.google.android.gsf.gservices/prefix", "gservices_prefix"},
            {"content://drm/WVLicenseManager", "widevine"},
            {"content://nfc/payment_default", "nfc_payment"},
            {"content://com.android.badge/badge", "badge"},
            {"content://com.google.android.gms.phenotype/", "phenotype"},
            {"content://com.google.android.gms.phenotype/com.google.android.gms", "phenotype_gms"},
            {"content://com.google.android.gms.chimera.container/", "chimera"},
            {"content://com.google.android.gms.config/", "gms_config"},
            {"content://com.google.android.gms.auth.accounts/", "gms_auth"},
            {"content://com.google.android.gms.fonts", "gms_fonts"},
            {"content://com.google.android.gms.instantapps.devman/", "instant_apps"},
            {"content://com.android.launcher3.settings/favorites", "launcher_fav"},
            {"content://com.google.android.apps.nexuslauncher.settings/favorites", "pixel_launcher_fav"},
        };

        for (String[] entry : uris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(entry[0]), null, null, null, null);
                if (c != null) {
                    String[] cols = c.getColumnNames();
                    int count = c.getCount();
                    log("[OPEN] " + entry[1] + ": " + count + " rows, cols=" + String.join(",", cols));
                    // Show first few rows of interesting providers
                    if (count > 0 && count < 20) {
                        while (c.moveToNext()) {
                            StringBuilder row = new StringBuilder("  ");
                            for (int i = 0; i < Math.min(cols.length, 3); i++) {
                                String val = c.getString(i);
                                if (val != null && val.length() > 60) val = val.substring(0, 60) + "...";
                                row.append(cols[i]).append("=").append(val).append(" ");
                            }
                            log(row.toString());
                        }
                    }
                    c.close();
                } else {
                    log("[NULL] " + entry[1]);
                }
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && msg.length() > 60) msg = msg.substring(0, 60);
                log("[ERR] " + entry[1] + ": " + e.getClass().getSimpleName());
            }
        }

        // Test GMS phenotype with specific flags
        log("\n=== GMS Phenotype flags ===");
        String[] phenotypePackages = {
            "com.google.android.gms",
            "com.google.android.gms.auth",
            "com.google.android.gms.people",
            "com.google.android.gms.maps",
        };
        for (String pkg : phenotypePackages) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.google.android.gms.phenotype/" + pkg),
                    null, null, null, null);
                if (c != null) {
                    log("[OPEN] phenotype/" + pkg + ": " + c.getCount() + " rows");
                    c.close();
                }
            } catch (Exception e) {
                log("[ERR] phenotype/" + pkg + ": " + e.getClass().getSimpleName());
            }
        }

        // Test openFile on GMS providers
        log("\n=== GMS file access ===");
        String[][] gmsFiles = {
            {"content://com.google.android.gms.fonts/", "gms_fonts_root"},
            {"content://com.google.android.gms.auth.api.phone.consent/", "phone_consent"},
        };
        for (String[] f : gmsFiles) {
            try {
                InputStream is = getContentResolver().openInputStream(Uri.parse(f[0]));
                if (is != null) {
                    byte[] buf = new byte[128];
                    int read = is.read(buf);
                    is.close();
                    log("[OPEN FILE] " + f[1] + ": " + read + " bytes");
                }
            } catch (Exception e) {
                log("[ERR FILE] " + f[1] + ": " + e.getClass().getSimpleName());
            }
        }

        log("\n=== ALL TESTS COMPLETE ===");
    }
}
