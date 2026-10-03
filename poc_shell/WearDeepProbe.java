import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class WearDeepProbe {
    static final String IWEAR_DESC = "com.google.wear.services.IWear";
    static final int TXN_GET_WEAR_SERVICE = 1;

    public static void main(String[] args) throws Exception {
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getMethod("getService", String.class);
        IBinder wearBinder = (IBinder) getService.invoke(null, "wear_service");

        System.out.println("=== TELEPHONY API (should require READ_PHONE_STATE) ===");
        IBinder telephony = getSubService(wearBinder, "telephony");
        if (telephony != null) {
            String iface = telephony.getInterfaceDescriptor();
            // getEmergencyNumbers() -> Map (txn 1 or 2)
            // isEmergencyNumber(String) -> boolean (txn 1 or 2)
            for (int txn = 1; txn <= 3; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    data.writeInterfaceToken(iface);
                    if (txn == 2) data.writeString("911"); // for isEmergencyNumber
                    telephony.transact(txn, data, reply, 0);
                    reply.readException();
                    System.out.println("  txn " + txn + ": OK, reply=" + reply.dataAvail() + "b");
                    if (reply.dataAvail() > 0) {
                        byte[] raw = new byte[Math.min(reply.dataAvail(), 200)];
                        reply.readByteArray(raw);
                        System.out.println("  data: " + bytesToHex(raw, 100));
                    }
                    data.recycle(); reply.recycle();
                } catch (Exception e) {
                    System.out.println("  txn " + txn + ": " + e.getMessage());
                }
            }
        }

        System.out.println("\n=== REMOTE INTERACTIONS API ===");
        IBinder remoteInteractions = getSubService(wearBinder, "remote_interactions");
        if (remoteInteractions != null) {
            String iface = remoteInteractions.getInterfaceDescriptor();
            System.out.println("  Interface: " + iface);
            for (int txn = 1; txn <= 5; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    data.writeInterfaceToken(iface);
                    // Write some basic params for different methods
                    if (txn <= 2) {
                        data.writeString("https://example.com"); // URI param
                        data.writeStrongBinder(null); // callback
                    } else {
                        data.writeStrongBinder(null);
                    }
                    remoteInteractions.transact(txn, data, reply, 0);
                    reply.readException();
                    System.out.println("  txn " + txn + ": OK, reply=" + reply.dataAvail() + "b");
                    data.recycle(); reply.recycle();
                } catch (Exception e) {
                    String msg = e.getMessage();
                    if (msg != null && msg.length() > 200) msg = msg.substring(0, 200);
                    System.out.println("  txn " + txn + ": " + msg);
                }
            }
        }

        System.out.println("\n=== COMPLICATIONS API ===");
        IBinder complications = getSubService(wearBinder, "complications");
        if (complications != null) {
            String iface = complications.getInterfaceDescriptor();
            System.out.println("  Interface: " + iface);
            // Try first 5 transactions
            for (int txn = 1; txn <= 5; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    data.writeInterfaceToken(iface);
                    data.writeInt(0); // some int param
                    complications.transact(txn, data, reply, 0);
                    reply.readException();
                    System.out.println("  txn " + txn + ": OK, reply=" + reply.dataAvail() + "b");
                    data.recycle(); reply.recycle();
                } catch (Exception e) {
                    String msg = e.getMessage();
                    if (msg != null && msg.length() > 150) msg = msg.substring(0, 150);
                    System.out.println("  txn " + txn + ": " + msg);
                }
            }
        }

        System.out.println("\n=== NOTIFICATION API (testing mute operations) ===");
        IBinder notification = getSubService(wearBinder, "notification");
        if (notification != null) {
            String iface = notification.getInterfaceDescriptor();
            // Try getActiveNotifications (txn 3 based on AIDL order)
            // registerNotificationEventListener is txn 1
            // The interesting ones: getActiveNotifications, getMutedApps, getCurrentInterruptionFilter
            for (int txn = 1; txn <= 6; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    data.writeInterfaceToken(iface);
                    data.writeStrongBinder(null); // callback
                    notification.transact(txn, data, reply, 0);
                    reply.readException();
                    System.out.println("  txn " + txn + ": OK, reply=" + reply.dataAvail() + "b");
                    data.recycle(); reply.recycle();
                } catch (Exception e) {
                    String msg = e.getMessage();
                    if (msg != null && msg.length() > 200) msg = msg.substring(0, 200);
                    System.out.println("  txn " + txn + ": " + msg);
                }
            }
        }

        System.out.println("\n=== MEDIA API (all transactions) ===");
        IBinder media = getSubService(wearBinder, "media");
        if (media != null) {
            String iface = media.getInterfaceDescriptor();
            for (int txn = 1; txn <= 4; txn++) {
                try {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    data.writeInterfaceToken(iface);
                    data.writeString("com.spotify.music"); // package name
                    media.transact(txn, data, reply, 0);
                    reply.readException();
                    int avail = reply.dataAvail();
                    System.out.println("  txn " + txn + ": OK, reply=" + avail + "b");
                    if (avail > 0) {
                        // Try to read different types
                        try { System.out.println("    int: " + reply.readInt()); } catch (Exception e) {}
                    }
                    data.recycle(); reply.recycle();
                } catch (Exception e) {
                    System.out.println("  txn " + txn + ": " + e.getMessage());
                }
            }
        }
    }

    static IBinder getSubService(IBinder wearBinder, String id) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken(IWEAR_DESC);
        data.writeString(id);
        wearBinder.transact(TXN_GET_WEAR_SERVICE, data, reply, 0);
        reply.readException();
        IBinder binder = reply.readStrongBinder();
        data.recycle(); reply.recycle();
        return binder;
    }

    static String bytesToHex(byte[] bytes, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, max); i++) {
            sb.append(String.format("%02x", bytes[i]));
            if (i % 4 == 3) sb.append(" ");
        }
        return sb.toString();
    }
}
