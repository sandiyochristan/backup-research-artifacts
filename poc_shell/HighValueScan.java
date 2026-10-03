import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class HighValueScan {
    static Method getService;

    public static void main(String[] args) throws Exception {
        Class<?> sm = Class.forName("android.os.ServiceManager");
        getService = sm.getMethod("getService", String.class);
        System.out.println("UID: " + android.os.Process.myUid());

        scanPhoneSubInfo();
        scanSms();
        scanClipboard();
        scanNotification();
        scanNfc();
        scanTrust();
        scanUsageStats();
        scanMediaSession();
        scanWearService();
        scanWearPower();
        scanCompanion();
        scanTaskContinuity();
        scanSimPhonebook();
        scanSupervision();
    }

    static IBinder svc(String name) throws Exception {
        return (IBinder) getService.invoke(null, name);
    }

    static String probe(IBinder b, String iface, int txn, byte[] extraData) {
        Parcel d = Parcel.obtain();
        Parcel r = Parcel.obtain();
        try {
            d.writeInterfaceToken(iface);
            if (extraData != null) d.unmarshall(extraData, 0, extraData.length);
            b.transact(txn, d, r, 0);
            r.setDataPosition(0);
            int ex = r.readInt();
            int avail = r.dataAvail();
            if (ex == 0) {
                if (avail > 4) {
                    byte[] raw = new byte[Math.min(avail, 1024)];
                    r.readByteArray(raw);
                    String strings = extractStrings(raw);
                    return "OK " + avail + "b" + (strings.isEmpty() ? "" : " [" + strings + "]");
                }
                return "OK " + avail + "b";
            } else {
                String msg = r.readString();
                if (msg == null) msg = "";
                if (msg.length() > 120) msg = msg.substring(0, 120);
                return "ex=" + ex + " " + msg;
            }
        } catch (Exception e) {
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            d.recycle();
            r.recycle();
        }
    }

    static void scanPhoneSubInfo() throws Exception {
        System.out.println("\n=== IPhoneSubInfo (IMEI/phone number) ===");
        IBinder b = svc("iphonesubinfo");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        System.out.println("Interface: " + iface);
        for (int txn = 1; txn <= 20; txn++) {
            String r = probe(b, iface, txn, null);
            if (r.contains("OK") && !r.equals("OK 0b") && !r.equals("OK 4b")) {
                System.out.println("  txn" + txn + ": " + r);
            } else if (r.contains("Security") || r.contains("permission")) {
                System.out.println("  txn" + txn + ": BLOCKED - " + r);
            }
        }
        // Try with subId=0 and callingPackage
        System.out.println("  --- With subId args ---");
        for (int txn = 1; txn <= 15; txn++) {
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            try {
                d.writeInterfaceToken(iface);
                d.writeInt(0); // subId
                d.writeString("com.vrp.appops"); // callingPkg
                d.writeString(null); // callingFeatureId
                b.transact(txn, d, r, 0);
                r.setDataPosition(0);
                int ex = r.readInt();
                int avail = r.dataAvail();
                if (ex == 0 && avail > 4) {
                    byte[] raw = new byte[Math.min(avail, 256)];
                    r.readByteArray(raw);
                    String s = extractStrings(raw);
                    System.out.println("  txn" + txn + " (subId): " + avail + "b [" + s + "]");
                } else if (ex != 0) {
                    String msg = r.readString();
                    if (msg != null && (msg.contains("Security") || msg.contains("READ_PHONE"))) {
                        System.out.println("  txn" + txn + ": PERM: " + (msg.length() > 80 ? msg.substring(0,80) : msg));
                    }
                }
            } catch (Exception e) {
                // skip
            } finally {
                d.recycle();
                r.recycle();
            }
        }
    }

    static void scanSms() throws Exception {
        System.out.println("\n=== ISms (SMS operations) ===");
        IBinder b = svc("isms");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        System.out.println("Interface: " + iface);
        for (int txn = 1; txn <= 15; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.contains("not fully consumed") && !r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanClipboard() throws Exception {
        System.out.println("\n=== IClipboard (clipboard data) ===");
        IBinder b = svc("clipboard");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 10; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.contains("not fully consumed") && !r.equals("OK 0b") && !r.equals("OK 4b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
        // Try getPrimaryClip with package name
        Parcel d = Parcel.obtain();
        Parcel r = Parcel.obtain();
        try {
            d.writeInterfaceToken(iface);
            d.writeString("com.vrp.appops");
            d.writeString(null); // attribution
            d.writeInt(0); // userId
            d.writeInt(0); // deviceId
            b.transact(2, d, r, 0);
            r.setDataPosition(0);
            int ex = r.readInt();
            int avail = r.dataAvail();
            if (ex == 0 && avail > 4) {
                byte[] raw = new byte[Math.min(avail, 512)];
                r.readByteArray(raw);
                System.out.println("  getPrimaryClip: " + avail + "b [" + extractStrings(raw) + "]");
            } else if (ex != 0) {
                String msg = r.readString();
                System.out.println("  getPrimaryClip: " + (msg != null ? msg.substring(0, Math.min(msg.length(), 80)) : "denied"));
            }
        } catch (Exception e) {
            System.out.println("  getPrimaryClip: " + e.getMessage());
        } finally {
            d.recycle();
            r.recycle();
        }
    }

    static void scanNotification() throws Exception {
        System.out.println("\n=== INotificationManager ===");
        IBinder b = svc("notification");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 25; txn++) {
            String r = probe(b, iface, txn, null);
            if (r.contains("OK") && !r.equals("OK 0b") && !r.equals("OK 4b")) {
                System.out.println("  txn" + txn + ": " + r);
            } else if (r.contains("Security") || r.contains("permission")) {
                // skip - expected
            }
        }
    }

    static void scanNfc() throws Exception {
        System.out.println("\n=== INfcAdapter (NFC) ===");
        IBinder b = svc("nfc");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 20; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.contains("not fully consumed") && !r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanTrust() throws Exception {
        System.out.println("\n=== ITrustManager ===");
        IBinder b = svc("trust");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 15; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.contains("not fully consumed") && !r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanUsageStats() throws Exception {
        System.out.println("\n=== IUsageStatsManager ===");
        IBinder b = svc("usagestats");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 15; txn++) {
            String r = probe(b, iface, txn, null);
            if (r.contains("OK") && !r.equals("OK 0b") && !r.equals("OK 4b")) {
                System.out.println("  txn" + txn + ": " + r);
            } else if (r.contains("Security") || r.contains("permission")) {
                System.out.println("  txn" + txn + ": BLOCKED");
            }
        }
    }

    static void scanMediaSession() throws Exception {
        System.out.println("\n=== ISessionManager (media) ===");
        IBinder b = svc("media_session");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 10; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.contains("not fully consumed") && !r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanWearService() throws Exception {
        System.out.println("\n=== IWear (Wear-specific) ===");
        IBinder b = svc("wear_service");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        System.out.println("Interface: " + iface);
        for (int txn = 1; txn <= 30; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.contains("not fully consumed") && !r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanWearPower() throws Exception {
        System.out.println("\n=== IWearPowerService ===");
        IBinder b = svc("WearPowerService");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        System.out.println("Interface: " + iface);
        for (int txn = 1; txn <= 15; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.contains("not fully consumed") && !r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanCompanion() throws Exception {
        System.out.println("\n=== ICompanionDeviceManager ===");
        IBinder b = svc("companiondevice");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 15; txn++) {
            String r = probe(b, iface, txn, null);
            if (r.contains("OK") && !r.equals("OK 0b") && !r.equals("OK 4b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanTaskContinuity() throws Exception {
        System.out.println("\n=== ITaskContinuityManager ===");
        IBinder b = svc("task_continuity");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 10; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanSimPhonebook() throws Exception {
        System.out.println("\n=== IIccPhoneBook (SIM contacts) ===");
        IBinder b = svc("simphonebook");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 10; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.contains("not fully consumed") && !r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static void scanSupervision() throws Exception {
        System.out.println("\n=== ISupervisionManager ===");
        IBinder b = svc("supervision");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        for (int txn = 1; txn <= 10; txn++) {
            String r = probe(b, iface, txn, null);
            if (!r.equals("OK 0b")) {
                System.out.println("  txn" + txn + ": " + r);
            }
        }
    }

    static String extractStrings(byte[] data) {
        StringBuilder result = new StringBuilder();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < data.length - 1; i += 2) {
            char c = (char)((data[i] & 0xff) | ((data[i+1] & 0xff) << 8));
            if (c >= 32 && c < 127) {
                current.append(c);
            } else if (current.length() > 3) {
                if (result.length() > 0) result.append(", ");
                result.append(current);
                current.setLength(0);
            } else {
                current.setLength(0);
            }
        }
        if (current.length() > 3) {
            if (result.length() > 0) result.append(", ");
            result.append(current);
        }
        return result.toString();
    }
}
