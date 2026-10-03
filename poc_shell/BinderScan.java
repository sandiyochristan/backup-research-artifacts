import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class BinderScan {
    static Class<?> smClass;
    static Method getService;

    public static void main(String[] args) throws Exception {
        smClass = Class.forName("android.os.ServiceManager");
        getService = smClass.getMethod("getService", String.class);

        System.out.println("UID: " + android.os.Process.myUid());

        // Test 1: AppOps getOpsForPackage with correct Parcel format
        testAppOps();

        // Test 2: HealthService
        testHealthService();

        // Test 3: Scan interesting Wear OS services
        scanWearServices();
    }

    static IBinder svc(String name) throws Exception {
        return (IBinder) getService.invoke(null, name);
    }

    static void testAppOps() throws Exception {
        System.out.println("\n=== AppOps Service Scan ===");
        IBinder b = svc("appops");
        if (b == null) { System.out.println("not found"); return; }
        String iface = b.getInterfaceDescriptor();
        System.out.println("Interface: " + iface);

        // Scan all transactions to find which ones work
        for (int txn = 1; txn <= 25; txn++) {
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            try {
                d.writeInterfaceToken(iface);
                // Write a minimal valid payload
                d.writeInt(10103); // gms uid
                d.writeString("com.google.android.gms");
                boolean ok = b.transact(txn, d, r, 0);
                r.setDataPosition(0);
                int exCode = r.readInt(); // exception code
                int avail = r.dataAvail();
                if (exCode == 0 && avail > 0) {
                    System.out.println("  txn " + txn + ": OK data=" + avail + " bytes");
                } else if (exCode == 0) {
                    System.out.println("  txn " + txn + ": OK (empty)");
                } else {
                    // Read exception string
                    String msg = r.readString();
                    if (msg != null && msg.length() > 80) msg = msg.substring(0, 80);
                    System.out.println("  txn " + txn + ": ex=" + exCode + " " + msg);
                }
            } catch (Exception e) {
                String m = e.getMessage();
                if (m != null && m.length() > 60) m = m.substring(0, 60);
                System.out.println("  txn " + txn + ": " + e.getClass().getSimpleName() + " " + m);
            } finally {
                d.recycle();
                r.recycle();
            }
        }

        // Now try getOpsForPackage with ops=null (writeInt(-1) as size)
        System.out.println("\n--- getOpsForPackage null ops format ---");
        int[] uids = {10103, 10016, 10066}; // gms, wearable, wallet
        String[] pkgs = {"com.google.android.gms", "com.google.android.wearable.app", "com.google.android.apps.walletnfcrel"};
        for (int txn : new int[]{3, 4, 5, 6, 7, 8}) {
            for (int i = 0; i < uids.length; i++) {
                Parcel d = Parcel.obtain();
                Parcel r = Parcel.obtain();
                try {
                    d.writeInterfaceToken(iface);
                    d.writeInt(uids[i]);
                    d.writeString(pkgs[i]);
                    d.writeInt(-1); // null ops array
                    b.transact(txn, d, r, 0);
                    r.setDataPosition(0);
                    int ex = r.readInt();
                    int avail = r.dataAvail();
                    if (ex == 0 && avail > 4) {
                        System.out.println("  txn" + txn + " " + pkgs[i] + ": data=" + avail);
                    }
                } catch (Exception e) {
                    // skip
                } finally {
                    d.recycle();
                    r.recycle();
                }
            }
        }
    }

    static void testHealthService() throws Exception {
        System.out.println("\n=== HealthService ===");
        IBinder b = svc("HealthService");
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
                if (ex == 0) {
                    System.out.println("  txn" + txn + ": " + avail + " bytes");
                } else {
                    String msg = r.readString();
                    if (msg != null && msg.length() > 100) msg = msg.substring(0, 100);
                    System.out.println("  txn" + txn + ": ex=" + ex + " " + (msg != null ? msg : ""));
                }
            } catch (Exception e) {
                System.out.println("  txn" + txn + ": " + e.getClass().getSimpleName());
            } finally {
                d.recycle();
                r.recycle();
            }
        }
    }

    static void scanWearServices() throws Exception {
        System.out.println("\n=== Scanning Interesting Wear Services ===");
        String[] services = {
            "WearableSensingService",
            "wearable_sensing",
            "notification",
            "statusbar",
            "media.audio_flinger",
            "bluetooth_manager",
            "usb",
            "wallpaper",
            "dreams",
            "accessibility",
            "alarm",
            "location",
            "display",
            "power",
            "battery",
            "telephony.registry",
            "content",
            "account",
            "input",
            "window",
            "activity",
        };

        for (String name : services) {
            IBinder b = svc(name);
            if (b == null) continue;
            try {
                String iface = b.getInterfaceDescriptor();
                // Try a few transactions without args to see what leaks
                for (int txn = 1; txn <= 5; txn++) {
                    Parcel d = Parcel.obtain();
                    Parcel r = Parcel.obtain();
                    try {
                        d.writeInterfaceToken(iface);
                        b.transact(txn, d, r, 0);
                        r.setDataPosition(0);
                        int ex = r.readInt();
                        int avail = r.dataAvail();
                        if (ex == 0 && avail > 100) {
                            System.out.println("  " + name + " txn" + txn + ": " + avail + " bytes!");
                        }
                    } catch (Exception e) {
                        // skip
                    } finally {
                        d.recycle();
                        r.recycle();
                    }
                }
            } catch (Exception e) {
                // skip
            }
        }
    }
}
