import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import java.lang.reflect.Method;

public class PermCheck {
    static final String IWEAR_DESC = "com.google.wear.services.IWear";

    public static void main(String[] args) throws Exception {
        System.out.println("Running as UID=" + Process.myUid() + " PID=" + Process.myPid());

        // Check specific permissions
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getMethod("getService", String.class);

        // Check via activity_service or package_manager if we have specific permissions
        // Use checkPermission via IActivityManager
        IBinder amBinder = (IBinder) getService.invoke(null, "activity");
        String amIface = amBinder.getInterfaceDescriptor();
        System.out.println("ActivityManager interface: " + amIface);

        // Instead, check via Context-less approach: try to call service and check
        // what error messages we get

        // Get IWear and test services
        IBinder wearBinder = (IBinder) getService.invoke(null, "wear_service");

        // Test Telephony API (should need READ_PHONE_STATE)
        System.out.println("\n=== TELEPHONY getEmergencyNumbers ===");
        IBinder telephony = getSubService(wearBinder, "telephony");
        if (telephony != null) {
            String iface = telephony.getInterfaceDescriptor();
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            telephony.transact(1, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            System.out.println("  Reply size: " + avail + " bytes");
            if (avail > 0) {
                // Read as raw hex
                byte[] raw = new byte[Math.min(avail, 500)];
                reply.readByteArray(raw);
                // Look for emergency numbers - Map<Integer, List<EmergencyNumber>>
                // Try to interpret: first int is map size
                Parcel p2 = Parcel.obtain();
                p2.unmarshall(raw, 0, raw.length);
                p2.setDataPosition(0);
                System.out.println("  Raw hex (first 200): " + bytesToHex(raw, 200));
                // Try to extract strings
                StringBuilder strings = new StringBuilder();
                for (int i = 0; i < raw.length - 1; i++) {
                    if (raw[i] >= 0x30 && raw[i] <= 0x39 && (i == 0 || raw[i-1] == 0)) {
                        // Potential number
                        StringBuilder num = new StringBuilder();
                        for (int j = i; j < raw.length && raw[j] >= 0x20 && raw[j] < 0x7f; j += 2) {
                            num.append((char)raw[j]);
                        }
                        if (num.length() > 1) {
                            strings.append(num).append(" ");
                        }
                    }
                }
                System.out.println("  Extracted numbers: " + strings);
                p2.recycle();
            }
            data.recycle(); reply.recycle();
        }

        // Test Complications API
        System.out.println("\n=== COMPLICATIONS API ===");
        IBinder comp = getSubService(wearBinder, "complications");
        if (comp != null) {
            String iface = comp.getInterfaceDescriptor();
            // Try getActiveProviders or similar — txn 2 returned 4b
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            data.writeInt(0);
            comp.transact(2, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            System.out.println("  txn 2 reply: " + avail + "b");
            if (avail > 0) {
                int val = reply.readInt();
                System.out.println("  value: " + val);
            }
            data.recycle(); reply.recycle();
        }

        // Check Notification API more carefully — test with better params
        System.out.println("\n=== NOTIFICATION getCurrentInterruptionFilter (txn 5) ===");
        IBinder notif = getSubService(wearBinder, "notification");
        if (notif != null) {
            String iface = notif.getInterfaceDescriptor();
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            notif.transact(5, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            System.out.println("  reply: " + avail + "b");
            if (avail > 0) {
                int val = reply.readInt();
                System.out.println("  interruption filter: " + val + " (1=ALL, 2=PRIORITY, 3=NONE, 4=ALARMS)");
            }
            data.recycle(); reply.recycle();

            // Try getNotificationCountData (txn 10)
            System.out.println("\n=== NOTIFICATION getNotificationCountData ===");
            data = Parcel.obtain();
            reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            data.writeStrongBinder(null); // callback
            notif.transact(10, data, reply, 0);
            try {
                reply.readException();
                System.out.println("  txn 10: OK, reply=" + reply.dataAvail() + "b");
            } catch (Exception e) {
                System.out.println("  txn 10: " + e.getMessage());
            }
            data.recycle(); reply.recycle();
        }
    }

    static IBinder getSubService(IBinder wearBinder, String id) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken(IWEAR_DESC);
        data.writeString(id);
        wearBinder.transact(1, data, reply, 0);
        reply.readException();
        IBinder binder = reply.readStrongBinder();
        data.recycle(); reply.recycle();
        return binder;
    }

    static String bytesToHex(byte[] bytes, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, max); i++) {
            sb.append(String.format("%02x", bytes[i]));
            if (i % 2 == 1) sb.append(" ");
            if (i % 32 == 31) sb.append("\n    ");
        }
        return sb.toString();
    }
}
