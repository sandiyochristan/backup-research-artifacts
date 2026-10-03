import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class MassScan {
    public static void main(String[] args) throws Exception {
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method listServices = smClass.getMethod("listServices");
        Method getService = smClass.getMethod("getService", String.class);

        String[] services = (String[]) listServices.invoke(null);
        System.out.println("Total services: " + services.length);

        for (String svcName : services) {
            try {
                IBinder binder = (IBinder) getService.invoke(null, svcName);
                if (binder == null) continue;

                String iface = "?";
                try { iface = binder.getInterfaceDescriptor(); } catch (Exception e) {}

                // Test transaction 1 with empty/minimal data
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(iface);
                    binder.transact(1, data, reply, 0);
                    reply.readException();
                    int avail = reply.dataAvail();
                    if (avail > 20) {
                        // Only report services returning substantial data
                        System.out.println("DATA " + svcName + " (" + iface + ") txn1=" + avail + "b");
                    }
                } catch (SecurityException e) {
                    // Permission denied - expected for most services
                } catch (Exception e) {
                    String msg = e.getMessage();
                    if (msg != null && msg.contains("SecurityException")) {
                        // Also permission denied
                    } else if (msg != null && avail(reply) > 50) {
                        System.out.println("ERR+DATA " + svcName + " txn1 err=" + shorten(msg, 60) + " data=" + avail(reply) + "b");
                    }
                }
                data.recycle();
                reply.recycle();

                // Test transaction 2
                data = Parcel.obtain();
                reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(iface);
                    data.writeInt(0);
                    binder.transact(2, data, reply, 0);
                    reply.readException();
                    int avail2 = reply.dataAvail();
                    if (avail2 > 20) {
                        System.out.println("DATA " + svcName + " (" + iface + ") txn2=" + avail2 + "b");
                    }
                } catch (SecurityException e) {
                } catch (Exception e) {}
                data.recycle();
                reply.recycle();

            } catch (Exception e) {
                // Service not accessible, skip
            }
        }
        System.out.println("SCAN COMPLETE");
    }

    static int avail(Parcel p) {
        try { return p.dataAvail(); } catch (Exception e) { return 0; }
    }

    static String shorten(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
