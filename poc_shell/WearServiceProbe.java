import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class WearServiceProbe {
    // IWear descriptor
    static final String IWEAR_DESC = "com.google.wear.services.IWear";

    // IWear transaction codes (AIDL ordering)
    // 1: getWearService(String) -> IBinder
    // 2: getWearServicesInBatch(List<String>) -> Map<String, IBinder>
    // 3: handleShellCommand(...)
    static final int TXN_GET_WEAR_SERVICE = 1;

    public static void main(String[] args) throws Exception {
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getMethod("getService", String.class);

        // Get the IWear Binder (wear_service)
        IBinder wearBinder = (IBinder) getService.invoke(null, "wear_service");
        if (wearBinder == null) {
            System.out.println("ERROR: wear_service not found");
            return;
        }
        System.out.println("wear_service found: " + wearBinder);
        System.out.println("Interface: " + wearBinder.getInterfaceDescriptor());

        // Known service IDs from static analysis
        String[] serviceIds = {
            "media", "telephony", "notification", "complications",
            "tiles", "ongoing_activity", "remote_events", "remote_interactions",
            "migration", "companion_connection_status", "watchfaces", "watchface_editing"
        };

        for (String serviceId : serviceIds) {
            try {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(IWEAR_DESC);
                data.writeString(serviceId);
                boolean ok = wearBinder.transact(TXN_GET_WEAR_SERVICE, data, reply, 0);
                reply.readException();
                IBinder subBinder = reply.readStrongBinder();
                if (subBinder != null) {
                    String iface = "?";
                    try { iface = subBinder.getInterfaceDescriptor(); } catch (Exception e) {}
                    System.out.println("SERVICE [" + serviceId + "] => " + iface);

                    // For media, try calling isAutoLaunchEnabled (txn 1)
                    if ("media".equals(serviceId)) {
                        probeMediaApi(subBinder, iface);
                    }

                    // For remote_events, try calling querySupportedEvents (txn 1)
                    if ("remote_events".equals(serviceId)) {
                        probeRemoteEventsApi(subBinder, iface);
                    }
                } else {
                    System.out.println("SERVICE [" + serviceId + "] => null (not registered)");
                }
                data.recycle();
                reply.recycle();
            } catch (Exception e) {
                System.out.println("SERVICE [" + serviceId + "] => ERROR: " + e.getMessage());
            }
        }
    }

    static void probeMediaApi(IBinder binder, String iface) {
        System.out.println("  Probing MediaApi...");
        try {
            // isAutoLaunchEnabled(String packageName) -> int
            // Transaction 1 on IMediaApi
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            data.writeString("com.google.android.apps.maps");
            binder.transact(1, data, reply, 0);
            reply.readException();
            int result = reply.readInt();
            System.out.println("  isAutoLaunchEnabled(maps) = " + result + " (0=unknown, 1=disabled, 2=enabled)");
            data.recycle();
            reply.recycle();

            // showAutoLaunchSettings(String callerPackageName) -> boolean
            // Transaction 2 on IMediaApi
            data = Parcel.obtain();
            reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            data.writeString("com.evil.attacker");
            binder.transact(2, data, reply, 0);
            reply.readException();
            boolean shown = reply.readInt() != 0;
            System.out.println("  showAutoLaunchSettings(evil) = " + shown);
            data.recycle();
            reply.recycle();
        } catch (Exception e) {
            System.out.println("  MediaApi error: " + e.getMessage());
        }
    }

    static void probeRemoteEventsApi(IBinder binder, String iface) {
        System.out.println("  Probing RemoteEventsApi...");
        try {
            // querySupportedEvents takes a callback, so we can't easily call it
            // from app_process. Instead, let's try sendRemoteEvent with a basic event
            // to see if we get a permission error or something else.

            // Try transaction 1 (querySupportedEvents) - takes ICallback
            // For now, just try raw transactions to see what works
            for (int txn = 1; txn <= 3; txn++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(iface);
                // Write a null callback binder
                data.writeStrongBinder(null);
                try {
                    binder.transact(txn, data, reply, 0);
                    reply.readException();
                    System.out.println("  txn " + txn + ": OK, reply=" + reply.dataAvail() + "b");
                } catch (Exception e) {
                    System.out.println("  txn " + txn + ": " + e.getMessage());
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            System.out.println("  RemoteEventsApi error: " + e.getMessage());
        }
    }
}
