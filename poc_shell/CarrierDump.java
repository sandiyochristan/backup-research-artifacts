import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;
import java.io.FileOutputStream;

public class CarrierDump {
    public static void main(String[] args) throws Exception {
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getMethod("getService", String.class);

        System.out.println("UID=" + android.os.Process.myUid());

        // Test carrier_config
        System.out.println("\n=== CARRIER_CONFIG ===");
        IBinder carrier = (IBinder) getService.invoke(null, "carrier_config");
        if (carrier != null) {
            String iface = carrier.getInterfaceDescriptor();
            System.out.println("Interface: " + iface);

            // getConfigForSubId(int subId, String callingPackage, String callingFeatureId)
            // txn 1 on ICarrierConfigLoader
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            data.writeInt(0); // subId = 0
            data.writeString("com.android.shell"); // callingPackage
            data.writeString(null); // callingFeatureId
            carrier.transact(1, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            System.out.println("Reply size: " + avail + " bytes");

            // Save raw data
            if (avail > 0) {
                byte[] raw = new byte[avail];
                reply.readByteArray(raw);
                FileOutputStream fos = new FileOutputStream("/data/local/tmp/carrier_config.bin");
                fos.write(raw);
                fos.close();
                System.out.println("Saved to /data/local/tmp/carrier_config.bin");

                // Extract readable strings
                StringBuilder sb = new StringBuilder();
                StringBuilder current = new StringBuilder();
                for (byte b : raw) {
                    if (b >= 0x20 && b < 0x7f) {
                        current.append((char)b);
                    } else {
                        if (current.length() > 4) {
                            sb.append(current).append("\n");
                        }
                        current.setLength(0);
                    }
                }
                System.out.println("\n--- STRINGS IN CARRIER CONFIG ---");
                String[] lines = sb.toString().split("\n");
                for (String line : lines) {
                    if (line.length() > 4) {
                        System.out.println("  " + line);
                    }
                }
            }
            data.recycle(); reply.recycle();
        }

        // Test device_identifiers
        System.out.println("\n=== DEVICE_IDENTIFIERS ===");
        IBinder devId = (IBinder) getService.invoke(null, "device_identifiers");
        if (devId != null) {
            String iface = devId.getInterfaceDescriptor();
            System.out.println("Interface: " + iface);
            // getDeviceIdentifierForPackage txn 1
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            data.writeString("com.android.shell"); // callingPackage
            data.writeString(null); // callingFeatureId
            devId.transact(1, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            System.out.println("Reply: " + avail + " bytes");
            if (avail > 0) {
                byte[] raw = new byte[avail];
                reply.readByteArray(raw);
                System.out.println("Hex: " + bytesToHex(raw, 64));
                // Try reading as strings
                StringBuilder sb = new StringBuilder();
                for (byte b : raw) {
                    if (b >= 0x20 && b < 0x7f) sb.append((char)b);
                    else if (sb.length() > 0) { System.out.println("  String: " + sb); sb.setLength(0); }
                }
                if (sb.length() > 0) System.out.println("  String: " + sb);
            }
            data.recycle(); reply.recycle();
        }

        // Test storaged_pri
        System.out.println("\n=== STORAGED_PRI ===");
        IBinder stored = (IBinder) getService.invoke(null, "storaged_pri");
        if (stored != null) {
            String iface = stored.getInterfaceDescriptor();
            System.out.println("Interface: " + iface);
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(iface);
            stored.transact(1, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            System.out.println("Reply: " + avail + " bytes");
            // Just report size — storage data parsing is complex
            data.recycle(); reply.recycle();
        }
    }

    static String bytesToHex(byte[] bytes, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, max); i++) {
            sb.append(String.format("%02x", bytes[i]));
            if (i % 2 == 1) sb.append(" ");
        }
        return sb.toString();
    }
}
