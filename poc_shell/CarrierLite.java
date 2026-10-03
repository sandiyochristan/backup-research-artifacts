import android.os.IBinder;
import android.os.Parcel;
import android.os.Bundle;
import java.lang.reflect.Method;

public class CarrierLite {
    public static void main(String[] args) throws Exception {
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getMethod("getService", String.class);
        System.out.println("UID=" + android.os.Process.myUid());

        IBinder carrier = (IBinder) getService.invoke(null, "carrier_config");
        String iface = carrier.getInterfaceDescriptor();

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken(iface);
        data.writeInt(1); // subId
        data.writeString("com.android.shell");
        data.writeString(null);
        carrier.transact(1, data, reply, 0);
        reply.readException();

        // Read as Bundle
        Bundle b = reply.readBundle(CarrierLite.class.getClassLoader());
        if (b != null) {
            System.out.println("Bundle keys: " + b.keySet().size());
            // Look for sensitive keys
            String[] sensitiveKeys = {
                "carrier_name_string", "carrier_id_int",
                "carrier_nr_availabilities_int_array",
                "carrier_default_wfc_ims_roaming_enabled_bool",
                "carrier_volte_available_bool",
                "imsi_key_availability_int",
                "carrier_certificate_string_array",
                "carrier_config_version_string",
                "carrier_nr_availabilities_int_array",
                "carrier_metered_apn_types_strings",
                "gps.emergency_supl_server_string",
                "carrier_sim_provisioning_status_int",
                "iccid_string",
                "mccmnc_string",
                "carrier_provisioning_app_string"
            };
            for (String key : sensitiveKeys) {
                Object val = b.get(key);
                if (val != null) {
                    System.out.println("  " + key + " = " + val);
                }
            }
            // Also dump first 50 keys
            int count = 0;
            for (String key : b.keySet()) {
                if (count++ >= 50) break;
                Object val = b.get(key);
                String vs = String.valueOf(val);
                if (vs.length() > 80) vs = vs.substring(0, 80) + "...";
                System.out.println("  " + key + " = " + vs);
            }
        }
        data.recycle(); reply.recycle();
    }
}
