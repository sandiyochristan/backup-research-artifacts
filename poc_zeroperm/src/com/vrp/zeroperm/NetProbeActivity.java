package com.vrp.zeroperm;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class NetProbeActivity extends Activity {
    private static final String T = "NET_PROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== GMS Network Port Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        new Thread(() -> {
            probePort("127.0.0.1", 38211, "raw_empty", new byte[0]);
            probePort("127.0.0.1", 38211, "http_get",
                "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes());
            probePort("127.0.0.1", 38211, "grpc_preface",
                "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes());

            byte[] mdnsQuery = new byte[]{
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x05, 0x5f, 0x68, 0x74,
                0x74, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05,
                0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, (byte)0xff, 0x00, 0x01
            };
            probePort("127.0.0.1", 38211, "mdns_query", mdnsQuery);

            // Nearby Share uses a custom protocol — try with various initial bytes
            byte[] nearbyHello = new byte[]{
                0x00, 0x00, 0x00, 0x04, // length
                0x08, 0x01, 0x10, 0x01  // protobuf: field 1=1, field 2=1
            };
            probePort("127.0.0.1", 38211, "nearby_proto", nearbyHello);

            // Try sending a protobuf-like handshake
            byte[] protoHandshake = new byte[]{
                0x0a, 0x02, 0x08, 0x01  // field 1 = {field 1 = 1}
            };
            probePort("127.0.0.1", 38211, "protobuf_hs", protoHandshake);

            // Try port 46213 on loopback (uid 10200)
            probePort("127.0.0.1", 46213, "loopback_raw", new byte[0]);
            probePort("127.0.0.1", 46213, "loopback_http",
                "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes());

            // Try all the external-facing ports
            probePort("192.168.1.7", 64660, "ext_64660", new byte[0]);
            probePort("192.168.1.7", 51692, "ext_51692", new byte[0]);
            probePort("192.168.1.7", 53601, "ext_53601", new byte[0]);

            Log.w(T, "=== Network probe complete ===");
        }).start();
    }

    private void probePort(String host, int port, String label, byte[] payload) {
        try {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(host, port), 3000);
            s.setSoTimeout(3000);
            Log.w(T, "[+] " + label + " connected to " + host + ":" + port);

            if (payload.length > 0) {
                OutputStream os = s.getOutputStream();
                os.write(payload);
                os.flush();
            }

            InputStream is = s.getInputStream();
            byte[] buf = new byte[4096];
            int read = -1;
            try {
                read = is.read(buf);
            } catch (java.net.SocketTimeoutException e) {
                Log.w(T, "[*] " + label + ": no response (timeout)");
            }

            if (read > 0) {
                StringBuilder hex = new StringBuilder();
                StringBuilder ascii = new StringBuilder();
                for (int i = 0; i < Math.min(read, 128); i++) {
                    hex.append(String.format("%02x", buf[i]));
                    if (buf[i] >= 32 && buf[i] < 127) ascii.append((char) buf[i]);
                    else ascii.append('.');
                }
                Log.w(T, "[!!!] " + label + " RESPONSE: " + read + " bytes");
                Log.w(T, "[!!!] HEX: " + hex.toString());
                Log.w(T, "[!!!] ASCII: " + ascii.toString());
            } else if (read == 0) {
                Log.w(T, "[*] " + label + ": 0 bytes");
            }

            s.close();
        } catch (java.net.ConnectException e) {
            Log.w(T, "[-] " + label + " " + host + ":" + port + " refused");
        } catch (Exception e) {
            Log.w(T, "[-] " + label + " " + host + ":" + port + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
