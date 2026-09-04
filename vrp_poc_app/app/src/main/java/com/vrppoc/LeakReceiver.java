package com.vrppoc;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.LinearLayout;
import android.view.Gravity;

public class LeakReceiver extends Activity {
    private static final String TAG = "VRP_LEAK";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 32, 32, 32);

        TextView tv = new TextView(this);
        tv.setTextSize(14);
        tv.setTextIsSelectable(true);

        Intent intent = getIntent();
        StringBuilder sb = new StringBuilder();
        sb.append("=== LEAKED DATA RECEIVED ===\n\n");
        sb.append("Action: ").append(intent.getAction()).append("\n");
        sb.append("Data: ").append(intent.getData()).append("\n");
        sb.append("Type: ").append(intent.getType()).append("\n");
        sb.append("Flags: 0x").append(Integer.toHexString(intent.getFlags())).append("\n");

        if (intent.getExtras() != null) {
            sb.append("\nExtras:\n");
            for (String key : intent.getExtras().keySet()) {
                Object val = intent.getExtras().get(key);
                sb.append("  ").append(key).append(" = ").append(val).append("\n");
                Log.d(TAG, "Extra: " + key + " = " + val);
            }
        }

        if (intent.getClipData() != null) {
            sb.append("\nClipData:\n");
            for (int i = 0; i < intent.getClipData().getItemCount(); i++) {
                sb.append("  [").append(i).append("] ").append(intent.getClipData().getItemAt(i)).append("\n");
            }
        }

        Log.d(TAG, sb.toString());
        tv.setText(sb.toString());
        layout.addView(tv);
        setContentView(layout);
    }
}
