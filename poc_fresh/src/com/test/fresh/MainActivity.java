package com.test.fresh;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setText("UID=" + android.os.Process.myUid() + " LAUNCHED OK");
        tv.setTextSize(14f);
        setContentView(tv);
        Log.i("FRESH_TEST", "LAUNCHED UID=" + android.os.Process.myUid());
    }
}
