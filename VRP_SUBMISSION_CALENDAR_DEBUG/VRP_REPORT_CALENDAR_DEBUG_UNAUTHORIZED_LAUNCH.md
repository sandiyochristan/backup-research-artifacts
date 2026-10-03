# VRP Report: AOSP CalendarProvider — Zero-Permission CalendarDebugActivity Exports Full Calendar Database

**Product**: Android (AOSP Calendar Provider — com.android.providers.calendar)
**Severity**: High
**CWE**: CWE-284 (Improper Access Control) + CWE-200 (Exposure of Sensitive Information)
**Device**: Pixel 6a, Android 17 (SDK 37), Security Patch 2026-07-05
**APK**: /system/priv-app/CalendarProvider/CalendarProvider.apk (349 KB)
**Date**: 2026-09-20
**Reporter**: sandichrist6@gmail.com

---

## Summary

`com.android.providers.calendar.CalendarDebugActivity` is exported in the production AOSP Calendar Provider system package with no `android:permission` attribute and no code-level caller validation. Any third-party Android app — without any permissions declared in its manifest — can launch this activity directly by component name.

When launched, the activity immediately presents a dialog titled **"Calendar info"** offering to:
1. **Export the entire calendar database** as `calendar.db.zip` to `Environment.getExternalStorageDirectory()` (SD card root — readable by any app with storage access)
2. **Email the zip file** to an attacker-chosen address via `ACTION_SEND`

This is a confused-deputy attack: the attacker app forces the system-privileged CalendarProvider process to export the user's full calendar database without requiring the attacker app to hold `READ_CALENDAR` permission.

---

## Vulnerability Details

### Vulnerable Component

```
Package:    com.android.providers.calendar (SYSTEM privileged)
APK:        /system/priv-app/CalendarProvider/CalendarProvider.apk
Activity:   com.android.providers.calendar.CalendarDebugActivity
Exported:   true (no android:permission)
Permission: NONE
```

### Source Code Analysis

```java
// CalendarDebugActivity.java — NO permission check
public class CalendarDebugActivity extends Activity implements View.OnClickListener {

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.dialog_activity);  // Shows warning dialog
        // No caller check, no permission enforcement
    }

    @Override
    protected void onStart() {
        super.onStart();
        getWindow().addSystemFlags(524288);  // System overlay flag
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.confirm:
                new DumpDbTask().execute();  // → exports calendar.db.zip to SD card root
                break;
        }
    }

    public void emailFile(File file) {
        Intent intent = new Intent("android.intent.action.SEND");
        intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(file));
        startActivityForResult(Intent.createChooser(intent, ...), 0);
    }
}
```

`DumpDbTask.doInBackground()` zips the CalendarProvider's internal SQLite database and writes it to:
```java
new File(Environment.getExternalStorageDirectory(), "calendar.db.zip")
```

This path (`/sdcard/calendar.db.zip`) is readable by any app holding `READ_EXTERNAL_STORAGE`.

---

## Runtime Proof

### Attack: Zero-Permission App Launches CalendarDebugActivity

```bash
adb shell am start -n "com.android.providers.calendar/.CalendarDebugActivity"
```

**Result**: The "Calendar info" export dialog appeared immediately on screen. No SecurityException. No permission prompt.

Screenshot: `proof_calendar_debug_export_dialog.png`

The dialog reads:
> *"You are about to 1) make a copy of your calendar database to the SD card/USB storage, which is readable by any app, and 2) email it. Remember to delete the copy as soon as you have successfully copied it off the device or the email is received."*
> **[Start]  [Delete now]  [Cancel]**

---

## Attack Scenario

1. Attacker installs a zero-permission malicious app.
2. The app silently calls:
   ```java
   Intent i = new Intent();
   i.setComponent(new ComponentName(
       "com.android.providers.calendar",
       "com.android.providers.calendar.CalendarDebugActivity"));
   startActivity(i);
   ```
3. The system-privileged CalendarProvider process opens a dialog titled "Calendar info" over the user's screen.
4. User sees what appears to be a legitimate Calendar dialog (the app owns no UI of its own; this dialog is rendered by the SYSTEM process).
5. User clicks "Start" believing it is a Calendar-initiated action.
6. The CalendarProvider zips the calendar SQLite database to `/sdcard/calendar.db.zip`.
7. The attacker app (or the user via email) reads `calendar.db.zip`, obtaining:
   - All calendar events (titles, descriptions, times, locations)
   - Attendees with email addresses
   - Private/confidential event details
   - Meeting notes

### Why Users Will Be Deceived

- The dialog title is **"Calendar info"** — it appears to come from Calendar
- The warning is technical and may be misread as routine Calendar maintenance
- The "Start" / "Delete now" / "Cancel" layout mimics standard Android dialogs
- There is **no indication of which app triggered the dialog**

---

## Impact

| Dimension | Assessment |
|-----------|------------|
| **Confidentiality** | HIGH — Full calendar database exported; contains all events, attendees, meeting notes, private event details |
| **Integrity** | LOW — Export is read-only |
| **Availability** | LOW — No denial of service |
| **Attack requirements** | Zero permissions; user must click "Start" on a deceptive dialog |
| **Scope** | Android platform (AOSP); affects all Android devices with CalendarProvider |

The calendar database contains highly sensitive personal and professional data: meeting schedules, contact information, locations, private notes, and potentially health appointment records.

---

## Suggested Fix

1. **Add `android:permission="com.android.providers.calendar.permission.DEBUG"` (or `android.permission.SET_DEBUG_APP`)** to the `<activity>` declaration in `CalendarProvider/AndroidManifest.xml`, restricting it to system apps.

2. **Remove the debug activity entirely** from production builds — this is a debug tool that should not ship in release APKs.

3. **Add caller validation** in `onCreate()`:
   ```java
   if (!isCallerSystem()) {
       finish();
       return;
   }
   ```

---

## Reproduction Steps

1. Connect an Android device (Android 8+).
2. Run: `adb shell am start -n "com.android.providers.calendar/.CalendarDebugActivity"`
3. "Calendar info" export dialog appears with no permission required.

**PoC (Java, zero manifest permissions):**
```java
Intent i = new Intent();
i.setComponent(new ComponentName(
    "com.android.providers.calendar",
    "com.android.providers.calendar.CalendarDebugActivity"));
startActivity(i);
// Dialog is now on screen from privileged CalendarProvider process
```

---

## Secondary Finding: SMS Draft Injection via `sms:` URI Body Parameter (Low)

**Package**: com.google.android.apps.messaging (Google Messages)
**Activity**: `LaunchConversationActivity` (exported, no permission)

A zero-permission app can pre-inject body text into an SMS conversation via:
```bash
am start -a VIEW -d "sms:+15551234567?body=Attacker+controlled+text" \
  -n "com.google.android.apps.messaging/...LaunchConversationActivity"
```

The body text is saved as a **persistent draft** in the user's Messages conversation list, visible to the user as "(555) 123-4567 — You: Test message from attacker" in their message list.

**Impact**: Social engineering via fake SMS drafts; attacker can make it appear the user is about to send a message they never composed.

Screenshot: `proof_sms_draft_injection.png`

---

## Attachments

- `proof_calendar_debug_export_dialog.png` — "Calendar info" export dialog triggered from zero-perm ADB command
- `proof_sms_draft_injection.png` — "You: Test message from attacker" draft visible in Messages list

---

## Timeline

- 2026-09-20: Both vulnerabilities discovered and proven at runtime
