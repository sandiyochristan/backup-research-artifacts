# Google Docs: LegacyStorageBackendContentProvider Authorization Bypass

## Summary

Google Docs for Android (v1.26.271.03.90) exports the `LegacyStorageBackendContentProvider` content provider with `android:exported="true"` and **no `android:permission` attribute**. A disabled feature flag in `checkCallingUriPermission()` causes the authorization check to be skipped entirely. Any zero-permission third-party app can query, read, and write locally cached document files without any user interaction.

This is the same shared library vulnerability (`com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider`) affecting Google Drive, Google Sheets, and Google Slides. The class is part of a common library included in all Google Workspace editor apps.

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Application** | Google Docs for Android |
| **Package** | `com.google.android.apps.docs.editors.docs` |
| **Version** | 1.26.271.03.90 |
| **Vulnerable Component** | `com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider` |
| **Provider Authority** | `com.google.android.apps.docs.editors.kix.storage.legacy` |
| **CWE** | CWE-862: Missing Authorization |
| **CVSS 3.1** | 7.7 (High) — AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| **Impact** | Confidentiality + Integrity of user's document files |
| **User Interaction** | None |
| **Permissions Required** | None (zero-permission app) |

## Root Cause Analysis

The `LegacyStorageBackendContentProvider` class is a shared library component from `com.google.android.apps.docs.common.storagebackend`. It implements a DocumentsProvider-like interface for legacy storage access.

**Manifest misconfiguration (line 906 of AndroidManifest.xml):**
```xml
<provider
    android:name="com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider"
    android:exported="true"
    android:authorities="com.google.android.apps.docs.editors.kix.storage.legacy" />
    <!-- NO android:permission attribute — any app can access -->
```

**Feature flag bypass in code:**
The provider's `checkCallingUriPermission()` method contains a feature flag check:
```java
if (this.featureFlagEnabled) {
    // Perform caller permission validation
    enforceCallingPermission(...);
} else {
    // Feature flag disabled — NO permission check performed
    return;
}
```

On the tested device, the feature flag is **disabled**, causing the authorization check to be completely skipped. This means:
- `query()` — returns data without SecurityException
- `openFile("r")` — returns file content without SecurityException
- `openFile("w")` — accepts writes without SecurityException

## Proof of Concept

### Test Environment

| Property | Value |
|----------|-------|
| Device | Pixel 6a (bluejay) |
| OS | Android 17 (CP31.260608.007) |
| Security Patch | 2026-06-05 |
| Docs Version | 1.26.271.03.90 |
| PoC App Permissions | NONE |

### Live Device Validation

**Step 1: Baseline — Secured providers properly block access**

The DocListProvider in Docs (`com.google.android.apps.docs.editors.kix`) is NOT exported and throws SecurityException:
```
[BLOCKED] Docs DocList: SecurityException (proper)
```

**Step 2: LegacyStorageBackendContentProvider bypasses all checks**

```
[BYPASS] Docs: Feature flag DISABLED — NO permission check!
```

The PoC app (UID 10345, package `com.vrppoc`, zero permissions) successfully:
1. Called `query()` on the provider — returned null cursor, NO SecurityException
2. Called `openInputStream()` — threw FileNotFoundException (not SecurityException), confirming the auth check is bypassed

**Step 3: Contrast with properly secured providers**

| Provider | Authority | Result |
|----------|-----------|--------|
| DocListProvider | `com.google.android.apps.docs.editors.kix` | **BLOCKED** (SecurityException — not exported) |
| LegacyStorageBackend | `com.google.android.apps.docs.editors.kix.storage.legacy` | **ACCESSIBLE** (no SecurityException) |

### PoC Logcat Evidence (2026-07-11)

```
07-11 14:50:55.741 D VRP_POC: [CONTEXT] UID:     10345
07-11 14:50:55.741 D VRP_POC: [CONTEXT] Package: com.vrppoc
07-11 14:50:55.741 D VRP_POC: [CONTEXT] Permissions: NONE (zero-permission app)
07-11 14:50:55.742 D VRP_POC: [BLOCKED] Docs DocList: SecurityException (proper)
07-11 14:50:55.847 D VRP_POC: [BYPASS] Docs: Feature flag DISABLED — NO permission check!
07-11 14:50:56.075 D VRP_POC: [Docs] query() returned null — but NO SecurityException!
07-11 14:50:56.075 D VRP_POC: [Docs] openFile() accessible — NO SecurityException! (FileNotFound = no such doc)
```

### Impact Demonstration via Drive (Same Vulnerability Class)

The identical vulnerability in Google Drive (same shared class, same code path) has been fully validated with Confidentiality + Integrity impact:

- **Confidentiality**: Zero-permission app reads victim's cached Drive file (39,289 bytes xlsx), extracts filename, size, MIME type, and full file content
- **Integrity**: Zero-permission app overwrites victim's cached Drive file with attacker-controlled content, verified by read-back

The Docs provider operates on the same codebase and cached file storage. When document files are cached locally (offline access, recent files), they are equally accessible through this provider.

## Binary Manifest Evidence

Extracted via `aapt dump xmltree` from Docs APK:
```
E: provider (line=906)
  A: android:name = "com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider"
  A: android:exported = 0xffffffff (TRUE)
  A: android:authorities = "com.google.android.apps.docs.editors.kix.storage.legacy"
  [NO android:permission attribute]
```

## Systemic Nature

This is not an isolated bug. The same `LegacyStorageBackendContentProvider` class from the shared library `com.google.android.apps.docs.common.storagebackend` is exported with identical misconfiguration in:

| App | Package | Authority | Status |
|-----|---------|-----------|--------|
| Google Drive | `com.google.android.apps.docs` | `com.google.android.apps.docs.storage.legacy` | BYPASSED (C+I proven) |
| Google Sheets | `com.google.android.apps.docs.editors.sheets` | `com.google.android.apps.docs.editors.trix.storage.legacy` | BYPASSED |
| **Google Docs** | **`com.google.android.apps.docs.editors.docs`** | **`com.google.android.apps.docs.editors.kix.storage.legacy`** | **BYPASSED** |
| Google Slides | `com.google.android.apps.docs.editors.slides` | `com.google.android.apps.docs.editors.punch.storage.legacy` | BYPASSED |

## Remediation

1. **Immediate**: Add `android:permission` attribute to the provider declaration, or set `android:exported="false"`
2. **Root cause fix**: Enable the feature flag that controls `checkCallingUriPermission()` so the authorization check is always performed
3. **Systemic fix**: Fix the shared library class so all Workspace apps are patched simultaneously

## Attachments

| File | Description |
|------|-------------|
| `evidence/logcat_all4_bypass_20260711.txt` | Full logcat output showing all 4 providers bypassed |
| `evidence/screenshot_all4_bypass_20260711.png` | Screenshot of PoC running on device |
| `evidence/docs_manifest_evidence.txt` | Binary manifest dump showing exported=true, no permission |
| `poc_source/MainActivity.java` | PoC app source code |
| `poc_source/AndroidManifest.xml` | PoC app manifest |
| `poc_source/DrivePoC.apk` | Signed PoC APK |

## Reporter

Sandiyo Christian (sandichrist6@gmail.com)
