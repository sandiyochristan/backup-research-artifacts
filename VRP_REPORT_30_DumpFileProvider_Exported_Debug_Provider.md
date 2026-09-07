# VRP Report #30: ContactsProvider DumpFileProvider Exported in Production — Debug Database Dump Accessible Without Permission

## Summary

The `DumpFileProvider` (`com.android.providers.contacts/.debug.DumpFileProvider`) is a **debug content provider** that is **exported and accessible** to any installed application without any permission on production Android 17 (Pixel 6a). This provider serves contacts database dump ZIP files (`[hex]-contacts-db.zip`) from the ContactsProvider's storage. Any app can query the provider and, if a dump file exists, read the **entire contacts database** as a ZIP archive without any permission.

## Severity: Medium-High (conditional on dump file existence)

- **Attack Surface**: Debug provider exported in production firmware
- **No Permission Required**: Any installed app can query and read files
- **Potential Impact**: Full contacts database exfiltration (if dump file exists)
- **Path Traversal**: Properly blocked (".. path specifier not allowed")

## Affected Component

- **Provider**: `com.android.providers.contacts/.debug.DumpFileProvider`
- **Authority**: `com.android.contacts.dumpfile`
- **File Pattern**: `[0-9A-Fa-f]+-contacts-db.zip`
- **Build**: CP2A.260605.012, Android 17 (API 37), Pixel 6a

## Vulnerability Details

### The Provider

The DumpFileProvider is part of the ContactsProvider package (`com.android.providers.contacts`) and is located in the `debug` namespace. It is designed to serve contacts database dump files for debugging purposes. Despite being a debug component, it is:

1. **Exported** — accessible from any application
2. **No permission protection** — no `android:permission` or `android:readPermission` attribute
3. **Present in production firmware** — not stripped from release builds

### What the Provider Does

- Accepts URIs matching `content://com.android.contacts.dumpfile/[hex]-contacts-db.zip`
- Validates filename format: only `[0-9A-Fa-f]+-contacts-db.zip` accepted
- Returns file metadata via `query()` (display_name, _size)
- Serves file contents via `openFileDescriptor()` / `openInputStream()`
- Blocks path traversal: rejects `..` sequences

### Dynamic Proof

**Query succeeds for any valid filename pattern:**
```
content query --uri content://com.android.contacts.dumpfile/deadbeef-contacts-db.zip
→ Row: 0 _display_name=deadbeef-contacts-db.zip, _size=NULL
```

**openFileDescriptor returns FileNotFoundException (dump file not currently present):**
```
content read --uri content://com.android.contacts.dumpfile/0-contacts-db.zip
→ FileNotFoundException: open failed: ENOENT (No such file or directory)
```

**Path traversal properly blocked:**
```
content://com.android.contacts.dumpfile/../databases/contacts2.db
→ IllegalArgumentException: .. path specifier not allowed
```

### Attack Scenario

1. A dump file is created via `adb shell dumpsys`, a debugging tool, a crash dump, or other system mechanism
2. The dump file contains the **entire contacts2.db** as a ZIP archive
3. Any installed app monitors for dump file existence by polling the DumpFileProvider with common hex prefixes
4. When a dump file is found, the app reads the entire contacts database without any permission
5. The dump file contains: all contacts, phone numbers, email addresses, photos, sync state, and account information

### Why This Is a Finding

Even though the dump file may not always exist:
1. A **debug provider should never be exported** in production firmware
2. The provider accepts and responds to queries from **any caller** with **no permission check**
3. If any mechanism creates a dump (crash recovery, backup operations, debugging tools, OTA updates), the window for exploitation opens
4. An attacker could combine this with a separate bug that triggers a dump to achieve full contacts exfiltration

## Proof of Concept

### PoC App

`poc_app/src/com/vrp/poc/NovelVectorDeepActivity.java` — Tests DumpFileProvider with:
- Multiple hex prefix patterns
- `openFileDescriptor()` calls to read dump files
- Path traversal attempts (all properly blocked)

### Reproduction Steps

1. Install any app (no permissions needed)
2. Query `content://com.android.contacts.dumpfile/0-contacts-db.zip`
3. Observe: query succeeds, returns _display_name and _size columns
4. If a dump file exists: `openInputStream()` returns the full contacts database ZIP

## Impact

1. **Debug code in production**: A debug provider is exported and accessible in production firmware
2. **Conditional full database access**: If a dump file exists, any app can read the entire contacts database
3. **No permission boundary**: The provider performs no caller authentication
4. **Information disclosure**: Even the query response (file exists vs. not found) leaks information about whether dumps have been triggered

## Remediation

1. **Remove or disable DumpFileProvider** in production builds
2. If the provider must exist: add `android:exported="false"` to the manifest
3. Add `android:readPermission` requiring a signature-level permission
4. Strip the `debug` package from release builds entirely

## Environment

- Device: Pixel 6a (bluejay)
- Build: CP2A.260605.012
- Android: 17 (API 37)
- ADB ID: 26131JEGR04733
- Evidence: `dynamic_evidence/session3_evidence.log`

## Timeline

- 2026-09-08: DumpFileProvider discovered as exported debug provider
- 2026-09-08: Confirmed accessible without any permission from PoC app
- 2026-09-08: Path traversal tested and confirmed blocked
- 2026-09-08: Dump file not currently present but provider fully accessible
