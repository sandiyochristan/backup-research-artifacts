# VRP Report #33: SystemUI MediaProjection Consent-Reuse Confused Deputy — Potential Silent Screen Capture

## Summary
SystemUI's `MediaProjectionPermissionActivity` is exported with no permission, `showForAllUsers=true`, and `visibleToInstantApps=true`. When `getCallingPackage()` returns null, the activity reads a package name from the attacker-controlled intent extra `extra_media_projection_package_reusing_consent` and uses it to check if that package has an existing MediaProjection grant. If so, it creates or reuses a MediaProjection token and returns it via `setResult()` — potentially allowing a confused-deputy attack where an untrusted app obtains a screen-capture token by impersonating a legitimately-granted package.

**STATUS: Needs device testing to confirm result delivery mechanism and timing window.**

## Affected Component
- **App**: SystemUI (SystemUIGoogle.apk)
- **Activity**: `com.android.systemui.mediaprojection.permission.MediaProjectionPermissionActivity`
- **Manifest** (line 405): `exported="true"`, NO permission, `showForAllUsers="true"`, `visibleToInstantApps="true"`, `launchMode="singleTop"`
- **File**: `com/android/systemui/mediaprojection/permission/MediaProjectionPermissionActivity.java`

## Vulnerability Details

### Code Flow (lines 96-131)
```java
// Line 100: Default to launching package
this.mPackageName = getLaunchedFromPackage();

// Line 101-106: When getCallingPackage() is null, trust the intent extra
if (getCallingPackage() == null) {
    if (!intent.hasExtra("extra_media_projection_package_reusing_consent")) {
        finishAsCancelled(); return;
    }
    // ATTACKER-CONTROLLED: package name from intent extra
    this.mPackageName = intent.getStringExtra("extra_media_projection_package_reusing_consent");
}

// Line 110: Get ApplicationInfo for the attacker-supplied package
ApplicationInfo applicationInfo = packageManager.getApplicationInfo(this.mPackageName, 0);
int i2 = applicationInfo.uid;
this.mUid = i2;

// Line 114: Check if that package has existing projection permission
boolean zHasProjectionPermission = MediaProjectionServiceHelper.service
    .hasProjectionPermission(i2, this.mPackageName);

// Lines 117-131: If YES — skip consent dialog, return projection token
if (zHasProjectionPermission) {
    IMediaProjection proj = MediaProjectionServiceHelper.Companion
        .createOrReuseProjection(this.mUid, 0, this.mPackageName, false);
    Intent intent2 = new Intent();
    intent2.putExtra("android.media.projection.extra.EXTRA_MEDIA_PROJECTION", proj.asBinder());
    setResult(-1, intent2);  // RESULT_OK with projection binder
    finish(1, proj);
    return;
}
```

### Attack Prerequisites
1. A legitimate app (e.g., Chromecast, Google Meet, a screen mirroring app) must currently have or recently had an active MediaProjection session
2. Attacker must trigger `getCallingPackage() == null` while still being able to receive the result

### Key Question (Needs Device Testing)
The `getCallingPackage()` null path and `setResult()` result delivery may be incompatible in standard Android activity lifecycle:
- `startActivityForResult()` → `getCallingPackage()` returns caller's package (not null)
- `startActivity()` → `getCallingPackage()` returns null, but `setResult()` has no recipient

Potential bypasses to investigate on device:
1. `FLAG_ACTIVITY_NEW_TASK` + `startActivityForResult()` behavior on Android 17
2. Using `startIntentSender()` or `PendingIntent` mechanisms
3. Task reparenting with `singleTop` launch mode
4. Cross-user launch via `showForAllUsers=true`

Even without result delivery, the confused deputy can:
- **Disrupt existing projections**: `createOrReuseProjection` may terminate/replace the victim's session
- **Information disclosure**: `hasProjectionPermission` oracle reveals which packages have active projection grants

## Impact (If Result Delivery Confirmed)
- **CRITICAL**: Silent screen capture without user consent
- An untrusted app (even an instant app) can obtain a working `IMediaProjection` binder
- Captures all on-screen content: banking apps, 2FA codes, messages, passwords
- No user interaction required (no consent dialog shown on the reuse path)

## Impact (Minimum, Confirmed Statically)
- **MEDIUM**: Confused deputy allows disruption of legitimate MediaProjection sessions
- **LOW**: Information disclosure about which packages have active projection grants

## Proof of Concept
```java
// Test consent-reuse path
Intent intent = new Intent();
intent.setComponent(new ComponentName(
    "com.android.systemui",
    "com.android.systemui.mediaprojection.permission.MediaProjectionPermissionActivity"));
intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
intent.putExtra("extra_media_projection_package_reusing_consent",
    "com.google.android.apps.chromecast.app");
intent.putExtra("extra_media_projection_user_consent_required", false);
startActivityForResult(intent, 1001);
```

## Fix Recommendation
1. When `getCallingPackage()` is null, do NOT trust `extra_media_projection_package_reusing_consent` from external callers
2. Verify that the launching app's UID matches the UID of the package named in the extra
3. Add a signature-level permission requirement to the activity manifest entry
4. Consider removing `visibleToInstantApps=true` — instant apps should not access MediaProjection

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- SystemUI (SystemUIGoogle.apk) as bundled with the build
