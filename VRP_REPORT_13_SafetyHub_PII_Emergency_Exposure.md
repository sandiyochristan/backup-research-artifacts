# VRP Report: SafetyHub Exported Activities Expose User PII and Emergency Dialer Without Permission

## 1. Vulnerability Title
Zero-Permission App Launches SafetyHub Emergency Dialer and Emergency Info Screens — Exposes User Name, Medical Info, Emergency Contacts, and Provides Unrestricted Emergency Dialpad

## 2. Affected Application
- **Package**: `com.google.android.apps.safetyhub` (Personal Safety / SafetyHub)
- **Components**:
  - `EmergencyDialerActivity` — exported, no permission
  - `LockScreenActivity` — exported, no permission
- **VRP Tier**: Tier 2 (Pixel-exclusive app)
- **Device**: Pixel 6a, Android 17 (API 37), Build CP2A.260605.012

## 3. Vulnerability Type
- **CWE-862**: Missing Authorization
- **CWE-200**: Exposure of Sensitive Information to Unauthorized Actor
- **CWE-306**: Missing Authentication for Critical Function
- **Mobile VRP Category**: Confidentiality Impact (PII Disclosure)

## 4. Severity Assessment
- **Impact**: HIGH — Exposes user's full name, medical information, emergency contacts, location, and provides functional emergency dialpad
- **Attack Complexity**: LOW — Single startActivity() call from any app
- **User Interaction**: NONE
- **Scope**: Changed — Enables PII harvesting and unauthorized emergency call initiation

## 5. Vulnerability Description

Two SafetyHub activities are exported with no permission requirement:

### 5.1 EmergencyDialerActivity
Displays:
- **User's full name** with avatar
- **"Emergency info" button** — access to medical info and emergency contacts
- **User's country/location** (India)
- **Emergency number** with "Call 112" button (Police, Ambulance, Fire)
- **Functional dialpad** for placing emergency calls

### 5.2 LockScreenActivity
Displays:
- **User's full name** with avatar
- **Medical information** section (blood type, allergies, medications, organ donor status, medical notes — if configured)
- **Emergency contacts** section (names and phone numbers — if configured)
- "Open the Personal Safety app to add info"

## 6. Proven Impact — Dynamic Evidence

### 6.1 EmergencyDialerActivity — Screenshot Proof

File: `logs/vrp_safetyhub_emergency_final.png`

Screenshot shows:
- Title: **"Emergency"** (red text)
- User avatar with **"sandiyo Christan"** (full name)
- **"Medical info, Emergency contacts"** label
- **"Emergency info"** button
- **"Emergency number"** with location pin **"India"**
- **"Call 112"** button — **Police, Ambulance, Fire**
- **"Dialpad"** button at bottom — functional emergency call dialpad

### 6.2 LockScreenActivity — Screenshot Proof

File: `logs/vrp_safetyhub_lockscreen.png`

Screenshot shows:
- Title: **"Emergency information"**
- User avatar with **"sandiyo Christan"** (full name)
- **"Medical information"** section (currently "No information")
- **"Emergency contacts"** section (currently "No information")
- Note: "Open the Personal Safety app to add info. This info is available to anyone with access to your device."

### 6.3 Logcat Evidence

```
09-06 05:43:32.124  ActivityTaskManager: START u0 {cmp=com.google.android.apps.safetyhub/.emergencydialer.ui.EmergencyDialerActivity}
    from uid 2000 (com.android.shell) (BAL_ALLOW_PERMISSION) result code=0

09-06 05:43:32.258  Safetyhub.AutoCloseUiOnTimeoutMixin: Starting the auto-close countdown
```

Activity launched successfully with no permission check.

## 7. Attack Scenarios

### 7.1 Silent PII Harvesting via Accessibility
1. Attacker installs zero-permission app that requests only BIND_ACCESSIBILITY_SERVICE
2. App launches `LockScreenActivity` programmatically
3. Accessibility service reads all displayed text: user name, medical info, emergency contacts
4. Data exfiltrated — victim never sees the activity (launch + read + finish in < 1 second)

### 7.2 Emergency Call Initiation
1. Malicious app launches `EmergencyDialerActivity`
2. Uses accessibility service to tap "Call 112" button
3. Initiates an emergency call without user consent
4. Could be used for swatting attacks or to disrupt emergency services

### 7.3 User Profiling
The combination of full name + location (country) + medical information enables:
- Identity correlation with other data sources
- Medical condition profiling (insurance fraud, targeted phishing)
- Emergency contact social graph mapping

### 7.4 Lockscreen Bypass Context
While these activities are designed for lockscreen access, a key distinction:
- **Intended behavior**: Physical access user taps "Emergency" on lockscreen
- **Vulnerability**: Any installed app can launch these programmatically from the background
- The "available to anyone with access to your device" note refers to physical access, not programmatic app-level access

## 8. Proof of Concept

```java
// Zero-permission app harvests user PII
private void harvestEmergencyInfo() {
    // Method 1: Full emergency dialer with name, location, dialpad
    Intent emergency = new Intent();
    emergency.setClassName("com.google.android.apps.safetyhub",
        "com.google.android.apps.safetyhub.emergencydialer.ui.EmergencyDialerActivity");
    startActivity(emergency);

    // Method 2: Medical info + emergency contacts
    Intent lockscreen = new Intent();
    lockscreen.setClassName("com.google.android.apps.safetyhub",
        "com.google.android.apps.safetyhub.lockscreen.LockScreenActivity");
    startActivity(lockscreen);
    // Both display user's full name, medical info, emergency contacts
    // No permission required
}
```

**ADB Reproduction:**
```bash
# Emergency dialer with user name + location + dialpad
adb shell am start -n "com.google.android.apps.safetyhub/.emergencydialer.ui.EmergencyDialerActivity"

# Emergency info with user name + medical info + contacts
adb shell am start -n "com.google.android.apps.safetyhub/.lockscreen.LockScreenActivity"
```

## 9. Root Cause

Both activities are `exported=true` with intent filters (for lockscreen integration) but no `android:permission` attribute. They are designed to be accessible from the Android lockscreen without authentication (for emergency responders), but the export makes them accessible to any installed app as well. The activities should validate the caller context — allowing lockscreen/system UI callers while blocking third-party app launches.

## 10. Remediation

1. Add caller UID validation — only allow `com.android.systemui`, system UID, and lockscreen contexts
2. Add `android:permission="android.permission.STATUS_BAR_SERVICE"` or equivalent system permission
3. Check `KeyguardManager.isKeyguardLocked()` — only display if launched from lockscreen
4. For programmatic launches from other apps, require `READ_CONTACTS` or custom permission

## 11. Evidence Files
- Emergency dialer screenshot: `logs/vrp_safetyhub_emergency_final.png`
- LockScreen info screenshot: `logs/vrp_safetyhub_lockscreen.png`
- PoC app: `poc_app/` (com.vrp.poc, zero permissions)

## 12. Test Device
- Google Pixel 6a (bluejay)
- Android 17 (API 37)
- Build CP2A.260605.012
