# VRP Report #37: YouTube OAuth Custom Scheme Interception (RFC 8252 §8.1)

## Vulnerability Summary

YouTube's `AccountLinkingActivity` uses custom URI schemes (`com.google.android.apps.youtube://oauth2redirect` and `vnd.youtube.gdi://`) for OAuth redirect handling. Per RFC 8252 Section 8.1, custom URI schemes are NOT exclusive on Android — any malicious app can register an identical intent filter and intercept the OAuth redirect, stealing the authorization code.

Additionally, the WebOAuth flow (tsb fragment) does not validate the `redirect_state` parameter against a stored expected value on the client side, unlike the App Flip flow which correctly validates the `state` parameter.

## Affected Component

| Attribute | Value |
|-----------|-------|
| Package | `com.google.android.youtube` |
| Activity | `com.google.android.libraries.accountlinking.activity.AccountLinkingActivity` |
| Exported | `true` |
| Launch Mode | `singleInstance` |
| Schemes | `com.google.android.apps.youtube://oauth2redirect`, `vnd.youtube.gdi://` |

## Technical Details

### Manifest Declaration

```xml
<activity android:exported="true"
  android:launchMode="singleInstance"
  android:name="com.google.android.libraries.accountlinking.activity.AccountLinkingActivity">
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="vnd.youtube.gdi"/>
  </intent-filter>
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:host="oauth2redirect"
          android:scheme="com.google.android.apps.youtube"/>
  </intent-filter>
</activity>
```

### Attack: Custom Scheme Hijacking

A malicious app registers an identical intent filter:

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="com.google.android.apps.youtube"
          android:host="oauth2redirect"/>
  </intent-filter>
</activity>
```

When YouTube initiates the WebOAuth flow via tsb.h(), it opens a browser for authentication. The OAuth server redirects back to:
```
com.google.android.apps.youtube://oauth2redirect?redirect_state=AUTHORIZATION_CODE
```

Android's disambiguation logic may:
1. Show a chooser dialog between YouTube and the malicious app
2. On some versions/configurations, deliver directly to the malicious app
3. Allow the malicious app to receive the redirect if installed after YouTube

### Finding 2: Missing Client-Side State Validation

```java
// AccountLinkingActivity.java onNewIntent(), WebOAuth flow (tsb fragment):
// Line 517-525 — redirect_state NOT validated against expected value
String queryParameter3 = data.getQueryParameter("redirect_state");
if (TextUtils.isEmpty(queryParameter3)) {
    truVarA = tsb.a;   // error path
} else {
    truVarA = tru.a(2, queryParameter3);  // ACCEPTS ANY VALUE
}
tsbVar.e.a(truVarA);  // Passes to handler without validation

// Compare with App Flip flow (trw fragment) which CORRECTLY validates:
// Line 557-563
String queryParameter5 = data.getQueryParameter("state");
if (queryParameter5 == null || !queryParameter5.equals(trwVar.e)) {
    // Error - state mismatch (CORRECT behavior)
}
```

The WebOAuth flow trusts whatever `redirect_state` it receives without comparing it to the value it originally sent. The App Flip flow correctly validates the `state` parameter — proving the developers know how to do this but missed it in the WebOAuth path.

## Impact

### Confidentiality (HIGH)
- OAuth authorization code theft: The `redirect_state` parameter contains the authorization code from the OAuth server
- This code can be exchanged for access tokens granting access to the user's linked third-party account

### Integrity (HIGH)
- Account linking hijack: Attacker can complete the OAuth flow with a stolen code, linking the victim's third-party account to an attacker-controlled YouTube session
- Alternatively, inject a crafted redirect to disrupt legitimate account linking (DoS)

### Attack Prerequisites
- Malicious app installed on device (no permissions required)
- User initiates YouTube account linking (e.g., connecting a streaming service)
- Browser redirects OAuth code via custom scheme

## Proof of Concept

PoC app registers for the same custom scheme:
```java
// YouTubeOAuthInterceptActivity.java
// This activity has an identical intent-filter to YouTube's AccountLinkingActivity
// When installed alongside YouTube, it can intercept OAuth redirects
Uri data = getIntent().getData();
String authCode = data.getQueryParameter("redirect_state");
// authCode now contains the OAuth authorization code
```

## Remediation

1. **Migrate to Android App Links** (HTTPS scheme with `autoVerify="true"`) for OAuth redirects — these are verified against the domain's `.well-known/assetlinks.json` and cannot be intercepted
2. **Implement PKCE** (RFC 7636) — even if the authorization code is intercepted, it cannot be exchanged without the code verifier
3. **Validate `redirect_state` client-side** in the WebOAuth flow (tsb fragment), matching the pattern already used in the App Flip flow (trw fragment)

## References

- RFC 8252 Section 8.1: "Authorization Code Interception Attack" — explicitly warns against custom URI schemes
- RFC 7636: PKCE for OAuth 2.0
- Google VRP: account takeover / credential theft via OAuth flow vulnerability
