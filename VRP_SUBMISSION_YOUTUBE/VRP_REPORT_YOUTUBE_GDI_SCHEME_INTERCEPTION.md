# YouTube: vnd.youtube.gdi:// Scheme Interception — Account Linking OAuth Code Theft

## Summary

YouTube (com.google.android.youtube) registers a `vnd.youtube.gdi://` custom URI scheme handler via `AccountLinkingActivity` with `BROWSABLE` category for Google Device Integration (GDI) account linking flows. This is used when linking a Google account to YouTube on secondary devices such as smart TVs, streaming devices, and smart displays. Because Android cannot verify ownership of custom URI schemes (only HTTPS schemes support Digital Asset Links verification per RFC 8252 §8.1), a zero-permission attacker app can register an identical intent filter and intercept the account linking OAuth code. The attacker can then complete the device linking on their own device, gaining persistent YouTube access tied to the victim's Google account.

## Severity: HIGH (Confidentiality + Integrity)

- **Attack vector**: Local (installed zero-permission app)
- **Privileges required**: None (zero Android permissions)
- **User interaction**: One tap to select attacker in chooser (or zero if "Always" was previously selected)
- **Impact**: YouTube/Google account linking OAuth code theft — attacker links victim's account to attacker-controlled device

## Affected Component

- **Package**: `com.google.android.youtube` (YouTube)
- **Activity**: `com.google.android.libraries.accountlinking.activity.AccountLinkingActivity`
- **Device**: Pixel 6a (oriole), Android 17 Beta (API 37)

## Root Cause

YouTube registers:

```
Action: "android.intent.action.VIEW"
Category: "android.intent.category.DEFAULT"
Category: "android.intent.category.BROWSABLE"
Scheme: "vnd.youtube.gdi"
```

The `vnd.youtube.gdi` scheme is used for Google Device Integration — the flow where a user scans a QR code or enters a code on tv.youtube.com to link their Google account to a smart TV or streaming device. The URI contains the OAuth authorization code that authorizes the device to access YouTube on behalf of the user.

Per RFC 8252 Section 8.1, custom URI schemes cannot be verified via Digital Asset Links. Any installed app can register an identical intent filter and compete for these URIs.

## Reproduction

1. Install the zero-permission attacker app (com.vrp.zeroperm, zero permissions declared)
2. The attacker manifest registers:
```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="vnd.youtube.gdi" />
</intent-filter>
```
3. User initiates YouTube account linking on a smart TV (enters code at tv.youtube.com on phone)
4. The account linking flow redirects to: `vnd.youtube.gdi://account_link?code=OAUTH_CODE`
5. Android shows chooser: **ZeroPerm** vs **YouTube**
6. If the user selects the attacker app, the OAuth authorization code is captured

### Verification

```bash
# Confirm multiple handlers compete for vnd.youtube.gdi://
adb shell cmd package query-activities --brief -a android.intent.action.VIEW \
  -d "vnd.youtube.gdi://account_link?code=OAUTH_CODE"

# Output:
# 3 activities found:
#   com.google.android.youtube/com.google.android.libraries.accountlinking.activity.AccountLinkingActivity
#   com.vrp.poc/.YouTubeOAuthInterceptActivity
#   com.vrp.zeroperm/.OAuthInterceptActivity
```

Note: In a real attack scenario, only the attacker app + YouTube would be present (2 handlers).

## Proof

### Chooser dialog (see `screenshot_ytgdi_chooser.png`)
- "Open with" dialog shows **ZeroPerm**, **VRP PoC**, and **YouTube**
- "Just once" and "Always" options available
- If "Always" is selected for attacker, all future account linking flows are silently hijacked

### Stolen account linking code (see `screenshot_ytgdi_stolen.png`)
```
OAUTH INTERCEPTION PoC
UID: 10394
Package: com.vrp.zeroperm
Permissions: ZERO

--- INTERCEPTED OAUTH CALLBACK ---
Full URI: vnd.youtube.gdi://account_link?code=YOUTUBE_ACCT_LINK_CODE
Scheme: vnd.youtube.gdi
Host: account_link

STOLEN AUTH CODE: YOUTUBE_ACCT_LINK_CODE

Impact: attacker exchanges this code
for access_token + refresh_token
=> FULL ACCOUNT ACCESS

--- ALL PARAMETERS ---
code = YOUTUBE_ACCT_LINK_CODE

The legitimate app NEVER received this OAuth callback.
Target app: YouTube (account linking OAuth — device integration)
```

## Impact

### Primary: Account Linking Hijack (HIGH — Confidentiality + Integrity)

- **OAuth authorization code stolen** — the code that authorizes a device to access YouTube
- Attacker uses the stolen code to link THEIR device to the VICTIM's Google account
- Attacker gains persistent YouTube access:
  - View victim's watch history, subscriptions, and playlists
  - Post comments, like/dislike videos as the victim
  - Access YouTube Premium content if victim has subscription
  - Access YouTube Music library
  - View private/unlisted videos
- The linking is persistent — survives code expiration via refresh_token
- Since this is Google account-level OAuth, scope may extend beyond YouTube

### Secondary: Account Linking Denial (MEDIUM — Availability)

- YouTube NEVER receives the `vnd.youtube.gdi://` URI
- The legitimate account linking flow fails
- User cannot link their account to the smart TV/device
- Persistent denial if "Always" was selected

### Attack Chain: Persistent Account Surveillance

1. **Install zero-permission app** (disguised as "TV Remote" or "Screen Cast" utility)
2. **Wait for account linking** — user tries to sign into YouTube on a new TV/device
3. **Chooser appears** — attacker app named "YouTube TV Setup" for social engineering
4. **User selects attacker** — OAuth code captured
5. **Attacker links their device** — persistent access to victim's YouTube/Google
6. **Victim's linking fails** — they may retry, unaware the code was stolen
7. **Ongoing surveillance** — attacker monitors watch history, subscriptions, private content

## Environment

- Device: Pixel 6a (oriole), Android 17 Beta (API 37)
- YouTube: latest (com.google.android.youtube)
- Attacker app: com.vrp.zeroperm (UID=10394, zero permissions, targetSdkVersion=34)

## Recommended Fixes

### Option 1: Use Android App Links (HTTPS)
- Replace `vnd.youtube.gdi://` with `https://` URI (e.g., `https://youtube.com/gdi/link?...`)
- Register as App Link with Digital Asset Links verification
- This prevents interception because HTTPS domains are verified

### Option 2: Use Android AccountManager API
- Leverage the system AccountManager for device-to-device account transfer
- This doesn't use URI dispatch and cannot be intercepted

### Option 3: Remove BROWSABLE category
- If account linking URIs only come from the YouTube app itself (not from web)
- Remove `BROWSABLE` category to prevent external triggering

## Files

- `screenshot_ytgdi_chooser.png` — Chooser: ZeroPerm vs VRP PoC vs YouTube
- `screenshot_ytgdi_stolen.png` — Stolen account linking OAuth code
- `OAuthInterceptActivity.java` — PoC source (zero permissions)
- `AndroidManifest.xml` — Zero-permission manifest with vnd.youtube.gdi intent filter
