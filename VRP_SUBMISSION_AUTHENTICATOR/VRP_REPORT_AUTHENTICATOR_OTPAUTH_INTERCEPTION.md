# Google Authenticator: otpauth:// Scheme Interception — 2FA Secret Key Theft

## Summary

Google Authenticator (com.google.android.apps.authenticator2) registers an `otpauth://` custom URI scheme handler with `BROWSABLE` category. Because Android cannot verify ownership of custom URI schemes (only HTTPS schemes support Digital Asset Links verification), a zero-permission attacker app can register an identical intent filter and intercept `otpauth://` URIs. When the user scans a 2FA QR code or clicks an otpauth:// link, the Android chooser appears. If the user selects the attacker app, the TOTP/HOTP secret key is stolen — enabling the attacker to generate valid 2FA codes indefinitely.

## Severity: CRITICAL (Confidentiality)

- **Attack vector**: Local (installed zero-permission app)
- **Privileges required**: None (zero Android permissions)
- **User interaction**: One tap to select attacker in chooser (or zero if "Always" was previously selected)
- **Impact**: Complete 2FA bypass — attacker generates valid TOTP codes for the victim's account forever

## Affected Component

- **Package**: `com.google.android.apps.authenticator2`
- **Version**: 7.2 (versionCode 7002011)
- **Target SDK**: 37, Min SDK: 32
- **Vulnerable activity**: `com.google.android.apps.authenticator2.main.MainActivity`

## Root Cause

Google Authenticator's manifest registers:

```
Action: "android.intent.action.VIEW"
Category: "android.intent.category.DEFAULT"
Category: "android.intent.category.BROWSABLE"
Scheme: "otpauth"
```

Per RFC 8252 Section 8.1 and Android documentation, `autoVerify` only works for `http://` and `https://` schemes. Custom schemes like `otpauth://` cannot be verified via Digital Asset Links. Any installed app can register an identical intent filter and compete for these URIs.

The `otpauth://` URI format (RFC 6238, Google Authenticator Key URI Format) contains the TOTP/HOTP secret key in plaintext:

```
otpauth://totp/ISSUER:ACCOUNT?secret=BASE32_SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
```

The `secret` parameter is the cryptographic key used to generate one-time passwords. An attacker who obtains this secret can generate valid 2FA codes for the victim's account indefinitely.

## Reproduction

1. Install the zero-permission attacker app (com.vrp.zeroperm, zero permissions declared)
2. The attacker manifest contains a competing intent filter:
```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="otpauth" />
</intent-filter>
```
3. When a user scans a 2FA QR code (e.g., enabling 2FA on their Google account), the system generates an `otpauth://` URI:
```
otpauth://totp/Google:victim@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google&algorithm=SHA1&digits=6&period=30
```
4. Android shows an "Open with" chooser: **ZeroPerm** vs **Authenticator**
5. If the user selects the attacker app, all 2FA provisioning data is captured

### Verification

```bash
# Confirm two handlers compete for otpauth://
adb shell cmd package query-activities --brief -a android.intent.action.VIEW \
  -d "otpauth://totp/test"

# Output:
# 2 activities found:
#   com.google.android.apps.authenticator2/.main.MainActivity
#   com.vrp.zeroperm/.OAuthInterceptActivity
```

## Proof

### Chooser dialog (see `screenshot_otpauth_chooser.png`)
- "Open with" dialog shows both **ZeroPerm** and **Authenticator**
- "Just once" and "Always" options available
- If "Always" is selected for attacker, all future 2FA setups are silently hijacked

### Stolen 2FA secret (see `screenshot_otpauth_stolen.png`)
```
OAUTH INTERCEPTION PoC
UID: 10394
Package: com.vrp.zeroperm
Permissions: ZERO

--- INTERCEPTED OAUTH CALLBACK ---
Full URI: otpauth://totp/Google:victim@gmail.com?secret=JBSWY3DPEHPK3PXP
Scheme: otpauth
Host: totp
Path: /Google:victim@gmail.com

--- ALL PARAMETERS ---
secret = JBSWY3DPEHPK3PXP

The legitimate app NEVER received this OAuth callback.
Target app: Google Authenticator (2FA TOTP/HOTP secret)
```

### 2FA injection (see `screenshot_otpauth_injection.png`)
- Sending `otpauth://` URI from attacker directly to Authenticator triggers "Add token" dialog
- "Do you want to add the token named EVIL_SERVICE: victim@gmail.com?"
- This enables phishing: inject a fake 2FA entry that generates codes for an attacker-controlled service

## Impact

### Primary: 2FA Secret Key Theft (CRITICAL — Confidentiality)
- **TOTP secret key** (`secret=JBSWY3DPEHPK3PXP`) is stolen in plaintext
- Attacker can generate valid 2FA codes for the victim's account **forever**
- Works for any service using TOTP (Google, GitHub, AWS, banking, etc.)
- The secret key does not expire or rotate — it is the permanent seed
- If the user taps "Always", all future 2FA provisioning is silently redirected

### Secondary: 2FA Setup Denial (HIGH — Availability)
- Google Authenticator NEVER receives the `otpauth://` URI
- The 2FA setup fails silently — the user thinks they set up 2FA but the app has no token
- The user is locked out of their account on next login requiring 2FA

### Tertiary: 2FA Entry Injection (MEDIUM — Integrity)
- Attacker can inject fake `otpauth://` URIs into Google Authenticator
- Creates confusion with bogus 2FA entries in the victim's token list
- Can be used for social engineering (fake "recovery" 2FA entries)

## Attack Chain

1. **Install zero-permission attacker app** (background, no user awareness needed beyond install)
2. **Wait for 2FA setup** — user enables 2FA on any service (Google, GitHub, AWS, etc.)
3. **Chooser appears** — "ZeroPerm" vs "Authenticator"
4. **User selects attacker** (social engineering: attacker app named "2FA Setup" or similar)
5. **Secret key stolen** — attacker now generates valid 2FA codes
6. **User's Authenticator is empty** — 2FA setup appears to fail
7. **User retries** — may select Authenticator this time, but attacker already has the secret
8. **Attacker uses stolen secret** — bypasses 2FA on victim's account at will

If the user previously tapped "Always" for the attacker app:
- Steps 3-4 are eliminated — all `otpauth://` URIs go silently to the attacker
- The attack becomes completely invisible

## Environment

- Device: Pixel 6a (oriole), Android 17 Beta (API 37)
- Google Authenticator: v7.2 (versionCode 7002011)
- Attacker app: com.vrp.zeroperm (UID=10394, zero permissions, targetSdkVersion=34)

## Recommended Fixes

### Option 1: Use Android Credential Manager API
- Migrate to the Credential Manager API which provides a secure channel for TOTP provisioning
- Eliminates URI scheme interception entirely

### Option 2: Verify caller identity
- When receiving an `otpauth://` URI, verify the calling app's identity
- Only accept URIs from trusted sources (QR scanner within the app, Google services)

### Option 3: Use HTTPS redirect with App Links
- Instead of `otpauth://`, use `https://authenticator.google.com/add?...` with verified App Links
- This prevents interception because HTTPS domains are verified via Digital Asset Links

### Option 4: Show warning on external otpauth:// delivery
- If the `otpauth://` URI arrives via an external intent (not from internal QR scan), show a prominent warning that another app may have seen the secret
- Recommend the user regenerate the 2FA secret

## Files

- `OAuthInterceptActivity.java` — otpauth:// interception PoC
- `AndroidManifest.xml` — Zero-permission manifest with otpauth intent filter
- `poc_v44.apk` — Compiled PoC (v44, zero permissions)
- `screenshot_otpauth_chooser.png` — Chooser dialog: ZeroPerm vs Authenticator
- `screenshot_otpauth_stolen.png` — Stolen 2FA secret key displayed in attacker app
- `screenshot_otpauth_injection.png` — Fake 2FA token injection dialog
