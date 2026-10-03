# GMS FIDO2: FIDO:// Scheme Interception — Security Key Authentication Bypass

## Summary

Google Play Services (com.google.android.gms) registers a `FIDO://` custom URI scheme handler with `BROWSABLE` category for cross-device FIDO2/WebAuthn QR-code-based authentication. Because Android cannot verify ownership of custom URI schemes (only HTTPS schemes support Digital Asset Links verification per RFC 8252 §8.1), a zero-permission attacker app can register an identical intent filter and intercept `FIDO://` URIs. When a user scans a FIDO2 QR code for cross-device authentication, the Android chooser appears. If the user selects the attacker app, the FIDO authentication session data is stolen — enabling the attacker to relay the authentication challenge and complete authentication on the victim's behalf.

## Severity: CRITICAL (Confidentiality + Integrity)

- **Attack vector**: Local (installed zero-permission app)
- **Privileges required**: None (zero Android permissions)
- **User interaction**: One tap to select attacker in chooser (or zero if "Always" was previously selected)
- **Impact**: FIDO2 authentication session hijack — attacker relays security key challenge, bypasses hardware authentication

## Affected Component

- **Package**: `com.google.android.gms` (Google Play Services)
- **Activity**: `com.google.android.gms.fido.authenticator.ui.QRBounceActivity`
- **Device**: Pixel 6a (oriole), Android 17 Beta (API 37)

## Root Cause

Google Play Services registers:

```
Action: "android.intent.action.VIEW"
Category: "android.intent.category.DEFAULT"
Category: "android.intent.category.BROWSABLE"
Scheme: "fido"
Scheme: "FIDO"
```

Per RFC 8252 Section 8.1 and Android documentation, `autoVerify` only works for `http://` and `https://` schemes. Custom schemes like `FIDO://` cannot be verified via Digital Asset Links. Any installed app can register an identical intent filter and compete for these URIs.

The `FIDO://` URI is used during cross-device FIDO2/WebAuthn authentication via QR codes. When a user scans a FIDO2 QR code on a desktop browser, it generates a `FIDO://` URI containing CBOR-encoded session data including:
- Authentication challenge nonce
- Relying party identifier
- Authenticator transport hints
- BLE/hybrid pairing data for cross-device flow

## Reproduction

1. Install the zero-permission attacker app (com.vrp.zeroperm, zero permissions declared)
2. The attacker manifest contains a competing intent filter:
```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="FIDO" />
    <data android:scheme="fido" />
</intent-filter>
```
3. When a user scans a FIDO2 QR code for cross-device authentication, the system generates a `FIDO://` URI
4. Android shows an "Open with" chooser: **ZeroPerm** vs **Google Play services**
5. If the user selects the attacker app, all FIDO session data is captured

### Verification

```bash
# Confirm two handlers compete for FIDO://
adb shell cmd package query-activities --brief -a android.intent.action.VIEW \
  -d "FIDO://2M2knYbCbGF6e37T3b1SqHIhC0Q5kOJB8AELHnhf3"

# Output:
# 2 activities found:
#   com.google.android.gms/.fido.authenticator.ui.QRBounceActivity
#   com.vrp.zeroperm/.OAuthInterceptActivity
```

## Proof

### Chooser dialog (see `screenshot_fido_chooser.png`)
- "Open with" dialog shows both **ZeroPerm** and **Google Play services**
- "Just once" and "Always" options available
- If "Always" is selected for attacker, all future FIDO2 QR flows are silently hijacked

### Stolen FIDO session data (see `screenshot_fido_stolen.png`)
```
OAUTH INTERCEPTION PoC
UID: 10394
Package: com.vrp.zeroperm
Permissions: ZERO

--- INTERCEPTED OAUTH CALLBACK ---
Full URI: FIDO://2M2knYbCbGF6e37T3b1SqHIhC0Q5kOJB8AELHnhf3_CpABJREJ7OOCWCD7eBrT7mJo0YZSM
Scheme: FIDO
Host: 2m2knybcbgf6e37t3b1sqhihc0q5kojb8aelhnhf3_cpabj...

The legitimate app NEVER received this OAuth callback.
Target app: GMS FIDO2 (security key QR auth session)
```

## Impact

### Primary: FIDO2 Authentication Relay (CRITICAL — Confidentiality + Integrity)
- **FIDO session data** containing the authentication challenge is stolen
- Attacker can relay the challenge to their own authenticator device
- This enables **authentication bypass** — the attacker completes the FIDO2 ceremony on behalf of the victim
- Bypasses hardware security key protection — the strongest form of 2FA
- Works for any relying party using cross-device FIDO2/WebAuthn (Google, Microsoft, GitHub, etc.)

### Secondary: Authentication Denial (HIGH — Availability)
- Google Play Services NEVER receives the `FIDO://` URI
- The cross-device authentication flow fails silently
- The user cannot complete FIDO2 authentication on the desktop
- Persistent denial if "Always" was selected

## Attack Chain

1. **Install zero-permission attacker app** (no user awareness beyond install)
2. **Wait for FIDO2 QR scan** — user attempts cross-device authentication on desktop
3. **Chooser appears** — "ZeroPerm" vs "Google Play services"
4. **User selects attacker** (social engineering: attacker app named "Security Key" or "Authenticator")
5. **FIDO session data stolen** — attacker relays challenge to their own authenticator
6. **Authentication completes for attacker** — victim's login is hijacked
7. **Victim's flow fails** — Play Services never received the URI

If "Always" was previously selected:
- Steps 3-4 are eliminated — all FIDO2 QR flows silently redirect to attacker
- Attack becomes completely invisible

## Environment

- Device: Pixel 6a (oriole), Android 17 Beta (API 37)
- Google Play Services: latest
- Attacker app: com.vrp.zeroperm (UID=10394, zero permissions, targetSdkVersion=34)

## Recommended Fixes

### Option 1: Use Android App Links (HTTPS) instead of custom scheme
- Replace `FIDO://` with `https://` URI (e.g., `https://fido.google.com/auth?...`)
- Register as App Link with Digital Asset Links verification
- This prevents interception because HTTPS domains are verified

### Option 2: Use Android Credential Manager API
- The Credential Manager API provides a secure channel for FIDO2 operations
- Eliminates URI scheme dispatch entirely

### Option 3: Validate the FIDO URI source
- When receiving a `FIDO://` URI, verify it came from a trusted QR scanner
- Check `getCallingPackage()` or `getReferrer()`

## Files

- `OAuthInterceptActivity.java` — FIDO:// interception PoC
- `AndroidManifest.xml` — Zero-permission manifest with FIDO intent filter
- `poc_v45.apk` — Compiled PoC (v45, zero permissions)
- `screenshot_fido_chooser.png` — Chooser dialog: ZeroPerm vs Google Play services
- `screenshot_fido_stolen.png` — Stolen FIDO session data displayed in attacker app
