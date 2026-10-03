# Android System Key Verifier: contactkeys:// Scheme Interception — E2E Key Verification Bypass

## Summary

Android System Key Verifier (com.google.android.contactkeys) registers a `contactkeys://` custom URI scheme handler with `BROWSABLE` category for E2E encryption key verification. Because Android cannot verify ownership of custom URI schemes (only HTTPS schemes support Digital Asset Links verification per RFC 8252 §8.1), a zero-permission attacker app can register an identical intent filter and intercept `contactkeys://` URIs. When a user taps a key verification link, the Android chooser appears. If the user selects the attacker app, the key verification data is stolen and the verification flow is denied to the legitimate app.

## Severity: HIGH (Integrity + Availability)

- **Attack vector**: Local (installed zero-permission app)
- **Privileges required**: None (zero Android permissions)
- **User interaction**: One tap to select attacker in chooser
- **Impact**: E2E key verification bypass — attacker steals key fingerprints, prevents legitimate verification

## Affected Component

- **Package**: `com.google.android.contactkeys` (Android System Key Verifier)
- **Activity**: `com.google.android.gms.contactkeys.MainActivity`
- **Device**: Pixel 6a (oriole), Android 17 Beta (API 37)

## Root Cause

Android System Key Verifier registers:

```
Action: "android.intent.action.VIEW"
Category: "android.intent.category.DEFAULT"
Category: "android.intent.category.BROWSABLE"
Scheme: "contactkeys"
Scheme: "CONTACTKEYS"
```

The `contactkeys://` URI scheme is used for Android's Key Transparency feature — allowing users to verify each other's E2E encryption keys. The URI contains key fingerprints and contact identifiers.

## Reproduction

1. Install the zero-permission attacker app
2. The attacker manifest registers:
```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="contactkeys" />
    <data android:scheme="CONTACTKEYS" />
</intent-filter>
```
3. When a user taps a key verification link: `contactkeys://verify?fingerprint=ABCDEF&contact=user@gmail.com`
4. Chooser appears: **ZeroPerm** vs **Android System Key Verifier**

### Verification

```bash
adb shell cmd package query-activities --brief -a android.intent.action.VIEW \
  -d "contactkeys://verify?fingerprint=ABC123"

# 2 activities found:
#   com.google.android.contactkeys/com.google.android.gms.contactkeys.MainActivity
#   com.vrp.zeroperm/.OAuthInterceptActivity
```

## Proof

### Chooser dialog (see `screenshot_contactkeys_chooser.png`)
- "Open with" dialog shows **ZeroPerm** vs **Android System Key Verifier** (ContactKeys Platform)

### Stolen key data (see `screenshot_contactkeys_stolen.png`)
- URI parameters including fingerprint and contact identifier captured by attacker

## Impact

### Key Verification Bypass (HIGH — Integrity)
- Attacker intercepts the key verification URI
- The legitimate Key Verifier NEVER receives the data
- User cannot verify their contact's encryption key
- If attacker shows a fake "verified" UI, user believes keys are verified when they are not
- Undermines the trust model of E2E encryption key verification

### Key Data Theft (MEDIUM — Confidentiality)
- Key fingerprints and contact identifiers are stolen
- Enables targeted key substitution attacks

## Environment

- Device: Pixel 6a (oriole), Android 17 Beta (API 37)
- Android System Key Verifier: com.google.android.contactkeys
- Attacker app: com.vrp.zeroperm (UID=10394, zero permissions)

## Recommended Fix

Use `https://` App Links instead of `contactkeys://` custom scheme for key verification URIs, with Digital Asset Links verification.

## Files

- `screenshot_contactkeys_chooser.png` — Chooser: ZeroPerm vs Android System Key Verifier
- `screenshot_contactkeys_stolen.png` — Stolen key verification data
