# VRP Report #31: Google Dialer Zero-Permission Denial of Service via Dobby GatewayActivity Handler

## Summary
The Google Dialer app (`com.google.android.dialer`) exposes an activity alias `com.android.dialer.dobby.impl.growthkit.SettingsDeepLink` that is exported with no permission requirement. Unlike every other `GatewayActivity` handler in the Dialer, the Dobby promotion handler (`DobbyPromoGatewayHandler`) lacks the `GoogleSignatureVerifier` (`aavt`) caller check present in all sibling handlers. An attacker-supplied `extra_dobby_promotion_type` integer outside the valid range (0-5) causes an uncaught `IllegalArgumentException` that crashes the entire Dialer process.

## Affected Component
- **App**: Google Dialer (`com.google.android.dialer`)
- **Activity alias**: `com.android.dialer.dobby.impl.growthkit.SettingsDeepLink` (targets `GatewayActivity`)
- **Action**: `com.android.dialer.dobby.impl.growthkit.ACTION_SHOW_SETTINGS`
- **Manifest**: `exported="true"`, NO permission
- **Handler**: `defpackage/mpf.java` (DobbyPromoGatewayHandler) — routes to `defpackage/rrz.java` unconditionally, NO `aavt` (GoogleSignatureVerifier) check
- **Crash trigger**: `defpackage/a.java:140-155` (enum mapper `K(int)`) returns 0 for values outside 0-5 → `defpackage/rrz.java:36-52` throws `IllegalArgumentException("Required value was null.")`

## Vulnerability Details

### Missing GoogleSignatureVerifier Check
Every other GatewayActivity handler verifies the caller's package identity and Google signature via `aavt.b(callingPackage)`:
- Beesly (`ivu.java`), CallAnnouncer (`jnr.java`), CallRecording, Nautilus (`sgv.java`), Sharpie (`ucu.java`), Sonic (`uro.java`), Voicemail (`wgd.java`), Xatu (`wze.java`), RTT (`ttw.java`), Revelio, Atlas, CallingCard — ALL check `aavt.b(pkg)` (GoogleSignatureVerifier)

**DobbyPromoGatewayHandler** (`mpf.java:14`) is the ONLY handler that routes unconditionally without any caller verification.

### Crash Path
1. Attacker sends intent with `extra_dobby_promotion_type=999999`
2. `rrz.a()` reads the attacker-supplied extra: `Integer.valueOf(extras.getInt("extra_dobby_promotion_type"))`
3. `a.K(numValueOf.intValue())` — maps int to enum; only 0-5 are valid, any other returns 0
4. `if (iK == 0) { throw new IllegalArgumentException("Required value was null."); }` — CRASH
5. Exception is uncaught — propagates through `GatewayMixin.c()` → `onPostCreate` → kills Dialer process

### Impact
- **Availability**: Any zero-permission app can crash the default system Dialer
- **Persistent DoS**: A malicious background service can repeatedly trigger the crash, preventing users from making or receiving phone calls
- **No permissions required**: Zero Android permissions needed
- **No user interaction**: Crash is instant on intent delivery

## Proof of Concept

### ADB Command (no app required)
```bash
adb shell am start -n com.google.android.dialer/com.android.dialer.dobby.impl.growthkit.SettingsDeepLink \
  -a com.android.dialer.dobby.impl.growthkit.ACTION_SHOW_SETTINGS \
  --ei extra_dobby_promotion_type 999999
```

### Java PoC (from any installed app)
```java
Intent intent = new Intent("com.android.dialer.dobby.impl.growthkit.ACTION_SHOW_SETTINGS");
intent.setComponent(new ComponentName(
    "com.google.android.dialer",
    "com.android.dialer.dobby.impl.growthkit.SettingsDeepLink"));
intent.putExtra("extra_dobby_promotion_type", 999999);
startActivity(intent);
// Dialer process crashes immediately
```

## Fix Recommendation
Add `aavt.b(callingPackage)` (GoogleSignatureVerifier) check to `mpf.java` (DobbyPromoGatewayHandler) before routing, consistent with all other GatewayActivity handlers. Additionally, validate the `extra_dobby_promotion_type` value against the valid range (0-5) in `rrz.java` before passing to the enum mapper.

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- Google Dialer version as bundled with the build
