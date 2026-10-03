# PART 2 — STATIC ANALYSIS (DECOMPILATION & CODE REVIEW)

---

## 2.1 APK Decompilation Pipeline

### Batch Decompile with JADX

```bash
#!/bin/bash
# ── decompile_all.sh ──
# Decompiles all pulled APKs using jadx for Java source review

APK_DIR="./pulled_apks/priority"
DECOMPILED_DIR="./decompiled"
mkdir -p "$DECOMPILED_DIR"

LOGFILE="./decompiled/decompile_log.txt"
echo "Decompilation Log - $(date)" > "$LOGFILE"

for apk in "$APK_DIR"/*.apk; do
  BASENAME=$(basename "$apk" .apk)
  OUTPUT="$DECOMPILED_DIR/$BASENAME"
  
  if [ -d "$OUTPUT" ]; then
    echo "[SKIP] $BASENAME - already decompiled" | tee -a "$LOGFILE"
    continue
  fi
  
  echo "[DECOMPILE] $BASENAME..." | tee -a "$LOGFILE"
  jadx -d "$OUTPUT" --show-bad-code --deobf "$apk" 2>> "$LOGFILE"
  
  if [ $? -eq 0 ]; then
    echo "[OK] $BASENAME → $OUTPUT" | tee -a "$LOGFILE"
  else
    echo "[WARN] $BASENAME - partial decompilation" | tee -a "$LOGFILE"
  fi
done

echo "=== Decompilation Complete ===" | tee -a "$LOGFILE"
```

### Disassemble with Apktool (for Manifest & smali)

```bash
#!/bin/bash
# ── disassemble_all.sh ──
# Disassembles APKs with apktool for AndroidManifest.xml and smali code

APK_DIR="./pulled_apks/priority"
SMALI_DIR="./disassembled"
mkdir -p "$SMALI_DIR"

for apk in "$APK_DIR"/*.apk; do
  BASENAME=$(basename "$apk" .apk)
  OUTPUT="$SMALI_DIR/$BASENAME"
  
  echo "[DISASSEMBLE] $BASENAME..."
  apktool d "$apk" -o "$OUTPUT" -f 2>/dev/null
  
  if [ -f "$OUTPUT/AndroidManifest.xml" ]; then
    echo "[OK] Manifest extracted: $OUTPUT/AndroidManifest.xml"
  fi
done
```

---

## 2.2 AndroidManifest.xml Audit

### Automated Manifest Scanner Script

```bash
#!/bin/bash
# ── manifest_audit.sh ──
# Scans AndroidManifest.xml files for security-relevant configurations

SMALI_DIR="./disassembled"
FINDINGS_DIR="./findings/manifest"
mkdir -p "$FINDINGS_DIR"

audit_manifest() {
  local MANIFEST=$1
  local PKG_NAME=$(basename "$(dirname "$MANIFEST")")
  local REPORT="$FINDINGS_DIR/${PKG_NAME}_manifest_audit.txt"
  
  echo "=== Manifest Audit: $PKG_NAME ===" > "$REPORT"
  echo "File: $MANIFEST" >> "$REPORT"
  echo "Date: $(date)" >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── 1. Exported Activities without permission ──
  echo "--- EXPORTED ACTIVITIES (no permission guard) ---" >> "$REPORT"
  grep -n 'android:exported="true"' "$MANIFEST" | while read -r line; do
    LINE_NUM=$(echo "$line" | cut -d: -f1)
    # Check if the next few lines have a permission attribute
    CONTEXT=$(sed -n "$((LINE_NUM-2)),$((LINE_NUM+10))p" "$MANIFEST")
    if ! echo "$CONTEXT" | grep -q "android:permission"; then
      echo "[CRITICAL] Line $LINE_NUM: Exported without permission guard" >> "$REPORT"
      echo "$CONTEXT" >> "$REPORT"
      echo "" >> "$REPORT"
    fi
  done
  
  # ── 2. Intent Filters on exported components ──
  echo "--- INTENT FILTERS ---" >> "$REPORT"
  grep -n -A5 "<intent-filter" "$MANIFEST" | grep -E "action|category|data" >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── 3. Custom permissions (look for signature vs dangerous) ──
  echo "--- CUSTOM PERMISSIONS ---" >> "$REPORT"
  grep -n "permission.*android:protectionLevel" "$MANIFEST" >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── 4. Backup allowed ──
  echo "--- BACKUP CONFIG ---" >> "$REPORT"
  if grep -q 'android:allowBackup="true"' "$MANIFEST"; then
    echo "[HIGH] Backup enabled - data exfiltration via adb backup" >> "$REPORT"
  fi
  echo "" >> "$REPORT"
  
  # ── 5. Debuggable ──
  echo "--- DEBUG CONFIG ---" >> "$REPORT"
  if grep -q 'android:debuggable="true"' "$MANIFEST"; then
    echo "[CRITICAL] App is debuggable!" >> "$REPORT"
  fi
  echo "" >> "$REPORT"
  
  # ── 6. ContentProviders ──
  echo "--- CONTENT PROVIDERS ---" >> "$REPORT"
  grep -n -A5 "<provider" "$MANIFEST" >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── 7. Deep links / URI schemes ──
  echo "--- URI SCHEMES / DEEP LINKS ---" >> "$REPORT"
  grep -n -B2 -A5 'android:scheme=' "$MANIFEST" >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── 8. Wear-specific: TileService / ComplicationProviderService ──
  echo "--- WEAR OS SPECIFIC SERVICES ---" >> "$REPORT"
  grep -n -A10 "TileService\|ComplicationProviderService\|WearableListenerService" "$MANIFEST" >> "$REPORT"
  echo "" >> "$REPORT"
  
  echo "[DONE] $PKG_NAME → $REPORT"
}

# ── Run audit on all decompiled manifests ──
find "$SMALI_DIR" -name "AndroidManifest.xml" -maxdepth 2 | while read -r manifest; do
  audit_manifest "$manifest"
done

echo "=== Manifest Audit Complete ==="
echo "Findings: $FINDINGS_DIR/"
```

### Key Manifest Patterns to Flag

```
AGENT_INSTRUCTION: When reviewing manifests, flag these patterns as HIGH PRIORITY:

1. EXPORTED WITHOUT PERMISSION:
   <activity android:exported="true"> with NO android:permission attribute
   → Potential confused-deputy (CVE-2025-12080 class)

2. SMS/CALL URI HANDLERS:
   <data android:scheme="sms" /> or "smsto" or "tel" or "mailto"
   → Silent action triggers without user confirmation

3. WEAR-SPECIFIC SERVICES:
   <service> extending TileService / ComplicationProviderService
   → These run outside Activity lifecycle, no confirmation UX

4. CUSTOM PERMISSIONS WITH protectionLevel="normal":
   → Any app can request these, no user prompt

5. CONTENT PROVIDERS WITH grantUriPermissions="true":
   → Potential data leakage across app boundaries

6. WearableListenerService WITHOUT permission:
   → Data Layer messages from watch/phone handled without auth
```

---

## 2.3 Source Code Vulnerability Patterns

### Automated Source Code Scanner

```bash
#!/bin/bash
# ── code_scanner.sh ──
# Searches decompiled Java/Kotlin source for vulnerability patterns

DECOMPILED_DIR="./decompiled"
FINDINGS_DIR="./findings/code"
mkdir -p "$FINDINGS_DIR"

scan_package() {
  local PKG_DIR=$1
  local PKG_NAME=$(basename "$PKG_DIR")
  local REPORT="$FINDINGS_DIR/${PKG_NAME}_code_findings.txt"
  
  echo "=== Code Scan: $PKG_NAME ===" > "$REPORT"
  
  # ── Intent handling without validation ──
  echo "--- INTENT HANDLING (getIntent/getExtras without validation) ---" >> "$REPORT"
  grep -rn "getIntent\|getExtras\|getStringExtra\|getParcelableExtra" "$PKG_DIR/sources/" \
    --include="*.java" 2>/dev/null | head -50 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── startActivity without user confirmation ──
  echo "--- STARTACTIVITY CALLS (potential silent actions) ---" >> "$REPORT"
  grep -rn "startActivity\|startService\|sendBroadcast" "$PKG_DIR/sources/" \
    --include="*.java" 2>/dev/null | head -50 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── SMS/Call related code ──
  echo "--- SMS/TELEPHONY CODE ---" >> "$REPORT"
  grep -rn "SmsManager\|ACTION_SENDTO\|ACTION_SEND\|ACTION_CALL\|ACTION_DIAL" "$PKG_DIR/sources/" \
    --include="*.java" 2>/dev/null >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── ContentProvider queries (SQL injection) ──
  echo "--- CONTENT PROVIDER QUERIES ---" >> "$REPORT"
  grep -rn "rawQuery\|execSQL\|query.*selection" "$PKG_DIR/sources/" \
    --include="*.java" 2>/dev/null | head -30 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── File operations (path traversal) ──
  echo "--- FILE OPERATIONS ---" >> "$REPORT"
  grep -rn "openFileOutput\|openFileInput\|getExternalStorage\|FileProvider\|openFile" "$PKG_DIR/sources/" \
    --include="*.java" 2>/dev/null | head -30 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── Hardcoded secrets ──
  echo "--- HARDCODED SECRETS ---" >> "$REPORT"
  grep -rn "api_key\|apikey\|secret\|password\|token.*=.*\"" "$PKG_DIR/sources/" \
    --include="*.java" -i 2>/dev/null | head -20 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── WebView (XSS/RCE) ──
  echo "--- WEBVIEW USAGE ---" >> "$REPORT"
  grep -rn "WebView\|loadUrl\|loadData\|addJavascriptInterface\|setJavaScriptEnabled" "$PKG_DIR/sources/" \
    --include="*.java" 2>/dev/null | head -30 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── Health/Sensor data access ──
  echo "--- HEALTH/SENSOR DATA ACCESS ---" >> "$REPORT"
  grep -rn "HealthServicesClient\|PassiveMonitoringClient\|SensorManager\|BODY_SENSORS\|heartRate\|HeartRate" \
    "$PKG_DIR/sources/" --include="*.java" 2>/dev/null | head -30 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── Data Layer (watch-phone bridge) ──
  echo "--- WEARABLE DATA LAYER ---" >> "$REPORT"
  grep -rn "MessageClient\|DataClient\|ChannelClient\|WearableListenerService\|onMessageReceived\|onDataChanged" \
    "$PKG_DIR/sources/" --include="*.java" 2>/dev/null | head -30 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── Crypto weaknesses ──
  echo "--- CRYPTO USAGE ---" >> "$REPORT"
  grep -rn "DES\|MD5\|SHA1\|ECB\|NoPadding\|TrustAllCerts\|ALLOW_ALL" "$PKG_DIR/sources/" \
    --include="*.java" 2>/dev/null | head -20 >> "$REPORT"
  echo "" >> "$REPORT"
  
  # ── PendingIntent without FLAG_IMMUTABLE ──
  echo "--- PENDING INTENT FLAGS ---" >> "$REPORT"
  grep -rn "PendingIntent" "$PKG_DIR/sources/" --include="*.java" 2>/dev/null \
    | grep -v "FLAG_IMMUTABLE" | head -20 >> "$REPORT"
  echo "" >> "$REPORT"
  
  echo "[DONE] $PKG_NAME → $REPORT"
}

# ── Scan all decompiled packages ──
for pkg_dir in "$DECOMPILED_DIR"/*/; do
  scan_package "$pkg_dir"
done

echo "=== Code Scan Complete ==="
```

---

## 2.4 Specific Analysis: Google Messages (CVE-2025-12080 Pattern)

```
AGENT_INSTRUCTION: This is the reference vulnerability pattern. Apply this exact
analysis methodology to ALL communication apps on Wear OS.

CVE-2025-12080 Root Cause:
- Google Messages on Wear OS handles ACTION_SENDTO with sms:/smsto:/mms:/mmsto: URI schemes
- On the PHONE version, a confirmation dialog appears before sending
- On the WEAR OS version, the message is sent IMMEDIATELY without confirmation
- No SEND_SMS permission required — any app can trigger the intent
- This is a "confused deputy" vulnerability

REPLICATION PATTERN — Apply to these targets:
1. com.google.android.dialer     → Check ACTION_CALL / ACTION_DIAL (tel: scheme)
2. com.google.android.apps.maps  → Check geo: / google.navigation: schemes
3. com.google.android.gm         → Check mailto: scheme
4. com.google.android.calendar   → Check content://com.android.calendar
5. Any app with ACTION_VIEW + exported Activity
```

### Manual Code Review Checklist

```bash
# For each decompiled target, examine:

# 1. Find the Activity that handles the vulnerable intent
grep -rn "ACTION_SENDTO\|ACTION_SEND\|ACTION_VIEW\|ACTION_CALL" \
  ./decompiled/<TARGET>/sources/ --include="*.java"

# 2. Trace the intent handling code path
# Look for: getIntent() → extract data → perform action
# Flag if: NO AlertDialog / NO confirmation step / NO user interaction check

# 3. Check if the Activity has exported=true in manifest
grep -A10 "activity.*<TARGET_ACTIVITY>" \
  ./disassembled/<TARGET>/AndroidManifest.xml

# 4. Verify no permission guard
# Flag if: no android:permission attribute on the exported component

# 5. Check for Wear OS specific bypasses
# The Wear OS version may skip confirmation UX that exists in the phone version
# Compare wear APK manifest vs phone APK manifest for the same app
```
