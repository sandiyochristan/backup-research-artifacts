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
