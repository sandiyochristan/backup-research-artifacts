#!/bin/bash
# Pull all APKs from connected Wear OS device

APK_DIR="./pulled_apks"
mkdir -p "$APK_DIR"

LOGFILE="$APK_DIR/pull_log.txt"
echo "APK Pull Log - $(date)" > "$LOGFILE"
echo "Device: $(adb shell getprop ro.product.model)" >> "$LOGFILE"
echo "Build: $(adb shell getprop ro.build.display.id)" >> "$LOGFILE"
echo "Patch: $(adb shell getprop ro.build.version.security_patch)" >> "$LOGFILE"
echo "---" >> "$LOGFILE"

TOTAL=0
SUCCESS=0
FAIL=0

while IFS= read -r line; do
  PKG=$(echo "$line" | sed 's/package://' | tr -d '\r')
  
  # Get APK path(s)
  PATHS=$(adb shell pm path "$PKG" 2>/dev/null | tr -d '\r')
  
  if [ -z "$PATHS" ]; then
    echo "[SKIP] $PKG - no path" | tee -a "$LOGFILE"
    FAIL=$((FAIL+1))
    TOTAL=$((TOTAL+1))
    continue
  fi
  
  # Create folder per package
  PKG_DIR="$APK_DIR/$PKG"
  mkdir -p "$PKG_DIR"
  
  echo "$PATHS" | while IFS= read -r pathline; do
    APK_PATH=$(echo "$pathline" | sed 's/package://')
    FILENAME=$(basename "$APK_PATH")
    adb pull "$APK_PATH" "$PKG_DIR/$FILENAME" 2>/dev/null
  done
  
  PULLED=$(ls "$PKG_DIR"/*.apk 2>/dev/null | wc -l | tr -d ' ')
  if [ "$PULLED" -gt 0 ]; then
    echo "[OK] $PKG ($PULLED apk(s))" | tee -a "$LOGFILE"
    SUCCESS=$((SUCCESS+1))
  else
    echo "[FAIL] $PKG" | tee -a "$LOGFILE"
    FAIL=$((FAIL+1))
  fi
  TOTAL=$((TOTAL+1))
  
done < <(adb shell pm list packages)

echo "---" >> "$LOGFILE"
echo "Total: $TOTAL | Success: $SUCCESS | Failed: $FAIL" | tee -a "$LOGFILE"
echo "=== PULL COMPLETE ==="
