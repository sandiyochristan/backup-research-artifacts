#!/bin/bash
# Robust APK puller — reads from saved package list

APK_DIR="./pulled_apks"
LOGFILE="$APK_DIR/pull_log.txt"

echo "APK Pull Log - $(date)" > "$LOGFILE"
echo "Device: $(adb shell getprop ro.product.model | tr -d '\r')" >> "$LOGFILE"
echo "Build: $(adb shell getprop ro.build.display.id | tr -d '\r')" >> "$LOGFILE"
echo "Patch: $(adb shell getprop ro.build.version.security_patch | tr -d '\r')" >> "$LOGFILE"
echo "---" >> "$LOGFILE"

# Save fresh package list
adb shell pm list packages | tr -d '\r' > "$APK_DIR/package_list.txt"

TOTAL=0
SUCCESS=0
FAIL=0

while IFS= read -r line; do
  PKG=$(echo "$line" | sed 's/package://')
  [ -z "$PKG" ] && continue
  
  TOTAL=$((TOTAL+1))
  
  # Get base APK path
  APK_PATH=$(adb shell pm path "$PKG" 2>/dev/null | head -1 | sed 's/package://' | tr -d '\r')
  
  if [ -z "$APK_PATH" ]; then
    echo "[$TOTAL] [SKIP] $PKG" | tee -a "$LOGFILE"
    FAIL=$((FAIL+1))
    continue
  fi
  
  # Use package name as filename
  SAFE_NAME=$(echo "$PKG" | tr '.' '_')
  
  adb pull "$APK_PATH" "$APK_DIR/${SAFE_NAME}.apk" > /dev/null 2>&1
  
  if [ $? -eq 0 ]; then
    SIZE=$(ls -lh "$APK_DIR/${SAFE_NAME}.apk" 2>/dev/null | awk '{print $5}')
    echo "[$TOTAL/202] [OK] $PKG ($SIZE)" | tee -a "$LOGFILE"
    SUCCESS=$((SUCCESS+1))
  else
    echo "[$TOTAL/202] [FAIL] $PKG" | tee -a "$LOGFILE"
    FAIL=$((FAIL+1))
  fi
  
done < "$APK_DIR/package_list.txt"

echo "---" >> "$LOGFILE"
echo "Total: $TOTAL | Success: $SUCCESS | Failed: $FAIL" | tee -a "$LOGFILE"
echo "=== PULL COMPLETE ==="
