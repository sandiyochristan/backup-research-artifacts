#!/bin/bash
APK_DIR="./pulled_apks"
LOGFILE="$APK_DIR/pull_log.txt"

TOTAL=0
SUCCESS=0
FAIL=0

for PKG in $(adb shell pm list packages | sed 's/package://' | tr -d '\r'); do
  TOTAL=$((TOTAL+1))
  
  # Get base APK path
  APK_PATH=$(adb shell pm path "$PKG" 2>/dev/null | head -1 | sed 's/package://' | tr -d '\r')
  
  if [ -z "$APK_PATH" ]; then
    echo "[$TOTAL/202] [SKIP] $PKG" | tee -a "$LOGFILE"
    FAIL=$((FAIL+1))
    continue
  fi
  
  SAFE_NAME=$(echo "$PKG" | tr '.' '_')
  
  echo "Pulling $APK_PATH to $APK_DIR/${SAFE_NAME}.apk"
  adb pull "$APK_PATH" "$APK_DIR/${SAFE_NAME}.apk" > /dev/null 2>&1
  
  if [ $? -eq 0 ]; then
    SIZE=$(ls -lh "$APK_DIR/${SAFE_NAME}.apk" 2>/dev/null | awk '{print $5}')
    echo "[$TOTAL/202] [OK] $PKG ($SIZE)" | tee -a "$LOGFILE"
    SUCCESS=$((SUCCESS+1))
  else
    echo "[$TOTAL/202] [FAIL] $PKG" | tee -a "$LOGFILE"
    FAIL=$((FAIL+1))
  fi
done

echo "Total: $TOTAL | Success: $SUCCESS | Failed: $FAIL" | tee -a "$LOGFILE"
echo "=== PULL COMPLETE ==="
