#!/bin/bash
# Build + install the zero-permission universal probe.
set -e
SDK="$HOME/Library/Android/sdk"
BT="$SDK/build-tools/35.0.1"
PLATFORM="$SDK/platforms/android-36/android.jar"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/build"

rm -rf "$OUT"; mkdir -p "$OUT/classes" "$OUT/dx"

javac -source 17 -target 17 -nowarn \
  -classpath "$PLATFORM" \
  -d "$OUT/classes" \
  $(find "$HERE/src" -name '*.java')

D8="$BT/d8"
"$D8" --lib "$PLATFORM" --min-api 32 --output "$OUT/dx" $(find "$OUT/classes" -name '*.class') >/dev/null

cp "$OUT/dx/classes.dex" "$OUT/classes.dex"
"$BT/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
  -o "$OUT/base.apk" --min-sdk-version 32 --target-sdk-version 36 >/dev/null

cp "$OUT/base.apk" "$OUT/universal.apk"
cd "$OUT" && zip -q -r universal.apk classes.dex
if [ -d "$HERE/assets" ]; then
  (cd "$HERE" && zip -q -r "$OUT/universal.apk" assets)
fi
if [ -d "$HERE/lib" ]; then
  (cd "$HERE" && zip -q -r "$OUT/universal.apk" lib)
fi

# sign with a throwaway debug key
KS="$HERE/probe.keystore"
if [ ! -f "$KS" ]; then
  keytool -genkeypair -v -keystore "$KS" -storepass android -keypass android \
    -alias probe -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=VRP Probe, OU=Research, O=Research, L=NA, S=NA, C=NA" >/dev/null 2>&1
fi

"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --ks-key-alias probe --out "$HERE/probe.apk" "$OUT/universal.apk" 2>&1 | tail -2

echo "BUILT: $HERE/probe.apk"
adb install -r -g "$HERE/probe.apk" 2>&1 | tail -3
adb shell pm list permissions -g 2>/dev/null >/dev/null
echo "--- installed permissions of com.vrp.probe ---"
adb shell dumpsys package com.vrp.probe 2>/dev/null | sed -n '/requested permissions/,/install permissions/p' | head -12