#!/bin/bash
set -e

ANDROID_SDK="/Users/sandiyochristan/Library/Android/sdk"
BUILD_TOOLS="$ANDROID_SDK/build-tools/36.0.0"
PLATFORM="$ANDROID_SDK/platforms/android-35/android.jar"

AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

mkdir -p build
echo "[1/6] Compiling resources..."
$AAPT2 compile --dir res -o build/compiled_res.zip

echo "[2/6] Linking APK..."
$AAPT2 link -o build/base.apk -I "$PLATFORM" --manifest AndroidManifest.xml build/compiled_res.zip --auto-add-overlay

echo "[3/6] Compiling Java..."
mkdir -p build/classes
find src -name "*.java" | xargs javac -source 11 -target 11 -classpath "$PLATFORM" -d build/classes 2>&1

echo "[4/6] Creating DEX..."
find build/classes -name "*.class" | xargs $D8 --output build/ --lib "$PLATFORM" --min-api 28

echo "[5/6] Adding DEX to APK..."
cd build
cp base.apk unsigned.apk
zip -j unsigned.apk classes.dex
cd ..

echo "[6/6] Signing APK..."
$ZIPALIGN -f 4 build/unsigned.apk build/aligned.apk
$APKSIGNER sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android --out build/testonly.apk build/aligned.apk

echo "Built: build/testonly.apk"
