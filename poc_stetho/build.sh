#!/bin/bash
set -e

ANDROID_SDK="$HOME/Library/Android/sdk"
BUILD_TOOLS="$ANDROID_SDK/build-tools/35.0.1"
PLATFORM="$ANDROID_SDK/platforms/android-35/android.jar"

AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

mkdir -p build/classes
rm -f build/classes/*.class

echo "[1/5] Compiling resources..."
$AAPT2 compile --dir res -o build/compiled_res.zip

echo "[2/5] Linking APK..."
$AAPT2 link -o build/base.apk -I "$PLATFORM" --manifest AndroidManifest.xml \
    build/compiled_res.zip --auto-add-overlay --min-sdk-version 34 \
    --version-code 1 --version-name 1

echo "[3/5] Compiling Java..."
find src -name "*.java" | xargs javac -source 11 -target 11 -nowarn \
    -classpath "$PLATFORM" -d build/classes 2>&1 | grep -v "^Note:" || true

echo "[4/5] DEX + package..."
find build/classes -name "*.class" | xargs $D8 --output build/ --lib "$PLATFORM" --min-api 34
cp build/base.apk build/unsigned.apk
(cd build && zip -j unsigned.apk classes.dex >/dev/null)

echo "[5/5] Signing..."
$ZIPALIGN -f 4 build/unsigned.apk build/aligned.apk
$APKSIGNER sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android \
    --out build/stetho_poc.apk build/aligned.apk

echo "Built: build/stetho_poc.apk"