#!/bin/bash
set -e
cd "$(dirname "$0")"

AAPT2="$HOME/Library/Android/sdk/build-tools/35.0.0/aapt2"
D8="$HOME/Library/Android/sdk/build-tools/36.0.0/d8"
ZIPALIGN="$HOME/Library/Android/sdk/build-tools/36.0.0/zipalign"
APKSIGNER="$HOME/Library/Android/sdk/build-tools/36.0.0/apksigner"
ANDROID_JAR="$HOME/Library/Android/sdk/platforms/android-35/android.jar"
KEYSTORE="/Users/sandiyochristan/Documents/vulnerabilityRes/poc_app/debug.keystore"

rm -rf build/gen build/obj build/classes build/*.apk build/*.jar build/*.dex build/res_compiled 2>/dev/null
mkdir -p build/gen build/obj build/classes build/res_compiled

echo "[1/7] Compiling resources..."
$AAPT2 compile --dir res -o build/res_compiled/

echo "[2/7] Linking resources..."
$AAPT2 link -o build/resources.apk \
    --manifest AndroidManifest.xml \
    -I "$ANDROID_JAR" \
    --java build/gen \
    --auto-add-overlay \
    build/res_compiled/*.flat

echo "[3/7] Compiling Java..."
javac --release 11 \
    -cp "$ANDROID_JAR" \
    -d build/classes \
    src/com/poc/confused_deputy/*.java

echo "[4/7] Creating JAR..."
jar cf build/classes.jar -C build/classes .

echo "[5/7] Running D8 (dex)..."
$D8 --min-api 28 --output build/ build/classes.jar

echo "[6/7] Packaging APK..."
cp build/resources.apk build/unsigned.apk
cd build
zip -j unsigned.apk classes.dex
cd ..

echo "[7/7] Aligning and signing..."
$ZIPALIGN -f 4 build/unsigned.apk build/aligned.apk
$APKSIGNER sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:android \
    --min-sdk-version 28 \
    --out build/confused_deputy_poc.apk \
    build/aligned.apk

echo ""
echo "Done: build/confused_deputy_poc.apk"
ls -la build/confused_deputy_poc.apk
