#!/bin/bash
set -e
cd "$(dirname "$0")"

AAPT2="$HOME/Library/Android/sdk/build-tools/35.0.0/aapt2"
D8="$HOME/Library/Android/sdk/build-tools/36.0.0/d8"
ZIPALIGN="$HOME/Library/Android/sdk/build-tools/36.0.0/zipalign"
APKSIGNER="$HOME/Library/Android/sdk/build-tools/36.0.0/apksigner"
ANDROID_JAR="$HOME/Library/Android/sdk/platforms/android-35/android.jar"
KEYSTORE="/Users/sandiyochristan/Documents/vulnerabilityRes/poc_app/debug.keystore"

rm -rf build/gen build/obj build/classes build/*.apk build/*.jar 2>/dev/null
mkdir -p build/gen build/obj build/classes

echo "[1/6] Linking resources..."
$AAPT2 link -o build/resources.apk \
    --manifest AndroidManifest.xml \
    -I "$ANDROID_JAR" \
    --java build/gen \
    --auto-add-overlay

echo "[2/6] Compiling Java..."
javac --release 11 \
    -cp "$ANDROID_JAR" \
    -d build/classes \
    src/com/poc/contactsdump/*.java

echo "[3/6] Creating JAR..."
jar cf build/classes.jar -C build/classes .

echo "[4/6] Running D8..."
$D8 --min-api 34 --output build/ build/classes.jar

echo "[5/6] Packaging APK..."
cp build/resources.apk build/unsigned.apk
cd build
unzip -o resources.apk resources.arsc 2>/dev/null || true
zip -j unsigned.apk classes.dex
zip -0 -j unsigned.apk resources.arsc 2>/dev/null || true
cd ..

echo "[6/6] Aligning and signing..."
$ZIPALIGN -f 4 build/unsigned.apk build/aligned.apk
$APKSIGNER sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:android \
    --min-sdk-version 34 \
    --out build/contacts_dump_poc.apk \
    build/aligned.apk

echo "Done: build/contacts_dump_poc.apk"
ls -la build/contacts_dump_poc.apk
