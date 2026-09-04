#!/bin/bash
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK="$HOME/Library/Android/sdk"
BUILD_TOOLS="$SDK/build-tools/36.0.0"
PLATFORM="$SDK/platforms/android-36/android.jar"

AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
APKSIGNER="$BUILD_TOOLS/apksigner"
ZIPALIGN="$BUILD_TOOLS/zipalign"

OUT="$APP_DIR/build"
rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/obj" "$OUT/apk"

echo "[1/6] Compiling resources..."
"$AAPT2" compile --dir "$APP_DIR/res" -o "$OUT/compiled_res.zip"

echo "[2/6] Linking APK..."
"$AAPT2" link \
    --proto-format \
    -o "$OUT/apk/base.apk" \
    -I "$PLATFORM" \
    --manifest "$APP_DIR/AndroidManifest.xml" \
    --java "$OUT/gen" \
    "$OUT/compiled_res.zip" \
    --auto-add-overlay

# Extract proto APK for classes
cd "$OUT/apk"
unzip -qo base.apk -d base_extracted 2>/dev/null || true
cd "$APP_DIR"

echo "[3/6] Compiling Java..."
# Need to convert proto format to binary for aapt classic
# Actually, let's use aapt (non-2) for simpler flow
"$BUILD_TOOLS/aapt" package \
    -f -m \
    -J "$OUT/gen" \
    -M "$APP_DIR/AndroidManifest.xml" \
    -S "$APP_DIR/res" \
    -I "$PLATFORM"

find "$APP_DIR/src" "$OUT/gen" -name "*.java" > "$OUT/sources.txt"
javac --release 17 \
    -classpath "$PLATFORM" \
    -d "$OUT/obj" \
    @"$OUT/sources.txt" 2>&1

echo "[4/6] Creating DEX..."
find "$OUT/obj" -name "*.class" > "$OUT/classes.txt"
"$D8" \
    --release \
    --min-api 34 \
    --output "$OUT" \
    @"$OUT/classes.txt"

echo "[5/6] Packaging APK..."
"$BUILD_TOOLS/aapt" package \
    -f \
    -M "$APP_DIR/AndroidManifest.xml" \
    -S "$APP_DIR/res" \
    -I "$PLATFORM" \
    -F "$OUT/unsigned.apk"

# Add classes.dex
cd "$OUT"
cp classes.dex "$OUT/apk_add/"  2>/dev/null || mkdir -p "$OUT/apk_add" && cp classes.dex "$OUT/apk_add/"
cd "$OUT/apk_add"
zip -j "$OUT/unsigned.apk" classes.dex

echo "[6/6] Signing APK..."
# Generate a debug keystore if needed
KEYSTORE="$OUT/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair \
        -keystore "$KEYSTORE" \
        -storepass android \
        -keypass android \
        -alias debug \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -dname "CN=Debug" 2>/dev/null
fi

"$APKSIGNER" sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:android \
    --key-pass pass:android \
    --ks-key-alias debug \
    --out "$OUT/binder_leak_poc.apk" \
    "$OUT/unsigned.apk"

echo ""
echo "=== Build complete ==="
echo "APK: $OUT/binder_leak_poc.apk"
echo ""
echo "Install: adb install -r $OUT/binder_leak_poc.apk"
echo "Run: adb shell am start -n com.research.binderleak/.MainActivity"
