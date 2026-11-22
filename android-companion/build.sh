#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_APK="$REPO_ROOT/internal/android/bin/cap-companion.apk"
BUILD_DIR="$SCRIPT_DIR/build"
KEYSTORE="$SCRIPT_DIR/cap-companion.keystore"
KEY_ALIAS="cap-companion"
KEY_PASS="cap-companion-guard"

# Locate Android SDK
ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
if [ ! -d "$ANDROID_HOME" ]; then
    echo "ERROR: ANDROID_HOME not found at $ANDROID_HOME" >&2
    exit 1
fi

# Pick build-tools (prefer 35.0.0)
if [ -d "$ANDROID_HOME/build-tools/35.0.0" ]; then
    BUILD_TOOLS="$ANDROID_HOME/build-tools/35.0.0"
else
    BUILD_TOOLS="$(ls -d "$ANDROID_HOME"/build-tools/* 2>/dev/null | sort -V | tail -n 1)"
fi

# Pick android.jar (prefer android-35, fallback android-34)
if [ -f "$ANDROID_HOME/platforms/android-35/android.jar" ]; then
    ANDROID_JAR="$ANDROID_HOME/platforms/android-35/android.jar"
elif [ -f "$ANDROID_HOME/platforms/android-34/android.jar" ]; then
    ANDROID_JAR="$ANDROID_HOME/platforms/android-34/android.jar"
else
    ANDROID_JAR="$(ls "$ANDROID_HOME"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -n 1)"
fi

# Locate JDK >= 11 (required by d8/apksigner)
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/javac" ]; then
    if [ -x "/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/javac" ]; then
        export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
    elif command -v /usr/libexec/java_home >/dev/null 2>&1 && /usr/libexec/java_home -v 11+ >/dev/null 2>&1; then
        export JAVA_HOME="$(/usr/libexec/java_home -v 11+)"
    fi
fi

if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/javac" ]; then
    echo "ERROR: JDK 11+ with javac not found. Set JAVA_HOME." >&2
    exit 1
fi
export PATH="$JAVA_HOME/bin:$PATH"

AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"

echo "==> Using JAVA_HOME=$JAVA_HOME"
echo "==> Using BUILD_TOOLS=$BUILD_TOOLS"
echo "==> Using ANDROID_JAR=$ANDROID_JAR"

# Generate deterministic signing keystore if missing
if [ ! -f "$KEYSTORE" ]; then
    echo "==> Generating signing keystore at $KEYSTORE"
    keytool -genkeypair \
        -keystore "$KEYSTORE" \
        -storetype PKCS12 \
        -storepass "$KEY_PASS" \
        -keypass "$KEY_PASS" \
        -alias "$KEY_ALIAS" \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -dname "CN=Cap Guard, OU=Cap, O=overkazaf, L=Local, ST=Local, C=US" \
        -noprompt
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/res_compiled" "$BUILD_DIR/gen" "$BUILD_DIR/classes" "$BUILD_DIR/dex" "$(dirname "$OUT_APK")"

echo "==> Compiling resources with aapt2"
"$AAPT2" compile --dir "$SCRIPT_DIR/res" -o "$BUILD_DIR/res_compiled/resources.zip"

echo "==> Linking resources & manifest with aapt2"
"$AAPT2" link \
    -o "$BUILD_DIR/unaligned.apk" \
    -I "$ANDROID_JAR" \
    --manifest "$SCRIPT_DIR/AndroidManifest.xml" \
    --java "$BUILD_DIR/gen" \
    --min-sdk-version 24 \
    --target-sdk-version 34 \
    "$BUILD_DIR/res_compiled/resources.zip"

echo "==> Compiling Java sources with javac"
JAVA_FILES="$(find "$SCRIPT_DIR/src" "$BUILD_DIR/gen" -name '*.java')"
javac \
    -Xlint:-options \
    -source 8 \
    -target 8 \
    -encoding UTF-8 \
    -classpath "$ANDROID_JAR" \
    -d "$BUILD_DIR/classes" \
    $JAVA_FILES

echo "==> Converting bytecode to DEX with d8"
CLASS_FILES="$(find "$BUILD_DIR/classes" -name '*.class')"
"$D8" \
    --release \
    --min-api 24 \
    --lib "$ANDROID_JAR" \
    --output "$BUILD_DIR/dex" \
    $CLASS_FILES

echo "==> Packaging classes.dex into APK"
(cd "$BUILD_DIR/dex" && zip -q -u "$BUILD_DIR/unaligned.apk" classes.dex)

echo "==> Running zipalign"
"$ZIPALIGN" -f -p 4 "$BUILD_DIR/unaligned.apk" "$BUILD_DIR/aligned.apk"

echo "==> Signing APK with apksigner"
"$APKSIGNER" sign \
    --ks "$KEYSTORE" \
    --ks-key-alias "$KEY_ALIAS" \
    --ks-pass "pass:$KEY_PASS" \
    --key-pass "pass:$KEY_PASS" \
    --v1-signing-enabled true \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    --v4-signing-enabled false \
    --out "$OUT_APK" \
    "$BUILD_DIR/aligned.apk"

echo "==> Verifying signed APK"
"$APKSIGNER" verify --print-certs "$OUT_APK"
"$AAPT2" dump badging "$OUT_APK" | head -n 25

rm -rf "$BUILD_DIR"
ls -lh "$OUT_APK"
echo "==> Done: $OUT_APK"
