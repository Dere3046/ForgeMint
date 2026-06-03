#!/bin/bash
set -e

# find project root
ROOT=$(cd "$(dirname "$0")" && pwd)
echo "PROJECT=$ROOT"

echo "Android: $(adb shell getprop ro.build.version.release)"
echo "ABI: $(adb shell getprop ro.product.cpu.abi)"

# build APK
cd "$ROOT"
chmod +x gradlew
./gradlew :app:assembleDebug

# install and run
apk=$(find "$ROOT/app/build/outputs" -name '*.apk' | head -1)
echo "APK=$apk"
adb install -r -g "$apk"

adb shell am start -n com.raplt.test/.MainActivity
sleep 5

echo "=== logcat ==="
adb logcat -d -s RaPLT:V | tail -10
