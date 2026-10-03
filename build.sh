#!/bin/bash
set -e
# LD-iOS 插件编译脚本（GitHub Actions macOS runner 上执行）

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
echo "SDK: $SDK"

clang -target arm64-apple-ios12.0 \
  -isysroot "$SDK" \
  -fobjc-arc \
  -O2 \
  -dynamiclib \
  -o LD_iOS_Aim.dylib \
  entry.mm \
  -framework UIKit -framework Foundation -lc++

codesign -s - --force LD_iOS_Aim.dylib
echo "BUILD OK:"
ls -la LD_iOS_Aim.dylib
file LD_iOS_Aim.dylib
