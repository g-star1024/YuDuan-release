#!/usr/bin/env bash
# 构建 macOS VideoToolbox 原生编码器动态库（§8.3.3 C-ABI）。
# 用法：bash build.sh [输出目录]   （默认输出到 /tmp/libyuduan_enc_vt.dylib）
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-/tmp/libyuduan_enc_vt.dylib}"
clang -dynamiclib -O2 \
  -framework VideoToolbox -framework CoreMedia -framework CoreFoundation -framework CoreVideo \
  "$DIR/yuduan_enc_vt.c" -o "$OUT"
echo "OK: $OUT"
