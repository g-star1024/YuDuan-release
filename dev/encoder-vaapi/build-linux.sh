#!/usr/bin/env bash
# 构建 Linux VAAPI 原生编码器动态库（§8.3.3 C-ABI，在 Linux 目标机上执行）。
# 用法：bash build-linux.sh [输出路径]   （默认 /tmp/libyuduan_enc_va.so）
# 依赖：libva-dev libva-drm2（Debian/Ubuntu：apt install libva-dev；
#       RHEL/Fedora：dnf install libva libva-devel）
# 有 GPU 的机器上亦可直接用系统头：把 -Iinclude 换成 $(pkg-config --cflags libva)。
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-/tmp/libyuduan_enc_va.so}"
CFLAGS=$(pkg-config --cflags libva 2>/dev/null || echo "-I$DIR/include")
LIBS=$(pkg-config --libs libva libva-drm 2>/dev/null || echo "-lva -lva-drm")
cc -shared -fPIC -O2 -Wall $CFLAGS "$DIR/yuduan_enc_va.c" $LIBS -o "$OUT"
echo "OK: $OUT"
# 冒烟：无 GPU 时 create 返回 NULL 属预期（能力探测诚实失败）
python3 - "$OUT" <<'EOF' || true
import ctypes, sys
lib = ctypes.CDLL(sys.argv[1])
lib.yuduan_enc_create.restype = ctypes.c_void_p
h = lib.yuduan_enc_create(b"h264", 1280, 720)
print("create(h264,1280x720) ->", "可用" if h else "NULL（无 GPU/驱动，副端将回退 RAW）")
if h:
    lib.yuduan_enc_destroy(h)
EOF
