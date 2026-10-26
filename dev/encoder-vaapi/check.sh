#!/usr/bin/env bash
# 离线语法/类型自检（可在 macOS 开发机执行）：用 vendored 真实 libva 头
# （include/va/，MIT 许可，取自 intel/libva master）做 -fsyntax-only，
# 保证 FFI 结构体布局/枚举/函数签名与上游 ABI 一致。运行时验证仍需 Linux 实机。
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
clang -fsyntax-only -Wall -I"$DIR/include" "$DIR/yuduan_enc_va.c"
echo "语法/类型自检通过（真实 libva 头，ABI 对齐上游 master）"
