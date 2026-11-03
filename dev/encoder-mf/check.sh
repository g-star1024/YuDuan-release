#!/usr/bin/env bash
# 离线语法/类型自检（可在 macOS 开发机执行）：用自写 MF 声明子集（mfstub.h，
# GUID/方法顺序据 MSDN）做 -fsyntax-only。Windows 目标机构建改用 SDK 真头
# （见 build-windows.cmd），运行时 ABI 由 SDK 保证；本检查保证代码内部自洽。
# -Wno-unused-function：非 Windows 检查路径下编码主链被 #ifdef 屏蔽，属预期。
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
clang -fsyntax-only -Wall -Wno-unused-function "$DIR/yuduan_enc_mf.c"
echo "语法/类型自检通过（mfstub.h 声明子集；Windows 目标机以 SDK 头为准）"
