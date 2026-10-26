@echo off
rem 构建 Windows 版编码器直测工具（与 encoder-vt/harness.c 同构，动态库加载用 LoadLibraryA）。
rem 依赖：Visual Studio Build Tools（在 "x64 Native Tools Command Prompt" 下执行）。
setlocal
set DIR=%~dp0
cl /nologo /O2 /W4 "%DIR%harness-win.c" /Fe:"%DIR%enc_harness.exe"
if errorlevel 1 (
  echo 构建失败
  exit /b 1
)
echo OK: %DIR%enc_harness.exe
echo 用法： enc_harness.exe %%TEMP%%\yuduan_enc_mf.dll h264 1280 720 60 out.h264
