@echo off
rem 构建 Windows Media Foundation 原生编码器动态库（SS8.3.3 C-ABI，Windows 目标机执行）。
rem 用法：build-windows.cmd [输出路径]（默认 %TEMP%\yuduan_enc_mf.dll）
rem 依赖：Visual Studio Build Tools（在 "x64 Native Tools Command Prompt" 下执行）。
rem 注意：使用 Windows SDK 真头（mfapi.h/mfidl.h/mfobjects.h/mftransform.h/codecapi.h/icodecapi.h），
rem ABI 由 SDK 保证。链接需 mfplat（MF 平台）/mfuuid（MF IID）/ole32（COM）/oleaut32（VARIANT）。
setlocal
set OUT=%1
if "%OUT%"=="" set OUT=%TEMP%\yuduan_enc_mf.dll
set DIR=%~dp0
cl /nologo /LD /O2 /W4 /utf-8 "%DIR%yuduan_enc_mf.c" /link /OUT:"%OUT%" mfplat.lib mfuuid.lib ole32.lib oleaut32.lib
if errorlevel 1 (
  echo 构建失败
  exit /b 1
)
echo OK: %OUT%
echo 接入副端：set YUDUAN_ENCODER_LIB=%OUT% 后启动 agent（无 GPU/无编码器 MFT 时
echo 副端能力探测会诚实回退 RAW_RGBA，属预期）。
