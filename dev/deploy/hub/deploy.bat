@echo off
rem YuDuan Hub one-click deploy (double-click to run).
rem Flow: self-elevate to admin -> register-task.ps1 (clean old env -> gen config -> firewall -> service).
rem Existing hub.env: press Enter to KEEP keys (agents stay valid); enter 2 to RESET all keys.
rem NOTE: keep this file ASCII + CRLF. cmd.exe on Chinese Windows reads UTF-8 as GBK.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
echo ===============================================
echo   YuDuan Hub one-click deploy
echo   clean old env -^> gen config -^> firewall -^> service
echo ===============================================
if not exist hub.env goto deploy
echo Existing config detected: hub.env
set "CHOICE="
set /p CHOICE=Press Enter to KEEP existing keys, or type 2 to RESET and regenerate:
if "%CHOICE%"=="2" set "RESET=-ResetConfig"
:deploy
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0register-task.ps1" %RESET%
if %errorlevel% neq 0 (
  echo.
  echo *************************************************
  echo   DEPLOY FAILED. Screenshot this window for support.
  echo   部署失败：请截图本窗口发支持。
  echo *************************************************
  pause
  exit /b 1
)
echo.
echo Done. Hub console: http://localhost:8080
echo (Other machines: http://^<this-server-ip^>:8080)
pause
