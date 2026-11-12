@echo off
rem v0.4.24: UTF-8 codepage so Chinese lines display correctly on zh-CN cmd (GBK default would mojibake).
chcp 65001 >nul
rem YuDuan Hub one-click deploy (double-click to run).
rem Flow: self-elevate to admin -> register-task.ps1 (clean old env -> gen config -> firewall -> service).
rem Existing hub.env: press Enter to KEEP keys (agents stay valid); enter 2 to RESET all keys.
rem NOTE: keep this file ASCII + CRLF. cmd.exe on Chinese Windows reads UTF-8 as GBK.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo Requesting administrator privileges...
  echo 正在申请管理员权限，本窗口即将关闭，请在弹出的 UAC 窗口点「是」。
  echo （这不是闪退：授权后会自动打开新的部署窗口继续执行。）
  rem v0.4.23: forward extra args (e.g. -DbDsn) through the elevation relaunch
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
echo ===============================================
echo   YuDuan Hub one-click deploy
echo   clean old env -^> gen config -^> firewall -^> service
echo ===============================================
set "PUBLIC_ARGS="
set "MODECHOICE="
set "STAGINGIN="
set /p MODECHOICE=Deploy mode - press Enter for LAN, or type P for Public network:
if /I "%MODECHOICE%"=="P" (
  set /p PUBDOMAIN=Enter public FQDN domain:
  set /p PUBEMAIL=Enter contact email:
  set "PUBCERT=self"
  set /p PUBCERTIN=Cert mode - press Enter for self-signed, or type acme:
  set /p STAGINGIN=ACME staging pre-validation - type S for staging, Enter for production:
)
if /I "%MODECHOICE%"=="P" if not "%PUBCERTIN%"=="" set "PUBCERT=%PUBCERTIN%"
if /I "%MODECHOICE%"=="P" set "PUBLIC_ARGS=-Public -Domain %PUBDOMAIN% -Email %PUBEMAIL% -CertMode %PUBCERT%"
if /I "%MODECHOICE%"=="P" if /I "%STAGINGIN%"=="S" set "PUBLIC_ARGS=%PUBLIC_ARGS% -Staging"

rem O-02 (v0.4.30): interactive UDP discovery port; empty keeps default 18242.
set "DISCOVERY_ARGS="
set /p DISCOVERYPORT=UDP discovery port (default 18242, press Enter to keep default):
if not "%DISCOVERYPORT%"=="" set "DISCOVERY_ARGS=-DiscoveryPort %DISCOVERYPORT%"

if not exist hub.env goto deploy
echo Existing config detected: hub.env
set "CHOICE="
set /p CHOICE=Press Enter to KEEP existing keys, or type 2 to RESET and regenerate:
if "%CHOICE%"=="2" set "RESET=-ResetConfig"
:deploy
rem v0.4.23: -NonInteractive = never block on hidden prompts (PG password / DSN paste).
rem Auto flow does its best; anything that needs input degrades with a yellow WARN instead.
rem Extra args (e.g. -DbDsn "postgres://...") are forwarded to register-task.ps1.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0register-task.ps1" -NonInteractive %RESET% %PUBLIC_ARGS% %DISCOVERY_ARGS% %*
if %errorlevel% neq 0 (
  echo.
  echo *************************************************
  echo   DEPLOY FAILED. Screenshot this window for support.
  echo   部署失败：请截图本窗口发支持。
  echo   多数情况直接重跑本脚本即可恢复（已保留 hub.env，不会重置密钥）。
  echo *************************************************
  pause
  exit /b 1
)
echo.
rem v0.4.35（一键部署成功率实测矩阵 #4）：实际端口由 register-task.ps1 落盘到 data\hub-port.txt，
rem 8080 被占用回退到 8081/8082/8083/18080 时显示真实端口，避免提示错误地址。
set "HUBPORT=8080"
if exist "%~dp0data\hub-port.txt" set /p HUBPORT=<"%~dp0data\hub-port.txt"
echo Done. Hub console: http://localhost:%HUBPORT%
echo (Other machines: http://^<this-server-ip^>:%HUBPORT%)
rem v0.4.36（一键部署成功率实测矩阵 #6）：机器可读结论 deploy-result.json（成功/失败 + 原因码），便于外部编排判定。
if exist "%~dp0deploy-result.json" (
  echo.
  echo [deploy-result.json]:
  type "%~dp0deploy-result.json"
)
pause
