@echo off
rem YuDuan Hub Windows launcher (foreground console; good for first-time deploy log)
rem Config: hub.env in the SAME directory (KEY=VALUE per line, same format as env.example; defaults if absent)
rem Auto-start on boot: right-click register-task.ps1 -> "Run with PowerShell"
rem NOTE: keep this file ASCII + CRLF. cmd.exe on Chinese Windows reads UTF-8/UTF-16 as GBK,
rem       which corrupts non-ASCII and breaks parsing (mojibake / "not recognized" errors).
setlocal enabledelayedexpansion
cd /d "%~dp0"

if exist hub.env (
  for /f "usebackq eol=# tokens=1,* delims==" %%a in ("hub.env") do (
    if not "%%b"=="" set "%%a=%%b"
  )
)

rem Plain listen defaults to :8080 inside yuduan-hub.exe (auto-fallback 8081-8083/18080 if busy)
if "%YUDUAN_REPO%"=="" set "YUDUAN_REPO=%~dp0data\repo"
if not exist "%YUDUAN_REPO%" mkdir "%YUDUAN_REPO%"
rem v0.4.29 F-07: discovery UDP port default 18242; override via YUDUAN_DISCOVERY_PORT in hub.env
if "%YUDUAN_DISCOVERY_PORT%"=="" set "YUDUAN_DISCOVERY_PORT=18242"

echo [yuduan-hub] listen %YUDUAN_HUB_ADDR%   repo %YUDUAN_REPO%
echo [yuduan-hub] agent auto-discovery UDP %YUDUAN_DISCOVERY_PORT%; cross-subnet: set YUDUAN_HUB on agent
echo.
rem Crash guard: auto-restart 5s after the hub process exits (kill/crash/panic).
rem Boot autostart comes from the scheduled task (register-task.ps1, ONSTART + SYSTEM).
rem ping is used as a portable sleep (timeout.exe may be blocked in some service contexts).
:loop
yuduan-hub.exe
echo [yuduan-hub] %date% %time% hub exited (code %errorlevel%), restarting in 5s...
ping -n 6 127.0.0.1 >nul
goto loop
