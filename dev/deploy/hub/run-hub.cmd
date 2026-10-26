@echo off
rem 御端中枢 Windows 启动脚本（控制台前台运行，便于首次部署观察日志）
rem 配置：同目录 hub.env（KEY=VALUE 逐行，与 env.example 同格式；缺省用默认值）
rem 服务化自启：右键「使用 PowerShell 运行」register-task.ps1
setlocal enabledelayedexpansion
cd /d "%~dp0"

if exist hub.env (
  for /f "usebackq eol=# tokens=1,* delims==" %%a in ("hub.env") do (
    if not "%%b"=="" set "%%a=%%b"
  )
)

if "%YUDUAN_HUB_ADDR%"=="" set "YUDUAN_HUB_ADDR=:18241"
if "%YUDUAN_REPO%"=="" set "YUDUAN_REPO=%~dp0data\repo"
if not exist "%YUDUAN_REPO%" mkdir "%YUDUAN_REPO%"

echo [yuduan-hub] 监听 %YUDUAN_HUB_ADDR%  软件仓库 %YUDUAN_REPO%
echo [yuduan-hub] 副端同网段自动发现（UDP 18242）；跨网段请设副端 YUDUAN_HUB
echo.
yuduan-hub.exe
pause
