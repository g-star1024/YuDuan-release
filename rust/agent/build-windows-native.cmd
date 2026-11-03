@echo off
REM ============================================================
REM 御端 Rust 副端 —— Windows 原生构建（发布唯一通道）
REM
REM 背景（2026-10-25 二次实机核实）：macOS 交叉编译链（rust-lld +
REM mingw CRT + libgcc/gimli）产物在 Windows 上启动即 STATUS_STACK_OVERFLOW
REM (0xC00000FD)，与 rustc 版本无关。Windows 发布包一律用本脚本原生构建。
REM
REM 用法（在真实 Windows 主机，仓库 rust/agent 目录下）：
REM   1. git pull 拉取最新源码
REM   2. 右键「使用 PowerShell 运行」本脚本，或管理员 PowerShell 执行
REM   3. 构建成功后：结束旧副端进程/服务，用新 exe 覆盖，run-agent.cmd 启动
REM
REM 注意：不要用 cargo build（本 crate 零外部依赖，离线环境会因更新
REM registry 失败）；直接 rustc 单文件编译即可。
REM ============================================================
setlocal
cd /d "%~dp0"

where rustc >nul 2>nul
if errorlevel 1 (
  echo [FATAL] 未找到 rustc。请先安装 rustup（MSVC 工具链）并重开终端。
  exit /b 1
)

echo [1/3] rustc 版本：
rustc -vV | findstr /C:"release" /C:"commit-hash"

echo [2/3] 原生编译 src\main.rs ...
rustc -O src\main.rs -o yuduan-agent.exe
if errorlevel 1 (
  echo [FATAL] 编译失败，见上方错误。
  exit /b 1
)

echo [3/3] 产物校验：
for %%F in (yuduan-agent.exe) do echo   大小: %%~zF 字节
certutil -hashfile yuduan-agent.exe SHA256 | findstr /v /C:"SHA256" /C:"certutil"

echo.
echo [DONE] 构建完成: yuduan-agent.exe
echo 部署三步：
echo   1) 停止旧副端（任务管理器结束 yuduan-agent.exe；或 net stop yuduan-agent）
echo   2) 用新 exe 覆盖旧文件
echo   3) 双击 run-agent.cmd 启动（务必在登录用户会话内，勿用服务方式跑远控）
echo 冒烟标准：控制台出现「[agent] 御端 Rust 副端启动」且注册成功，方可交付。
endlocal
