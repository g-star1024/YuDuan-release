@echo off
rem YuDuan agent - console run (Ctrl+C to stop)
rem
rem 默认无需任何配置：副端启动时向局域网 UDP 广播自动发现中枢（§8.4），
rem 中枢上线后自动注册（安装即注册）。
rem 仅当中枢不可达（跨网段广播被路由器隔离）或需指向其他环境时才显式指定：
rem   set YUDUAN_HUB=ws://<中枢IP>:18241/ws/agent
"%~dp0yuduan-agent.exe"
pause
