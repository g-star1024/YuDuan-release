@echo off
rem YuDuan agent - foreground console run for debugging (Ctrl+C to stop).
rem
rem Production install needs NO script: double-click yuduan-agent.exe itself.
rem   - First run: auto-elevates (UAC), cleans stale config, installs the
rem     Windows service (boot autostart + 5s crash-restart guard), starts it.
rem   - Later runs: shows service status and exits (service runs in background).
rem   - Reinstall/reset: yuduan-agent.exe --setup
rem   - Uninstall:      yuduan-agent.exe --uninstall
rem   - Status:         yuduan-agent.exe --status
rem
rem This script passes --console to force foreground mode (bypasses the
rem double-click install/status shortcuts above).
rem
rem No config needed by default: agent broadcasts UDP discovery on LAN and
rem registers with the hub as soon as it comes online (install-and-register).
rem Only needed when the hub is unreachable (cross-subnet / router isolates
rem broadcast) or to point at another environment:
rem   set YUDUAN_HUB=ws://<hub-ip>:8080/ws/agent
rem wss (TLS) on Windows needs a system openssl; v0.2.2+ auto-detects Git for
rem Windows' copy. Manual override only if installed elsewhere:
rem   set YUDUAN_OPENSSL=C:\Program Files\Git\usr\bin\openssl.exe
rem   set YUDUAN_HUB=wss://<hub-ip>:8443/ws/agent
rem NOTE: keep this file ASCII + CRLF. cmd.exe on Chinese Windows reads
rem       UTF-8/UTF-16 as GBK, corrupting non-ASCII and breaking parsing.
"%~dp0yuduan-agent.exe" --console
pause
