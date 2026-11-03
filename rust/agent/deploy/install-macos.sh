#!/bin/bash
# 御端（YuDuan）副端 —— macOS 服务安装/卸载脚本（launchd LaunchDaemon，系统级守护进程）。
#
# 用法：
#   sudo ./deploy/install-macos.sh                # 安装并启动
#   sudo ./deploy/install-macos.sh --uninstall    # 停止并移除
#
# 前置：先构建二进制  rustc -O src/main.rs -o target/agent
# 注意：安装后如需修改中枢地址/验签密钥，编辑 /Library/LaunchDaemons/com.yuduan.agent.plist
#       然后 sudo launchctl bootout system/com.yuduan.agent && sudo launchctl bootstrap system/com.yuduan.agent

set -euo pipefail

LABEL="com.yuduan.agent"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="${SRC_DIR}/target/agent"
PLIST_SRC="${SRC_DIR}/deploy/launchd/${LABEL}.plist"
BIN_DST="/usr/local/bin/yuduan-agent"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"
LOG_FILE="/var/log/yuduan-agent.log"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "错误：请用 sudo 运行（系统级服务需要 root）" >&2
    exit 1
fi

uninstall() {
    echo "==> 停止并移除 ${LABEL}"
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
    rm -f "${PLIST_DST}" "${BIN_DST}"
    echo "==> 已卸载（日志保留：${LOG_FILE}）"
}

if [[ "${1:-}" == "--uninstall" ]]; then
    uninstall
    exit 0
fi

echo "==> 检查二进制"
if [[ ! -x "${BIN_SRC}" ]]; then
    echo "错误：未找到 ${BIN_SRC}，请先在 rust/agent 目录执行：rustc -O src/main.rs -o target/agent" >&2
    exit 1
fi

echo "==> 安装二进制 -> ${BIN_DST}"
install -m 0755 "${BIN_SRC}" "${BIN_DST}"

echo "==> 安装 plist -> ${PLIST_DST}"
install -m 0644 "${PLIST_SRC}" "${PLIST_DST}"

echo "==> 预创建日志文件"
touch "${LOG_FILE}" && chmod 644 "${LOG_FILE}"

echo "==> 加载服务（先 bootout 避免重复注册）"
launchctl bootout "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "${PLIST_DST}"
launchctl enable "system/${LABEL}" 2>/dev/null || true

sleep 1
echo "==> 服务状态："
launchctl print "system/${LABEL}" | grep -E 'state|pid|program' || true
echo "==> 完成。查看日志：tail -f ${LOG_FILE}"
