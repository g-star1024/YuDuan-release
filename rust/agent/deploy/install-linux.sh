#!/bin/bash
# 御端（YuDuan）副端 —— Linux 服务安装/卸载脚本（systemd）。
#
# 用法：
#   sudo ./deploy/install-linux.sh                # 安装并启动
#   sudo ./deploy/install-linux.sh --uninstall    # 停止并移除
#
# 前置：先构建二进制  rustc -O src/main.rs -o target/agent
# 注意：安装后如需修改中枢地址/验签密钥：
#   systemctl edit yuduan-agent   （写入 override 片段，避免直接改单元文件被包升级覆盖）

set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="${SRC_DIR}/target/agent"
UNIT_SRC="${SRC_DIR}/deploy/systemd/yuduan-agent.service"
BIN_DST="/usr/local/bin/yuduan-agent"
UNIT_DST="/etc/systemd/system/yuduan-agent.service"
LOG_FILE="/var/log/yuduan-agent.log"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "错误：请用 sudo 运行（系统级服务需要 root）" >&2
    exit 1
fi

if [[ "${1:-}" == "--uninstall" ]]; then
    echo "==> 停止并禁用 yuduan-agent"
    systemctl disable --now yuduan-agent 2>/dev/null || true
    rm -f "${UNIT_DST}" "${BIN_DST}"
    systemctl daemon-reload
    echo "==> 已卸载（日志保留：${LOG_FILE}）"
    exit 0
fi

echo "==> 检查二进制"
if [[ ! -x "${BIN_SRC}" ]]; then
    echo "错误：未找到 ${BIN_SRC}，请先在 rust/agent 目录执行：rustc -O src/main.rs -o target/agent" >&2
    exit 1
fi

echo "==> 安装二进制 -> ${BIN_DST}"
install -m 0755 "${BIN_SRC}" "${BIN_DST}"

echo "==> 安装单元 -> ${UNIT_DST}"
install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"

echo "==> 预创建日志文件"
touch "${LOG_FILE}" && chmod 644 "${LOG_FILE}"

echo "==> 重载并启动"
systemctl daemon-reload
systemctl enable --now yuduan-agent

sleep 1
echo "==> 服务状态："
systemctl status yuduan-agent --no-pager || true
echo "==> 完成。查看日志：journalctl -u yuduan-agent -f  或  tail -f ${LOG_FILE}"
