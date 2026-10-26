#!/usr/bin/env bash
# 御端中枢一键安装脚本（Linux，systemd 环境）
# 用法：sudo ./install.sh [yuduan-hub 二进制路径]
# 产物布局：
#   /usr/local/bin/yuduan-hub          二进制
#   /etc/yuduan-hub/env                配置（首次安装生成，升级不覆盖）
#   /etc/systemd/system/yuduan-hub.service
#   /var/lib/yuduan-hub                数据与软件仓库目录
set -euo pipefail

BIN_SRC="${1:-yuduan-hub}"
[[ -x "$BIN_SRC" ]] || { echo "错误：找不到可执行文件 $BIN_SRC"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "请用 sudo 运行"; exit 1; }
command -v systemctl >/dev/null || { echo "错误：需要 systemd 环境"; exit 1; }

echo "==> 创建系统用户与目录"
id yuduan-hub &>/dev/null || useradd --system --home /var/lib/yuduan-hub --shell /usr/sbin/nologin yuduan-hub
mkdir -p /var/lib/yuduan-hub/repo /etc/yuduan-hub

echo "==> 安装二进制"
install -m 0755 "$BIN_SRC" /usr/local/bin/yuduan-hub

echo "==> 安装配置"
if [[ ! -f /etc/yuduan-hub/env ]]; then
  install -m 0640 -o root -g yuduan-hub "$SCRIPT_DIR/env.example" /etc/yuduan-hub/env
  # 自动生成三项生产密钥并写回（HMAC/ENFORCE/PEPPER）
  hmac=$(openssl rand -hex 32); pepper=$(openssl rand -hex 32)
  sed -i "s|^YUDUAN_HMAC_SECRET=$|YUDUAN_HMAC_SECRET=$hmac|" /etc/yuduan-hub/env
  sed -i "s|^YUDUAN_PEPPER=$|YUDUAN_PEPPER=$pepper|" /etc/yuduan-hub/env
  echo "    已自动生成 YUDUAN_HMAC_SECRET 与 YUDUAN_PEPPER（副端侧需同步 HMAC 密钥）"
else
  echo "    /etc/yuduan-hub/env 已存在，保留（升级不覆盖配置）"
fi

echo "==> 安装 systemd 单元"
install -m 0644 "$SCRIPT_DIR/yuduan-hub.service" /etc/systemd/system/yuduan-hub.service
chown -R yuduan-hub:yuduan-hub /var/lib/yuduan-hub
systemctl daemon-reload

echo "==> 完成。后续手动步骤："
echo "    1. 编辑 /etc/yuduan-hub/env（至少配置 YUDUAN_DB_DSN 生产库）"
echo "    2. systemctl enable --now yuduan-hub"
echo "    3. 防火墙放行：TCP 18241（HTTP/WS）、UDP 18242（自动发现）；TLS 模式另加 TCP 8443"
echo "    4. 副端无需配置——同网段 UDP 广播自动发现；跨网段才设 YUDUAN_HUB"
echo "    5. 日志查看：journalctl -u yuduan-hub -f"
