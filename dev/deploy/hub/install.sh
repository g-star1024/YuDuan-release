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

echo "==> 检测升级：停旧进程（D-02）"
UPGRADING=false
if systemctl is-active --quiet yuduan-hub 2>/dev/null; then
  UPGRADING=true
  systemctl stop yuduan-hub
  echo "    检测到运行中的服务，已停止旧进程（升级替换）"
fi

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

echo "==> 配置日志落盘（D-06）"
mkdir -p /var/log/yuduan-hub
chown yuduan-hub:yuduan-hub /var/log/yuduan-hub
if ! grep -q '^YUDUAN_LOG_FILE=' /etc/yuduan-hub/env; then
  echo 'YUDUAN_LOG_FILE=/var/log/yuduan-hub/hub.log' >> /etc/yuduan-hub/env
  echo "    已配置 YUDUAN_LOG_FILE=/var/log/yuduan-hub/hub.log"
fi

echo "==> 启动服务（D-01 装完即启动）"
systemctl enable --now yuduan-hub
if systemctl is-active --quiet yuduan-hub; then
  echo "    服务已启动并设为开机自启（active）"
else
  echo "    ⚠️ 服务启动失败，请排查：journalctl -u yuduan-hub -n 50"
fi

echo "==> 完成。"
echo "    配置：/etc/yuduan-hub/env"
echo "    日志：/var/log/yuduan-hub/hub.log 或 journalctl -u yuduan-hub -f"
echo "    防火墙放行：TCP 8080（HTTP/WS）、UDP 18242（自动发现）；TLS 模式另加 TCP 8443"
echo "    副端无需配置——同网段 UDP 广播自动发现；跨网段才设 YUDUAN_HUB"

# 生产必配 PostgreSQL 持久化（默认内存，重启即丢）
if grep -qE '^YUDUAN_DB_DSN=.+$' /etc/yuduan-hub/env 2>/dev/null; then
  echo "    ✅ 已配置 PostgreSQL 持久化（YUDUAN_DB_DSN）"
else
  echo "    ⚠️ 未配置 YUDUAN_DB_DSN —— 当前为【内存存储，重启即丢】！生产必须配置 PostgreSQL："
  if command -v psql >/dev/null 2>&1; then
    echo "        1) 建库建用户：sudo -u postgres createuser yuduan -P && sudo -u postgres createdb -O yuduan yuduan"
    echo "        2) 编辑 /etc/yuduan-hub/env 取消注释并改 YUDUAN_DB_DSN（URL 或键值格式均可）"
    echo "        3) sudo systemctl restart yuduan-hub"
  else
    echo "        1) 在任一 PostgreSQL 实例建库建用户（见 README-deploy.md「PostgreSQL 持久化」）"
    echo "        2) 编辑 /etc/yuduan-hub/env 配置 YUDUAN_DB_DSN"
    echo "        3) sudo systemctl restart yuduan-hub"
  fi
fi
