#!/usr/bin/env bash
# 御端中枢 macOS 安装脚本（launchd 常驻，LaunchDaemon 开机自启）
# 用法：sudo ./install-macos.sh [yuduan-hub 二进制路径]
# 布局：
#   /usr/local/bin/yuduan-hub            二进制
#   /usr/local/etc/yuduan-hub/env        配置（首次安装生成，升级不覆盖）
#   /Library/LaunchDaemons/io.yuduan.hub.plist
#   /usr/local/var/yuduan-hub            数据与软件仓库目录
set -euo pipefail

BIN_SRC="${1:-yuduan-hub}"
[[ -x "$BIN_SRC" ]] || { echo "错误：找不到可执行文件 $BIN_SRC"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "请用 sudo 运行"; exit 1; }

echo "==> 创建目录"
mkdir -p /usr/local/bin /usr/local/etc/yuduan-hub /usr/local/var/yuduan-hub/repo

echo "==> 安装二进制"
install -m 0755 "$BIN_SRC" /usr/local/bin/yuduan-hub

ENV_FILE=/usr/local/etc/yuduan-hub/env
if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0644 "$SCRIPT_DIR/env.example" "$ENV_FILE"
  hmac=$(openssl rand -hex 32); pepper=$(openssl rand -hex 32)
  sed -i '' "s|^YUDUAN_HMAC_SECRET=$|YUDUAN_HMAC_SECRET=$hmac|" "$ENV_FILE"
  sed -i '' "s|^YUDUAN_PEPPER=$|YUDUAN_PEPPER=$pepper|" "$ENV_FILE"
  echo "    已自动生成 YUDUAN_HMAC_SECRET 与 YUDUAN_PEPPER（副端侧需同步 HMAC 密钥）"
else
  echo "    $ENV_FILE 已存在，保留（升级不覆盖配置）"
fi

echo "==> 生成 launchd plist（把 env 文件展开为 EnvironmentVariables）"
PLIST=/Library/LaunchDaemons/io.yuduan.hub.plist
{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
  echo '<plist version="1.0"><dict>'
  echo '  <key>Label</key><string>io.yuduan.hub</string>'
  echo '  <key>ProgramArguments</key><array>'
  echo '    <string>/usr/local/bin/yuduan-hub</string>'
  echo '  </array>'
  echo '  <key>WorkingDirectory</key><string>/usr/local/var/yuduan-hub</string>'
  echo '  <key>EnvironmentVariables</key><dict>'
  # 只注入非注释、非空的 KEY=VALUE
  grep -Ev '^\s*(#|$)' "$ENV_FILE" | while IFS='=' read -r k v; do
    [[ -n "$k" && -n "$v" ]] && printf '    <key>%s</key><string>%s</string>\n' "$k" "$v"
  done
  echo '  </dict>'
  echo '  <key>RunAtLoad</key><true/>'
  echo '  <key>KeepAlive</key><true/>'
  echo '  <key>StandardOutPath</key><string>/usr/local/var/yuduan-hub/hub.log</string>'
  echo '  <key>StandardErrorPath</key><string>/usr/local/var/yuduan-hub/hub.log</string>'
  echo '  <key>Nice</key><integer>0</integer>'
  echo '</dict></plist>'
} > "$PLIST"
launchctl bootout system/io.yuduan.hub 2>/dev/null || true

echo "==> 完成。后续手动步骤："
echo "    1. 编辑 $ENV_FILE（生产至少配 YUDUAN_DB_DSN），改完重装本脚本刷新 plist"
echo "    2. sudo launchctl bootstrap system $PLIST"
echo "    3. 日志：tail -f /usr/local/var/yuduan-hub/hub.log"
echo "    4. 防火墙：系统设置允许传入连接；UDP 18242 自动发现勿拦"
echo "    5. 卸载：launchctl bootout system/io.yuduan.hub && rm $PLIST"
