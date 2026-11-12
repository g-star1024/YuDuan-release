#!/usr/bin/env bash
# 御端中枢 macOS 安装脚本（launchd 常驻，LaunchDaemon 开机自启）
# 用法：sudo ./install-macos.sh [yuduan-hub 二进制路径]
# 布局：
#   /usr/local/bin/yuduan-hub            二进制
#   /usr/local/etc/yuduan-hub/env        配置（首次安装生成，升级不覆盖）
#   /Library/LaunchDaemons/io.yuduan.hub.plist
#   /usr/local/var/yuduan-hub            数据与软件仓库目录
set -euo pipefail

# v0.4.29：公网部署参数（--public --domain --email --cert-mode --staging）
PUBLIC=false
DOMAIN=""
EMAIL=""
CERT_MODE="self"
STAGING=false
MEMORY=false
UPGRADING=false
BIN_SRC=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --public)    PUBLIC=true; shift ;;
    --domain)    DOMAIN="${2:-}"; shift 2 ;;
    --email)     EMAIL="${2:-}"; shift 2 ;;
    --cert-mode) CERT_MODE="${2:-}"; shift 2 ;;
    --staging)   STAGING=true; shift ;;
    --memory)    MEMORY=true; shift ;;
    *)           BIN_SRC="$1"; shift ;;
  esac
done
# 未知位置参数落入 BIN_SRC，保留原「$1 作二进制路径」的兼容语义
BIN_SRC="${BIN_SRC:-yuduan-hub}"
[[ -x "$BIN_SRC" ]] || { echo "错误：找不到可执行文件 $BIN_SRC"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# v0.4.29：公网参数校验
if $PUBLIC; then
  [[ -n "$DOMAIN" ]] || { echo "错误：--public 需要 --domain <FQDN>"; exit 2; }
  [[ -n "$EMAIL" ]]  || { echo "错误：--public 需要 --email <email>"; exit 2; }
  [[ "$CERT_MODE" == "acme" || "$CERT_MODE" == "self" ]] || { echo "错误：--cert-mode 必须是 acme|self（当前 '$CERT_MODE'）"; exit 2; }
fi

[[ $EUID -eq 0 ]] || { echo "请用 sudo 运行"; exit 1; }

echo "==> 创建目录"
mkdir -p /usr/local/bin /usr/local/etc/yuduan-hub /usr/local/var/yuduan-hub/repo /usr/local/var/log

echo "==> 检测升级：停旧进程（D-02）"
if launchctl print system/io.yuduan.hub &>/dev/null; then
  UPGRADING=true
  launchctl bootout system/io.yuduan.hub 2>/dev/null || true
  echo "    检测到运行中的服务，已停止旧进程（升级替换）"
fi

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
# D-06 日志：统一落盘路径（幂等追加，不重复）
LOG_FILE=/usr/local/var/log/yuduan-hub.log
if ! grep -q '^YUDUAN_LOG_FILE=' "$ENV_FILE"; then
  echo "YUDUAN_LOG_FILE=$LOG_FILE" >> "$ENV_FILE"
  echo "    已配置 YUDUAN_LOG_FILE=$LOG_FILE"
fi

# v0.4.29（F-07）：发现端口从 env 读取，缺省 18242；plist 的 EnvironmentVariables 展开天然注入该键
DISC_PORT="$(sed -n 's/^YUDUAN_DISCOVERY_PORT=//p' "$ENV_FILE" 2>/dev/null | head -1 | tr -d '[:space:]')"
DISC_PORT="${DISC_PORT:-18242}"

# =====================================================================
# 公网部署模式（v0.4.29）：launchd plist 是 env 的【静态快照】（下方 plist 生成段一次性
# 展开为 EnvironmentVariables），不是 systemd 的运行时 EnvironmentFile。证书准备 + 7 项 env
# 必须在【生成 plist 之前】完成，让展开时天然含公网变量，一次 bootstrap 即起公网服务，
# 无需二次 bootout/bootstrap；照搬 Linux「末尾写 env + restart」会静默按 LAN 启动。
# 未传 --public 时本段整体跳过，LAN 零回归（不建 certs / 不调外部脚本 / 不写 7 项 env）。
# =====================================================================
if $PUBLIC; then
  CERT_DIR=/usr/local/etc/yuduan-hub/certs
  mkdir -p "$CERT_DIR"

  # 幂等 upsert KEY=VALUE（存在则替换，不存在则追加）；唯一差异：sed 必须 BSD `sed -i ''`（参照 env 生成处的写法）
  upsert_env() {
    local key="$1" val="$2" file="$3"
    if grep -q "^${key}=" "$file" 2>/dev/null; then
      sed -i '' "s|^${key}=.*|${key}=${val}|" "$file"
    else
      echo "${key}=${val}" >> "$file"
    fi
  }

  # 防火墙：macOS 无 ufw / firewall-cmd，只打印人工指引、不阻断部署
  echo "==> [公网] 防火墙（macOS 无 ufw/firewall-cmd，仅打印人工指引、不阻断）"
  echo "    请在「系统设置 → 网络 → 防火墙」人工放行 TCP 8443；ACME 模式另需临时放行 TCP 80（HTTP-01，签发后关闭）"

  pin=""
  if [[ "$CERT_MODE" == "acme" ]]; then
    # HTTP-01 需 :80 空闲：占用预检，失败给明确提示（含 yuduan-acme -listen 逃生口），不阻断
    if lsof -nP -iTCP:80 -sTCP:LISTEN >/dev/null 2>&1; then
      echo "    ⚠️ 检测到 TCP 80 已被占用，ACME HTTP-01 挑战可能失败：请停止占用程序，"
      echo "       或用 yuduan-acme -listen 指定其它监听口并自行转发后再试（本脚本不自动改口）。"
    fi
    acme_exe=""
    for c in "${SCRIPT_DIR}/yuduan-acme" yuduan-acme; do
      if command -v "$c" >/dev/null 2>&1 || [[ -x "$c" ]]; then acme_exe="$c"; break; fi
    done
    [[ -n "$acme_exe" ]] || { echo "错误：未找到 yuduan-acme（请置于中枢目录或纳入 PATH）"; exit 1; }
    acme_args=(issue --domain "$DOMAIN" --email "$EMAIL")
    if $STAGING; then acme_args+=(--staging); fi
    acme_out="$($acme_exe "${acme_args[@]}" 2>&1)"
    echo "$acme_out"
    pin="$(echo "$acme_out" | grep -iE 'pin|spki|sha-?256' | grep -oE '[0-9a-f]{64}' | head -1)"
    cert_path="$CERT_DIR/acme.fullchain.pem"
    key_path="$CERT_DIR/acme.key"
  else
    # self：复用现有 prepare-public-cert.sh（私有 CA 签发）
    pub_sh="${SCRIPT_DIR}/prepare-public-cert.sh"
    pub_out=""
    if [[ -f "$pub_sh" ]]; then
      pub_out="$(bash "$pub_sh" -dns "$DOMAIN" -dir "$CERT_DIR" 2>&1)"
    elif command -v prepare-public-cert.sh >/dev/null 2>&1; then
      pub_out="$(prepare-public-cert.sh -dns "$DOMAIN" -dir "$CERT_DIR" 2>&1)"
    else
      echo "错误：未找到 prepare-public-cert.sh（请随包提供）"; exit 1
    fi
    echo "$pub_out"
    pin="$(echo "$pub_out" | grep -iE 'pin|spki|sha-?256' | grep -oE '[0-9a-f]{64}' | head -1)"
    cert_path="$CERT_DIR/chain.pem"
    key_path="$CERT_DIR/key.pem"
  fi

  # 校验产物
  [[ -s "$cert_path" ]] || { echo "错误：证书产物缺失或为空：$cert_path"; exit 1; }
  [[ -s "$key_path" ]]  || { echo "错误：证书私钥产物缺失或为空：$key_path"; exit 1; }

  # 写公网 env（幂等 upsert）——必须在 plist 生成之前，让 EnvironmentVariables 展开含 7 项
  echo "==> [公网] 写入公网配置到 ${ENV_FILE}（plist 生成前）"
  upsert_env YUDUAN_NET_MODE public "$ENV_FILE"
  upsert_env YUDUAN_TLS_ADDR :8443 "$ENV_FILE"
  upsert_env YUDUAN_TLS_CERT "$cert_path" "$ENV_FILE"
  upsert_env YUDUAN_TLS_KEY "$key_path" "$ENV_FILE"
  upsert_env YUDUAN_PUBLIC_ADDR "https://${DOMAIN}:8443" "$ENV_FILE"
  upsert_env YUDUAN_PUBLIC_DOMAIN "$DOMAIN" "$ENV_FILE"
  upsert_env YUDUAN_LOGIN_GUARD 1 "$ENV_FILE"
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
  printf '  <key>StandardOutPath</key><string>%s</string>\n' "$LOG_FILE"
  printf '  <key>StandardErrorPath</key><string>%s</string>\n' "$LOG_FILE"
  echo '  <key>Nice</key><integer>0</integer>'
  echo '</dict></plist>'
} > "$PLIST"
# 幂等 bootout（升级检测已停；此处对当前 plist 再停一次，防止重复加载）
launchctl bootout system/io.yuduan.hub 2>/dev/null || true

# v0.4.30：PG 持久化默认失败即中止（防静默内存模式丢数据；--memory 显式逃生舱）。
# 升级存量内存实例（UPGRADING 且未配 DSN）仅告警放行，避免误伤；其余无 DSN 且未显式
# --memory 即中止部署，强制运维配置 YUDUAN_DB_DSN 或显式选内存模式。
if ! grep -qE '^YUDUAN_DB_DSN=.+$' "$ENV_FILE" 2>/dev/null; then
  if $MEMORY || $UPGRADING; then
    echo "    ⚠️ 将以【内存存储】运行（重启即丢，仅供测试）"
  else
    echo "    ❌ 未配置 YUDUAN_DB_DSN 且未显式 --memory：中止部署（防止静默内存模式丢数据）。" >&2
    echo "        生产必须配置 PostgreSQL：编辑 $ENV_FILE 设 YUDUAN_DB_DSN 后重跑；或加 --memory 仅测试。" >&2
    exit 1
  fi
fi

echo "==> 启动服务（D-01 装完即启动）"
launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl load "$PLIST" 2>/dev/null || true
if launchctl print system/io.yuduan.hub &>/dev/null; then
  echo "    服务已加载（launchd 常驻，开机自启）"
else
  echo "    ⚠️ 服务加载失败，请排查：tail -n 50 $LOG_FILE"
fi

echo "==> 完成。"
echo "    配置：$ENV_FILE（生产至少配 YUDUAN_DB_DSN），改完重装本脚本刷新 plist"
echo "    日志：tail -f $LOG_FILE"
echo "    防火墙：系统设置允许传入连接；UDP ${DISC_PORT} 自动发现勿拦"
echo "    卸载：launchctl bootout system/io.yuduan.hub && rm $PLIST"

# =====================================================================
# 公网端点打印（install.sh L187-200 同款）：放在完成提示之后；PUBLIC=false 时整体跳过。
# =====================================================================
if $PUBLIC; then
  echo ""
  echo "=============================================================="
  echo " 公网部署完成（net mode = public）"
  echo "=============================================================="
  echo " 副端联动（在副端环境 / install-agent 时设置其一）："
  echo "   YUDUAN_HUB=wss://${DOMAIN}:8443/ws/agent"
  if [[ "$CERT_MODE" == "self" ]]; then
    echo "   YUDUAN_TLS_CAFILE=${CERT_DIR}/ca.pem   <- 带外预置（私有 CA 根）"
    [[ -n "$pin" ]] && echo "   YUDUAN_TLS_PIN=$pin"
  else
    echo "   （ACME 受信任证书：副端无需 PIN/CAFILE，信任系统根即可）"
  fi
  echo " 主端登录页： https://${DOMAIN}:8443"
  echo "=============================================================="
fi
