#!/usr/bin/env bash
# 御端中枢一键安装脚本（Linux，systemd 环境）
# 用法：sudo ./install.sh [yuduan-hub 二进制路径]
# 产物布局：
#   /usr/local/bin/yuduan-hub          二进制
#   /etc/yuduan-hub/env                配置（首次安装生成，升级不覆盖）
#   /etc/systemd/system/yuduan-hub.service
#   /var/lib/yuduan-hub                数据与软件仓库目录
set -euo pipefail

# v0.4.27：公网部署参数（--public --domain --email --cert-mode --staging）
PUBLIC=false
DOMAIN=""
EMAIL=""
CERT_MODE="self"
STAGING=false
MEMORY=false
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
BIN_SRC="${BIN_SRC:-yuduan-hub}"
[[ -x "$BIN_SRC" ]] || { echo "错误：找不到可执行文件 $BIN_SRC"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# v0.4.27：公网参数校验
if $PUBLIC; then
  [[ -n "$DOMAIN" ]] || { echo "错误：--public 需要 --domain <FQDN>"; exit 2; }
  [[ -n "$EMAIL" ]]  || { echo "错误：--public 需要 --email <email>"; exit 2; }
  [[ "$CERT_MODE" == "acme" || "$CERT_MODE" == "self" ]] || { echo "错误：--cert-mode 必须是 acme|self（当前 '$CERT_MODE'）"; exit 2; }
fi

# v0.4.27：防火墙助手（ufw 优先，其次 firewall-cmd，否则打印人工指引且不阻断部署）
open_fw() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${port}/tcp" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  else
    echo "    请手动放行 TCP ${port}（未检出 ufw / firewall-cmd）"
  fi
}
close_fw() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  else
    echo "    请手动关闭临时 TCP ${port}（未检出 ufw / firewall-cmd）"
  fi
}

# v0.4.29（F-07）：UDP 发现端口放行（LAN 自动发现）。此前 open_fw/close_fw 只处理 /tcp，
# Linux LAN 部署从未实际放行 UDP 发现端口（默认 18242），此处补齐；两者都不存在时只打印人工指引、不阻断部署。
open_fw_udp() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${port}/udp" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  else
    echo "    请手动放行 UDP ${port}（未检出 ufw / firewall-cmd）"
  fi
}

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

# v0.4.29（F-07）：发现端口从 env 读取，缺省 18242（存量 env 无该键即回退默认，零回归）。
# sed 无匹配输出空串、返回 0，配合 :- 回退；避免 grep 无匹配在 pipefail 下触发 set -e。
DISC_PORT="$(sed -n 's/^YUDUAN_DISCOVERY_PORT=//p' /etc/yuduan-hub/env 2>/dev/null | head -1 | tr -d '[:space:]')"
DISC_PORT="${DISC_PORT:-18242}"

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

# v0.4.30：PG 持久化默认失败即中止（防静默内存模式丢数据；--memory 显式逃生舱）。
# 升级存量内存实例（UPGRADING 且未配 DSN）仅告警放行，避免误伤；其余无 DSN 且未显式
# --memory 即中止部署，强制运维配置 YUDUAN_DB_DSN 或显式选内存模式。
if ! grep -qE '^YUDUAN_DB_DSN=.+$' /etc/yuduan-hub/env 2>/dev/null; then
  if $MEMORY || $UPGRADING; then
    echo "    ⚠️ 将以【内存存储】运行（重启即丢，仅供测试）"
  else
    echo "    ❌ 未配置 YUDUAN_DB_DSN 且未显式 --memory：中止部署（防止静默内存模式丢数据）。" >&2
    echo "        生产必须配置 PostgreSQL：编辑 /etc/yuduan-hub/env 设 YUDUAN_DB_DSN 后重跑；或加 --memory 仅测试。" >&2
    exit 1
  fi
fi

echo "==> 启动服务（D-01 装完即启动）"
systemctl enable --now yuduan-hub
if systemctl is-active --quiet yuduan-hub; then
  echo "    服务已启动并设为开机自启（active）"
else
  echo "    ⚠️ 服务启动失败，请排查：journalctl -u yuduan-hub -n 50"
fi

# v0.4.29（F-07）：LAN 基础部署放行 UDP 发现端口（默认 18242，可由 YUDUAN_DISCOVERY_PORT 覆盖）。
echo "==> 放行 UDP 发现端口 ${DISC_PORT}（LAN 自动发现）"
open_fw_udp "$DISC_PORT"

# =====================================================================
# 公网部署模式（v0.4.27）：在基础 LAN 部署完成之上，额外完成证书准备 +
# 写公网 env + 防火墙 8443（+ ACME 临时 80）+ 重启服务 + 打印副端端点。
# 未传 --public 时本段整体跳过。
# =====================================================================
if $PUBLIC; then
  CERT_DIR=/etc/yuduan-hub/certs
  mkdir -p "$CERT_DIR"

  # 幂等 upsert KEY=VALUE（存在则替换，不存在则追加）；不改动既有 HMAC/PEPPER/SIGN_SEED/DB_DSN
  upsert_env() {
    local key="$1" val="$2" file="$3"
    if grep -q "^${key}=" "$file" 2>/dev/null; then
      sed -i "s|^${key}=.*|${key}=${val}|" "$file"
    else
      echo "${key}=${val}" >> "$file"
    fi
  }

  pin=""
  if [[ "$CERT_MODE" == "acme" ]]; then
    # 临时放行 :80 供 http-01 挑战，签发后立即撤销
    open_fw 80
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
    close_fw 80
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

  # 写公网 env（幂等 upsert）
  echo "==> [公网] 写入公网配置到 /etc/yuduan-hub/env"
  upsert_env YUDUAN_NET_MODE public /etc/yuduan-hub/env
  upsert_env YUDUAN_TLS_ADDR :8443 /etc/yuduan-hub/env
  upsert_env YUDUAN_TLS_CERT "$cert_path" /etc/yuduan-hub/env
  upsert_env YUDUAN_TLS_KEY "$key_path" /etc/yuduan-hub/env
  upsert_env YUDUAN_PUBLIC_ADDR "https://${DOMAIN}:8443" /etc/yuduan-hub/env
  upsert_env YUDUAN_PUBLIC_DOMAIN "$DOMAIN" /etc/yuduan-hub/env
  upsert_env YUDUAN_LOGIN_GUARD 1 /etc/yuduan-hub/env

  # 防火墙：确保 8443 放行（ACME 临时 80 已撤销）
  open_fw 8443

  # 重启服务使新 env 生效
  systemctl restart yuduan-hub || true

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

echo "==> 完成。"
echo "    配置：/etc/yuduan-hub/env"
echo "    日志：/var/log/yuduan-hub/hub.log 或 journalctl -u yuduan-hub -f"
echo "    防火墙放行：TCP 8080（HTTP/WS）、UDP ${DISC_PORT}（自动发现，默认 18242 可配置）；TLS 模式另加 TCP 8443"
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
