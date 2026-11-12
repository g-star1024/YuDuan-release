#!/usr/bin/env bash
# 御端（YuDuan）客户自建公网部署 —— 证书准备脚本（Linux / macOS，v0.4.27）
#
# 定位（铁律 1 v1.2 / Gate G-2026-11-06-02）：官方不运营 / 不托管 / 不依赖任何
#   公网服务端、中继或代管域名；产品内置公网远控能力包（LAN/公网 开关、自绑域名、
#   ACME / 自传证书双轨、一键部署）。服务器、域名、DNS、证书、防火墙全部由客户自备并
#   自运维。本脚本只做一件事：用客户自己提供的域名/IP 生成 SAN，私有 CA 签发
#   服务器证书，导出 ca.pem，并打印 SPKI SHA-256 指纹供逐端固化。
#
# 与现有工具的关系：
#   - 复用中枢包内 yuduan-ca（dev/cmd/ca）的 init / issue-server / pin / check，
#     不重写证书逻辑、不改 dev/internal/tlsutil，也不改任何产品代码。
#   - 与 init-ca.sh 的区别：init-ca.sh 会自动写 hub.env（含 YUDUAN_CLIENT_CA、
#     YUDUAN_TLS_PIN），那是局域网 mTLS 口径；公网部署必须显式配置，故本脚本
#     **不写任何 env**，只打印可复制的配置清单。
#   - 产物对接 :8443：dev/cmd/hub/main.go 读 YUDUAN_TLS_CERT / YUDUAN_TLS_KEY，
#     ListenAndServeTLS 复用同一 h.Handler()；chain.pem 为 leaf+root 完整链。
#
# 用法（YOUR_DOMAIN / YOUR_IP 为占位符，请替换为客户的真实域名/IP；
#       脚本不内置任何固定域名、IP 或公网端点）：
#   sudo ./prepare-public-cert.sh -dns YOUR_DOMAIN
#   sudo ./prepare-public-cert.sh -dns YOUR_DOMAIN,YOUR_DOMAIN_2 -ip YOUR_IP
#   sudo ./prepare-public-cert.sh -ip YOUR_IP -dir /etc/yuduan-hub/tls -port 443
#   sudo ./prepare-public-cert.sh -dns YOUR_DOMAIN -rotate   # 轮换叶证书（需 ca.key 在场）
#
# 参数：
#   -dns  <列表>     客户 DNS 名称（逗号分隔），至少提供 -dns 或 -ip 之一
#   -ip   <列表>     客户 IP 地址（逗号分隔）
#   -dir  <绝对路径> 证书目录（Linux 默认 /etc/yuduan-hub/tls；macOS 默认
#                     /usr/local/etc/yuduan-hub/tls）
#   -org  <名>       根 CA 组织名（默认 YuDuan）
#   -port <端口>     仅用于生成示例地址，默认 8443；走 443 反代请显式 -port 443
#   -rotate          已存在根 CA 时，仅轮换服务器证书（issue-server）
#   -h|--help        显示本说明
#
# 产物（证书目录）：
#   ca.pem / ca.key        根 CA（ca.key 生成后立即移出中枢生产机离线保管）
#   cert.pem / key.pem     服务器证书（SAN 含 -dns/-ip）
#   chain.pem              完整链（leaf+root），YUDUAN_TLS_CERT 指向它
#
# 退出码：0 成功；2 参数错误；1 工具 / 产物异常。
#
# 说明：本脚本只生成证书与配置示例，不启动、不停止任何服务，不改变局域网默认
#   部署行为；不执行本章配置时，部署行为与 v0.4.24 局域网默认完全一致。

set -euo pipefail

DNS=""
IPS=""
DIR=""
ORG="YuDuan"
PORT="8443"
ROTATE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -dns)    DNS="${2:-}";  shift 2 ;;
    -ip)     IPS="${2:-}";  shift 2 ;;
    -dir)    DIR="${2:-}";  shift 2 ;;
    -org)    ORG="${2:-}";  shift 2 ;;
    -port)   PORT="${2:-}"; shift 2 ;;
    -rotate) ROTATE=true;   shift ;;
    -h|--help) awk '/^#!/{next} /^set -euo pipefail/{exit} /^#/{sub(/^# ?/, ""); print}' "$0"; exit 0 ;;
    *) echo "未知参数: $1（用 -h 查看用法）" >&2; exit 2 ;;
  esac
done

# —— 守卫 1：客户必须显式提供域名/IP，脚本没有任何内置地址 ——
if [[ -z "$DNS" && -z "$IPS" ]]; then
  echo "错误：必须显式提供 -dns <客户域名> 和/或 -ip <客户IP>。" >&2
  echo "      本脚本不内置任何固定域名、IP 或公网端点（Gate 决议）。" >&2
  exit 2
fi

# —— 守卫 2：示例地址端口只接受 1-65535 ——
if ! [[ "$PORT" =~ ^[0-9]{1,5}$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "错误：-port 必须是 1-65535 的整数（当前 '$PORT'）" >&2
  exit 2
fi

if [[ -z "$DIR" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    DIR="/usr/local/etc/yuduan-hub/tls"
  else
    DIR="/etc/yuduan-hub/tls"
  fi
fi
if [[ "$DIR" != /* ]]; then
  echo "错误：-dir 必须为绝对路径（当前 '$DIR'），避免相对路径随 cwd 漂移。" >&2
  exit 2
fi

# —— 取示例主机名：优先第一个 DNS，否则第一个 IP ——
HOST="$(printf '%s' "${DNS:-$IPS}" | cut -d, -f1 | tr -d '[:space:]')"
if [[ -z "$HOST" ]]; then
  echo "错误：无法从 -dns/-ip 解析出主机名" >&2
  exit 2
fi

# —— 定位 yuduan-ca：①脚本同目录 ②上级（hub 包根）③从 go module 根构建（开发场景）——
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_BIN=""
for cand in "${SCRIPT_DIR}/yuduan-ca" "${SCRIPT_DIR}/yuduan-ca.exe" \
            "$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd)/yuduan-ca"; do
  if [[ -x "$cand" ]]; then CA_BIN="$cand"; break; fi
done
if [[ -z "$CA_BIN" ]]; then
  MOD_ROOT=""
  d="$SCRIPT_DIR"
  while [[ "$d" != "/" && -n "$d" ]]; do
    if [[ -f "$d/go.mod" ]]; then MOD_ROOT="$d"; break; fi
    d="$(dirname "$d")"
  done
  if [[ -n "$MOD_ROOT" ]]; then
    echo "==> 构建 yuduan-ca（dev/cmd/ca，module: ${MOD_ROOT}）"
    (cd "$MOD_ROOT" && go build -o "${SCRIPT_DIR}/yuduan-ca" ./cmd/ca)
    CA_BIN="${SCRIPT_DIR}/yuduan-ca"
  fi
fi
if [[ -z "$CA_BIN" || ! -x "$CA_BIN" ]]; then
  echo "错误：未找到 yuduan-ca。请把中枢包内 yuduan-ca 与本脚本放同一目录，" >&2
  echo "      或在 go module 根下运行本脚本自动构建。" >&2
  exit 1
fi
echo "==> 使用 yuduan-ca：$CA_BIN"
echo "==> 证书目录：$DIR"
mkdir -p "$DIR"

ARGS=(-dir "$DIR")
[[ -n "$DNS" ]] && ARGS+=(-dns "$DNS")
[[ -n "$IPS" ]] && ARGS+=(-ip "$IPS")

if [[ -f "$DIR/ca.pem" ]]; then
  if [[ "$ROTATE" != true ]]; then
    echo "错误：$DIR/ca.pem 已存在。为避免误覆盖根 CA，轮换叶证书请显式加 -rotate。" >&2
    exit 2
  fi
  if [[ ! -f "$DIR/ca.key" ]]; then
    echo "错误：-rotate 需要根 CA 私钥 $DIR/ca.key；请从离线保管处临时取回，轮换后立即移出。" >&2
    exit 1
  fi
  echo "==> 复用既有根 CA，轮换服务器证书（issue-server）"
  "$CA_BIN" issue-server "${ARGS[@]}"
else
  if [[ "$ROTATE" == true ]]; then
    echo "错误：-rotate 要求已存在 $DIR/ca.pem，当前不存在。首次签发请去掉 -rotate。" >&2
    exit 2
  fi
  echo "==> 生成根 CA + 签发服务器证书（SAN: dns='${DNS:-（未指定）}' ip='${IPS:-（未指定）}'）"
  "$CA_BIN" init -org "$ORG" "${ARGS[@]}"
fi

# —— 校验产物完整性 ——
for f in ca.pem cert.pem key.pem chain.pem; do
  if [[ ! -s "$DIR/$f" ]]; then
    echo "错误：缺少产物 $DIR/$f" >&2
    exit 1
  fi
done

PIN="$("$CA_BIN" pin -cert "$DIR/cert.pem")"
if ! [[ "$PIN" =~ ^[0-9a-f]{64}$ ]]; then
  echo "错误：SPKI SHA-256 指纹输出异常：'$PIN'" >&2
  exit 1
fi

echo ""
echo "=============================================================="
echo " 证书准备完成（客户自备域名/IP，产品不托管任何公网服务）"
echo "=============================================================="
echo " 根 CA 公钥      : $DIR/ca.pem        <- 带外分发到主端/副端"
echo " 根 CA 私钥      : $DIR/ca.key        <- 立即移出中枢生产机，离线保管"
echo " 服务器证书      : $DIR/cert.pem"
echo " 服务器私钥      : $DIR/key.pem"
echo " 完整链          : $DIR/chain.pem     <- YUDUAN_TLS_CERT 指向它"
echo " SPKI SHA-256    : $PIN"
echo ""
echo "── 中枢 env（请自行写入，本脚本不写 env）──────────────────────"
echo " YUDUAN_TLS_ADDR=:8443"
echo " YUDUAN_TLS_CERT=$DIR/chain.pem"
echo " YUDUAN_TLS_KEY=$DIR/key.pem"
echo " YUDUAN_PUBLIC_ADDR=https://${HOST}:${PORT}"
echo " YUDUAN_LOGIN_GUARD=1"
echo ""
echo "── 主端 / 副端（端口必须写全）────────────────────────────────"
echo " 主端登录页      : https://${HOST}:${PORT}"
echo " 副端            : YUDUAN_HUB=wss://${HOST}:${PORT}/ws/agent"
echo " 副端信任锚      : YUDUAN_TLS_CAFILE=<带外预置的 ca.pem 路径>"
echo "                   或 YUDUAN_TLS_PIN=$PIN"
echo "                   （两者同时配置时为 AND 叠加，链校验与指纹均需通过）"
echo ""
echo "── 说明 ──────────────────────────────────────────────────────"
echo " * 主端对 https 省略端口时默认连 443，而中枢 TLS 默认 8443；"
echo "   若走 443 反向代理，请用 -port 443 重跑示例，并保证两边一致。"
echo " * YUDUAN_PUBLIC_ADDR 是事实必配项（非可选）：不设会兜底成明文监听串"
echo "   （如 :8080）、且只补 http:// 不补 https://，软件分发 URL 拼成 http://:8080/..."
echo "   或回环地址，副端 https 下载必然失败；必须写含 scheme 的完整 https 地址。"
echo " * 公网禁用一次性自签证书（其 SAN 固定 localhost/127.0.0.1/::1）。"
echo " * ca.pem / PIN 必须带外预置：claim 响应里的 caPem 不能作为本次校验信任锚。"
echo " * 不设 YUDUAN_CLIENT_CA：mTLS 是独立的 :8444 端口，公网只开 :8443。"
echo " * 不改 YUDUAN_HUB_ADDR：靠客户防火墙阻断公网 8080 / 18242 即可（18242 为默认发现端口，可由 YUDUAN_DISCOVERY_PORT 覆盖；公网形态请一并阻断该端口）。"
echo " * 显式 YUDUAN_TLS_CERT 会跳过中枢的证书到期告警，须挂 cron："
echo "     $CA_BIN check -dir $DIR        # <30 天退出码 1"
echo " * SNI 只设 -servername，不等于主机名校验；本轮严格校验只来自"
echo "   显式 CAFILE/PIN 下追加的 -CAfile + -verify_return_error。"
echo "=============================================================="

# 到期自检（新签证书 1 年有效，正常应通过；失败给出告警而非吞掉输出）
if ! "$CA_BIN" check -dir "$DIR"; then
  echo "警告：ca check 未通过，请检查 $DIR 下证书有效期。" >&2
fi
