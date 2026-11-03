#!/usr/bin/env bash
# 御端（YuDuan）内网根 CA 初始化 —— 一键建立内网信任锚并配置中枢 TLS/mTLS。
#
# 背景（§5 安全基座 / 铁律 4）：默认中枢用一次性自签证书（无信任锚）；生产纳管应
# 建立内网根 CA，用它签发中枢服务器证书（TLS/mTLS）+ 副端 mTLS 客户端证书，
# 副端经严格链校验或公钥固定接入。
#
# 用法：
#   sudo ./init-ca.sh                          # 默认 certs/，自动构建 yuduan-ca
#   sudo ./init-ca.sh -dns h1.example.com,10.0.0.5 -ip 10.0.0.5
#   sudo ./init-ca.sh -dir /etc/yuduan-hub/tls
#
# 参数：
#   -dir <目录>   证书目录（默认 certs/，建议 /etc/yuduan-hub/tls）
#   -dns <列表>   服务器证书附加 DNS SAN（逗号分隔，含中枢主机名）
#   -ip  <列表>   服务器证书附加 IP SAN（逗号分隔，含中枢 IP）
#   -org <名>     组织名（默认 YuDuan）
#   -no-config    不写中枢 env 配置（仅生成证书，配置手动做）
#
# 产物（证书目录下）：
#   ca.pem/ca.key        根 CA（ca.key 离线保管，生成后移出中枢生产机！）
#   cert.pem/key.pem     中枢服务器证书（含 SAN）
#   client-<id>.pem/.key 副端 mTLS 客户端证书（issue-client 逐个签发）
#
# 副端接入（分发 ca.pem 后任选其一）：
#   严格链校验：YUDUAN_TLS_CAFILE=/path/ca.pem
#   公钥固定（推荐）：YUDUAN_TLS_PIN=$(yuduan-ca pin -cert cert.pem)

set -euo pipefail

DIR="certs"
DNS=""
IPS=""
ORG="YuDuan"
NO_CONFIG=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -dir) DIR="$2"; shift 2 ;;
    -dns) DNS="$2"; shift 2 ;;
    -ip)  IPS="$2"; shift 2 ;;
    -org) ORG="$2"; shift 2 ;;
    -no-config) NO_CONFIG=true; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 && "$DIR" != "certs" ]]; then
  echo "提示：目标目录 $DIR 需写入权限（非 root 请加 sudo）" >&2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# 查找 yuduan-ca：①脚本同目录 ②脚本上级（hub 包根）③从 go module 根构建（开发场景）
CA_BIN=""
for cand in "${SCRIPT_DIR}/yuduan-ca" "$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd)/yuduan-ca"; do
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
  echo "错误：未找到 yuduan-ca（将预构建二进制与脚本同目录放置，或在 go module 下运行本脚本自动构建）" >&2
  exit 1
fi
echo "==> 使用 yuduan-ca：$CA_BIN"

echo "==> 证书目录：$DIR"
mkdir -p "$DIR"

if [[ -f "$DIR/ca.pem" ]]; then
  echo "==> 检测到既有根 CA（$DIR/ca.pem），跳过 init"
else
  echo "==> 生成根 CA + 服务器证书（SAN: dns='${DNS:-（自动）}' ip='${IPS:-（自动）}'）"
  ARGS=(-dir "$DIR" -org "$ORG")
  [[ -n "$DNS" ]] && ARGS+=(-dns "$DNS")
  [[ -n "$IPS" ]] && ARGS+=(-ip "$IPS")
  "$CA_BIN" init "${ARGS[@]}"
fi

echo "==> 证书概览："
ls -la "$DIR"/*.pem "$DIR"/*.key 2>/dev/null || true

echo "==> 服务器证书 SPKI 指纹（YUDUAN_TLS_PIN，副端公钥固定用）："
"$CA_BIN" pin -cert "$DIR/cert.pem" || echo "  （pin 失败，可跳过）"

# 中枢 YUDUAN_TLS_CERT 优先指向完整链（chain.pem 含根锚，pin 模式校验用）；无 chain 则单证书。
CERT_FILE="$DIR/cert.pem"
if [[ -f "$DIR/chain.pem" ]]; then CERT_FILE="$DIR/chain.pem"; fi

if [[ "$NO_CONFIG" == true ]]; then
  echo "==> -no-config：仅生成证书，未写中枢 env。手动配置："
  echo "    YUDUAN_TLS_ADDR=:8443"
  echo "    YUDUAN_TLS_CERT=$CERT_FILE"
  echo "    YUDUAN_TLS_KEY=$DIR/key.pem"
  echo "    YUDUAN_CLIENT_CA=$DIR/ca.pem   # mTLS（副端需客户端证书）"
  echo "    YUDUAN_TLS_PIN=<上方指纹>"
  echo "    改完 sudo systemctl restart yuduan-hub"
  exit 0
fi

# 尝试写入中枢 env（Linux /etc/yuduan-hub/env）
ENV_FILE=""
for cand in /etc/yuduan-hub/env /usr/local/etc/yuduan-hub/env; do
  if [[ -f "$cand" ]]; then ENV_FILE="$cand"; break; fi
done
if [[ -z "$ENV_FILE" && -w /etc/yuduan-hub ]]; then ENV_FILE=/etc/yuduan-hub/env; fi

if [[ -n "$ENV_FILE" ]]; then
  echo "==> 写入中枢 env：$ENV_FILE"
  PIN=$("$CA_BIN" pin -cert "$DIR/cert.pem")
  upsert() { # upsert KEY VALUE
    local k="$1" v="$2"
    if grep -q "^${k}=" "$ENV_FILE"; then
      sed -i "s|^${k}=.*|${k}=${v}|" "$ENV_FILE"
    else
      echo "${k}=${v}" >> "$ENV_FILE"
    fi
  }
  upsert YUDUAN_TLS_ADDR ":8443"
  upsert YUDUAN_TLS_CERT "$CERT_FILE"
  upsert YUDUAN_TLS_KEY "$DIR/key.pem"
  upsert YUDUAN_CLIENT_CA "$DIR/ca.pem"
  upsert YUDUAN_TLS_PIN "$PIN"
  echo "    已配置 TLS/mTLS（YUDUAN_TLS_ADDR=:8443 + 服务器证书 + client CA + PIN）"
  echo "    生效：sudo systemctl restart yuduan-hub"
else
  echo "==> 未找到中枢 env（/etc/yuduan-hub/env），请手动在 env 配置："
  echo "    YUDUAN_TLS_ADDR=:8443 / YUDUAN_TLS_CERT=$CERT_FILE / YUDUAN_TLS_KEY=$DIR/key.pem"
  echo "    YUDUAN_CLIENT_CA=$DIR/ca.pem / YUDUAN_TLS_PIN=<上方指纹>"
fi

echo ""
echo "==> 副端接入（分发 $DIR/ca.pem 到副端，任选其一）："
echo "    ① 严格链校验：YUDUAN_TLS_CAFILE=$DIR/ca.pem"
echo "    ② 公钥固定（推荐）：YUDUAN_TLS_PIN=<上方指纹>"
echo ""
echo "⚠️  安全：ca.key（根 CA 私钥）生成后请立即移出中枢生产机离线保管；"
echo "    轮换服务器证书：yuduan-ca issue-server -dir $DIR -dns ... -ip ..."
echo "    到期检查（cron 建议）：yuduan-ca check -dir $DIR"
