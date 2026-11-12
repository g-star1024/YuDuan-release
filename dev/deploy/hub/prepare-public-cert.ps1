<#
  御端（YuDuan）客户自建公网部署 —— 证书准备脚本（Windows / PowerShell，v0.4.27）

  定位（铁律 1 v1.2 / Gate G-2026-11-06-02）：官方不运营 / 不托管 / 不依赖任何
  公网服务端、中继或代管域名；产品内置公网远控能力包（LAN/公网 开关、自绑域名、
  ACME / 自传证书双轨、一键部署）。服务器、域名、DNS、证书、防火墙全部由客户自备并
  自运维。本脚本只用客户自己提供的域名/IP 生成 SAN，私有 CA 签发服务器证书，
  导出 ca.pem，并打印 SPKI SHA-256 指纹供逐端固化。

  复用中枢包内 yuduan-ca.exe（dev/cmd/ca）的 init / issue-server / pin / check，
  不重写证书逻辑、不改任何产品代码。与 init-ca.sh 不同：本脚本不写任何 hub.env
  （公网部署必须显式配置；局域网自动写入的 YUDUAN_CLIENT_CA / YUDUAN_TLS_PIN
  会拉起独立的 :8444 mTLS 端口，不适用于公网只开 :8443 的形态）。

  用法（YOUR_DOMAIN / YOUR_IP 为占位符，请替换为客户的真实域名/IP；
        脚本不内置任何固定域名、IP 或公网端点）：
    .\prepare-public-cert.ps1 -DnsNames YOUR_DOMAIN
    .\prepare-public-cert.ps1 -DnsNames YOUR_DOMAIN,YOUR_DOMAIN_2 -IpAddresses YOUR_IP
    .\prepare-public-cert.ps1 -IpAddresses YOUR_IP -Port 443
    .\prepare-public-cert.ps1 -DnsNames YOUR_DOMAIN -Rotate

  说明：本脚本只生成证书与配置示例，不启动、不停止任何服务，不改变局域网默认
  部署行为；不执行本章配置时，部署行为与 v0.4.24 局域网默认完全一致。
#>

param(
  [string]$DnsNames = "",
  [string]$IpAddresses = "",
  [string]$CertDir = "",
  [string]$Org = "YuDuan",
  [int]$Port = 8443,
  [switch]$Rotate
)

$ErrorActionPreference = "Stop"

# —— 守卫 1：客户必须显式提供域名/IP，脚本没有任何内置地址 ——
if (-not $DnsNames -and -not $IpAddresses) {
  throw "必须显式提供 -DnsNames <客户域名> 和/或 -IpAddresses <客户IP>；本脚本不内置任何固定域名、IP 或公网端点。"
}
if ($Port -lt 1 -or $Port -gt 65535) {
  throw "-Port 必须是 1-65535 的整数（当前 $Port）。"
}
if (-not $CertDir) {
  $CertDir = Join-Path $PSScriptRoot "certs"
}
if (-not [System.IO.Path]::IsPathRooted($CertDir)) {
  throw "-CertDir 必须为绝对路径（当前 '$CertDir'），避免相对路径随工作目录漂移。"
}

# 示例主机名：优先第一个 DNS，否则第一个 IP
$first = ""
if ($DnsNames) {
  $first = $DnsNames.Split(',')[0].Trim()
} else {
  $first = $IpAddresses.Split(',')[0].Trim()
}
if (-not $first) { throw "无法从 -DnsNames/-IpAddresses 解析出主机名。" }

# —— 定位 yuduan-ca.exe：①脚本同目录 ②上级（hub 包根）——
$caExe = $null
$parentDir = Split-Path $PSScriptRoot -Parent
foreach ($cand in @((Join-Path $PSScriptRoot "yuduan-ca.exe"), (Join-Path $parentDir "yuduan-ca.exe"))) {
  if (Test-Path $cand) { $caExe = $cand; break }
}
if (-not $caExe) {
  throw "未找到 yuduan-ca.exe。请把中枢包内 yuduan-ca.exe 与本脚本放同一目录后重跑。"
}
Write-Host "==> 使用 yuduan-ca：$caExe"
Write-Host "==> 证书目录：$CertDir"
New-Item -ItemType Directory -Force -Path $CertDir | Out-Null

$caPem = Join-Path $CertDir "ca.pem"
$caKey = Join-Path $CertDir "ca.key"
$certPem = Join-Path $CertDir "cert.pem"
$keyPem = Join-Path $CertDir "key.pem"
$chainPem = Join-Path $CertDir "chain.pem"

$a = @("-dir", $CertDir)
if ($DnsNames) { $a += @("-dns", $DnsNames) }
if ($IpAddresses) { $a += @("-ip", $IpAddresses) }

if (Test-Path $caPem) {
  if (-not $Rotate) {
    throw "已存在 $caPem。为避免误覆盖根 CA，轮换叶证书请显式加 -Rotate。"
  }
  if (-not (Test-Path $caKey)) {
    throw "-Rotate 需要根 CA 私钥 $caKey；请从离线保管处临时取回，轮换后立即移出。"
  }
  Write-Host "==> 复用既有根 CA，轮换服务器证书（issue-server）"
  & $caExe issue-server @a
} else {
  if ($Rotate) {
    throw "-Rotate 要求已存在 $caPem，当前不存在。首次签发请去掉 -Rotate。"
  }
  Write-Host "==> 生成根 CA + 签发服务器证书（SAN: dns='$DnsNames' ip='$IpAddresses'）"
  & $caExe init -org $Org @a
}
if ($LASTEXITCODE -ne 0) { throw "yuduan-ca 执行失败（exit $LASTEXITCODE）。" }

# —— 校验产物完整性 ——
foreach ($f in @($caPem, $certPem, $keyPem, $chainPem)) {
  if (-not (Test-Path $f) -or (Get-Item $f).Length -eq 0) {
    throw "缺少产物 $f"
  }
}

$pin = (& $caExe pin -cert $certPem | Select-Object -First 1).Trim()
if ($LASTEXITCODE -ne 0) { throw "yuduan-ca pin 执行失败（exit $LASTEXITCODE）。" }
if ($pin -notmatch '^[0-9a-f]{64}$') {
  throw "SPKI SHA-256 指纹输出异常：'$pin'"
}

$base = "https://${first}:$Port"
Write-Host ""
Write-Host "=============================================================="
Write-Host " 证书准备完成（客户自备域名/IP，产品不托管任何公网服务）"
Write-Host "=============================================================="
Write-Host " 根 CA 公钥      : $caPem        <- 带外分发到主端/副端"
Write-Host " 根 CA 私钥      : $caKey        <- 立即移出中枢生产机，离线保管"
Write-Host " 服务器证书      : $certPem"
Write-Host " 服务器私钥      : $keyPem"
Write-Host " 完整链          : $chainPem     <- YUDUAN_TLS_CERT 指向它"
Write-Host " SPKI SHA-256    : $pin"
Write-Host ""
Write-Host "── 中枢 hub.env（请自行写入，本脚本不写 env）─────────────────"
Write-Host " YUDUAN_TLS_ADDR=:8443"
Write-Host " YUDUAN_TLS_CERT=$chainPem"
Write-Host " YUDUAN_TLS_KEY=$keyPem"
Write-Host " YUDUAN_PUBLIC_ADDR=$base"
Write-Host " YUDUAN_LOGIN_GUARD=1"
Write-Host ""
Write-Host "── 主端 / 副端（端口必须写全）────────────────────────────────"
Write-Host " 主端登录页      : $base"
Write-Host " 副端            : YUDUAN_HUB=wss://${first}:$Port/ws/agent"
Write-Host " 副端信任锚      : YUDUAN_TLS_CAFILE=<带外预置的 ca.pem 路径>"
Write-Host "                   或 YUDUAN_TLS_PIN=$pin"
Write-Host "                   （两者同时配置时为 AND 叠加，链校验与指纹均需通过）"
Write-Host ""
Write-Host "── 说明 ──────────────────────────────────────────────────────"
Write-Host " * 主端对 https 省略端口时默认连 443，而中枢 TLS 默认 8443；"
Write-Host "   若走 443 反向代理，请用 -Port 443 重跑示例，并保证两边一致。"
Write-Host " * YUDUAN_PUBLIC_ADDR 是事实必配项（非可选）：不设会兜底成明文监听串"
Write-Host "   （如 :8080）、且只补 http:// 不补 https://，软件分发 URL 拼成 http://:8080/..."
Write-Host "   或回环地址，副端 https 下载必然失败；必须写含 scheme 的完整 https 地址。"
Write-Host " * 公网禁用一次性自签证书（其 SAN 固定 localhost/127.0.0.1/::1）。"
Write-Host " * ca.pem / PIN 必须带外预置：claim 响应里的 caPem 不能作为本次校验信任锚。"
Write-Host " * 不设 YUDUAN_CLIENT_CA：mTLS 是独立的 :8444 端口，公网只开 :8443。"
Write-Host " * 不改 YUDUAN_HUB_ADDR：靠客户防火墙阻断公网 8080 / 18242 即可（18242 为默认发现端口，可由 YUDUAN_DISCOVERY_PORT 覆盖；公网形态请一并阻断该端口）。"
Write-Host " * 显式 YUDUAN_TLS_CERT 会跳过中枢的证书到期告警，须挂计划任务："
Write-Host "     $caExe check -dir $CertDir        # <30 天退出码 1"
Write-Host " * SNI 只设 -servername，不等于主机名校验；本轮严格校验只来自"
Write-Host "   显式 CAFILE/PIN 下追加的 -CAfile + -verify_return_error。"
Write-Host "=============================================================="

# 到期自检（新签证书 1 年有效，正常应通过；失败给出告警而非吞掉）
& $caExe check -dir $CertDir
if ($LASTEXITCODE -ne 0) {
  Write-Warning "ca check 未通过，请检查 $CertDir 下证书有效期。"
}
