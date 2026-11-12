# 御端中枢 Windows 部署编排（v2，档位 A 设备引导配套）。
#
# 功能：
#   1. 生成完整生产配置 hub.env —— 落盘到【中枢安装目录】（本脚本所在目录，
#      与 run-hub.cmd 的 %~dp0hub.env 完全一致，不写死 C:\ProgramData）：
#        - YUDUAN_HMAC_SECRET / YUDUAN_PEPPER / YUDUAN_SIGN_SEED 均随机 32B hex
#        - YUDUAN_REPO 指向安装目录 data\repo（服务身份可写）
#   2. 密钥文件 ACL 收紧（SYSTEM + Administrators 可读，普通用户不可读）。
#      说明：中枢 Go 版为纯标准库实现，无法解密 DPAPI，故中枢侧以 ACL 防护；
#      副端侧（Rust）已实现 DPAPI 加密落盘（见 rust/agent/src/dpapi.rs）。
#   3. 私有 CA：同目录存在 yuduan-ca.exe 时自动 `ca init -dir certs`
#      （建根 CA + 签服务器证书；中枢启动即走私有 CA 模式 + claim 可签客户端证书）。
#   4. 服务化：注册计划任务（开机自启，SYSTEM 身份）。
#   5. 防火墙放行：自动放行 TCP 8080（明文）/ TCP 8443（TLS）/ UDP 18242（发现，默认 18242，可配置）。
#   6. 同机副端联动：-AgentDir 指向副端 deploy 目录时，自动调用
#      install-agent.ps1 -Secret <HMAC> —— 密钥自动同步，副端零手动填写。
#   7. PostgreSQL 自动就绪（v0.4.22）：检测宿主机 PG →（未检出时）解压捆绑 zip 或
#      自动下载 EDB 官方便携包装为 yuduan-pg 服务 → 自动建 yuduan 角色/库（随机
#      hex 口令）→ 拼 DSN 写入 hub.env；全自动不可行才回退交互询问。
#
# 用法（管理员 PowerShell，cd 到中枢安装目录）：
#   .\register-task.ps1                       # 生成配置 + 注册自启服务
#   .\register-task.ps1 -AgentDir D:\yuduan-agent\deploy\windows
#   .\register-task.ps1 -Remove               # 卸载服务（配置保留）
#   .\register-task.ps1 -AttestRequire                                    # 启用设备证明强制校验（仅验签）
#   .\register-task.ps1 -AttestRequire -AttestTrustedMeasurements <sha256>,<sha256>  # 启用 + 度量白名单
#   .\register-task.ps1 -AttestState off                                 # 关闭设备证明强制校验（回退，兼容旧副端）
#   .\register-task.ps1 -ClearAttestWhitelist                            # 清空可信度量白名单（保留强制校验开关）
param(
  [switch]$Remove,
  # 重置：删除既有 hub.env 重新生成全套密钥（副端需重装以重新 claim）
  [switch]$ResetConfig,
# v0.4.21 投产收口：直接指定 PostgreSQL DSN（跳过交互）；留空则部署时交互询问
[string]$DbDsn = "",
  # v0.4.23（第十四轮实测问题1）：非交互模式——所有 Read-Host 一律不阻塞，能自动则自动，
  # 不能自动则明确降级（打印黄色 WARN + 处置指引）后继续。deploy.bat 一键路径恒传此开关，
  # 杜绝「隐窗等待输入 300s 被守卫终止」类挂死。
  [switch]$NonInteractive,
  [string]$TaskName = "YuDuanHub",
  # 可选：同机副端部署目录（含 install-agent.ps1）；提供则自动同步密钥
  [string]$AgentDir,
  # v0.4.27：公网部署模式开关；开启后额外完成证书准备 + 写公网 env + 防火墙 8443。
  [switch]$Public,
  # 公网 FQDN（当 -Public 时必填）；用于证书 SAN、对外地址与副端 wss 端点
  [string]$Domain = "",
  # 公网证书联系人邮箱（当 -Public 时必填）；ACME 必需，私有 CA 仅作记录
  [string]$Email = "",
  # 证书模式：acme（自动签发受信任证书）| self（私有 CA 自签）；-Public 时必填
  [string]$CertMode = "self",
  # v0.4.29（F-07）：UDP 自动发现端口（带外约定，默认 18242，可用 1..65535 覆盖）。
  # 写入 hub.env 的 YUDUAN_DISCOVERY_PORT；三端须一致，多实例并存时各实例配非默认值。
  [int]$DiscoveryPort = 18242,
  # v0.4.27：ACME 预发验证开关（-Public -CertMode acme 时追加 --staging，走 Let's Encrypt staging 环境）
  [switch]$Staging,
  # v0.4.30：显式允许内存模式（默认拒绝，防静默丢数据）。仅测试用；投产必须配置 PostgreSQL。
  [switch]$Memory,
  # v0.4.36（一键部署成功率实测矩阵 #1）：便携 PostgreSQL 端口参数化。
  #   默认 0=自动：5432 空闲则用 5432；5432 被【非 PG】监听占用且本机无 yuduan-pg 服务时，
  #   自动选 5433..5442 中首个空闲端口安装 yuduan-pg，解决「5432 被占→自动就绪跳过→干净机零成功」。
  #   >0 则显式指定端口（须空闲）；与 -DbDsn 共存时优先用 -DbDsn（本参数仅影响自动就绪路径）。
  [int]$PgPort = 0,
  # v0.4.33 §9.2 收口：设备证明强制校验开关。开启时副端必须附带有效设备证明（Ed25519 验签
  # + 度量白名单命中）才能注册；关闭（默认）时对旧副端逐字节兼容放行。仅高安全内网/合规场景启用。
  [switch]$AttestRequire,
  # v0.4.33 §9.2 收口：可信度量白名单——逗号分隔的可执行文件 SHA-256 hex（小写）。
  # 非空时副端上报的 measurement 必须命中其一，否则拒绝注册；留空则仅验签不约束度量。
  [string]$AttestTrustedMeasurements = "",
  # v0.4.34（测试报告 N1 修复）：设备证明强制校验显式开关（on|off）。
  #   "on"  → 写 YUDUAN_ATTEST_REQUIRE=1（等价旧 -AttestRequire）
  #   "off" → 写 YUDUAN_ATTEST_REQUIRE=0（关闭强制校验，兼容旧副端）
  #   留空  → 不改变既有值（与 -Public 行为一致）。
  # 引入此参数以满足「部署器是唯一受支持配置路径」原则——此前仅 -AttestRequire 无法回退关闭，
  # 一旦灰度开启就只能进生产机手工改 hub.env，与该口径自相矛盾（测试报告 N1）。
  [string]$AttestState = "",
  # v0.4.34（测试报告 N1 修复）：清空可信度量白名单（删除 YUDUAN_ATTEST_TRUSTED_MEASUREMENTS 行）。
  # 与 -AttestTrustedMeasurements 配合：指定本开关即清空白名单；后续若再传 -AttestTrustedMeasurements 则以新值覆盖。
  [switch]$ClearAttestWhitelist,
  # v0.4.40（P1-2）：显式构建版本（最高优先，供编排/CI 注入）；留空则读 yuduan-hub.exe 的 PE FileVersion。
  #   deploy.bat 经 %* 透传（52 行），无需改 bat；deploy-result.json 的 version 即取本值。
  [string]$BuildVersion = "",
  # v0.4.40（P1-3）：从 stdin 读一行 postgres 超级用户口令（不落命令行/日志），用于复用宿主机 PG；
  #   仍失败则自动降级为自带 yuduan-pg。deploy.bat 经 %* 透传（52 行），无需改 bat。
  [switch]$PgSuperPwdStdin
)
$ErrorActionPreference = "Stop"

# v0.4.36（一键部署成功率实测矩阵 #5/#6）：结构化原因码 + 机器可读结论。
#   失败时 emit 结构化 REASON 码（供外部编排判定根因），末尾统一落盘 deploy-result.json。
$script:DeployReason = "OK"
function Write-DeployResult {
  # 写机器可读结论到 installDir\deploy-result.json（成功/失败 + 实际端口 + 原因码）。
  param([bool]$Success, [int]$HubPort = 0, [string]$Reason = "OK", [string]$Detail = "")
  $obj = [ordered]@{
    success   = $Success
    hub_port  = $HubPort
    reason    = $Reason
    detail    = $Detail
    version   = $script:DeployVersion
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz")
  }
  $json = $obj | ConvertTo-Json -Compress
  try { Set-Content -Path (Join-Path $installDir "deploy-result.json") -Value $json -Encoding UTF8 } catch {}
  return $json
}
function Fail-Deploy {
  # 结构化失败出口：打印红色 ERROR + 写 deploy-result.json + exit 1。
  param([string]$Reason, [string]$Detail)
  $script:DeployReason = $Reason
  Write-Host "[ERROR] $Detail" -ForegroundColor Red
  Write-DeployResult -Success $false -Reason $Reason -Detail $Detail | Out-Null
  exit 1
}

# ---- 公网部署参数校验（v0.4.27）----
if ($Public) {
  if (-not $Domain.Trim()) { Write-Error "-Public 需要 -Domain <FQDN>" }
  if (-not $Email.Trim())  { Write-Error "-Public 需要 -Email <email>" }
  if ($CertMode -notin @("acme","self")) { Write-Error "-Public 需要 -CertMode acme|self（当前 '$CertMode'）" }
}

# ---- 发现端口校验（v0.4.29 / F-07）：允许 1..65535，非法给明确报错 ----
if ($DiscoveryPort -lt 1 -or $DiscoveryPort -gt 65535) {
  Write-Error "-DiscoveryPort 必须是 1..65535 之间的端口（当前 '$DiscoveryPort'）"
}

# ---- 设备证明可信度量白名单校验（v0.4.33）：每个条目必须是 64 位 hex ----
if ($AttestTrustedMeasurements.Trim()) {
  foreach ($m in ($AttestTrustedMeasurements.Trim() -split ',')) {
    $t = $m.Trim()
    if (-not ($t -match '^[0-9a-fA-F]{64}$')) {
      Write-Error "-AttestTrustedMeasurements 条目 '$t' 非法（须为 64 位十六进制 SHA-256，当前 '$($t.Length)' 字符）"
    }
  }
}

# ---- 设备证明强制校验开关校验（v0.4.34 N1）：仅接受 on|off ----
if ($AttestState.Trim() -and $AttestState.Trim() -notin @("on","off")) {
  Write-Error "-AttestState 仅接受 on|off（当前 '$AttestState'）"
}

# ---- 一键部署「先清后写」：清除历史部署在 User/Machine 两级作用域残留的 YUDUAN_* 环境变量 ----
# 中枢的唯一配置源是同目录 hub.env（run-hub.cmd / run-service.cmd 加载），系统级残留只会
# 造成"前台直跑 exe"时的隐性覆盖（如旧 YUDUAN_SIGN_SEED/YUDUAN_HUB）。不清理 DB_DSN/TLS_* 等高级项。
# 注意：必须经 cmd /c 把 stderr 重定向进 cmd 内部——PowerShell 5.1 在 EAP=Stop 下会把
# 原生命令 stderr（值不存在是常态）转成 terminating error 中断整个部署（v0.2.5 实机踩坑）。
Write-Host "==> 清除历史残留环境变量（YUDUAN_HMAC/PEPPER/SIGN_SEED/HUB 等，两级作用域）"
foreach ($scopePath in @("HKCU\Environment", "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment")) {
  foreach ($n in @("YUDUAN_HMAC_SECRET","YUDUAN_HMAC_ENFORCE","YUDUAN_PEPPER","YUDUAN_SIGN_SEED","YUDUAN_SIGN_SEED_FILE","YUDUAN_HUB")) {
    cmd /c "reg delete `"$scopePath`" /v $n /f >nul 2>&1"
  }
}

$installDir = $PSScriptRoot
$hubExe = Join-Path $installDir "yuduan-hub.exe"
$envFile = Join-Path $installDir "hub.env"
$repoDir = Join-Path $installDir "data\repo"
if (-not (Test-Path $hubExe)) { Write-Error "找不到 $hubExe（请将本脚本放在中枢安装目录，与 yuduan-hub.exe 同级）" }

# v0.4.40（P1-2）：deploy-result.json 的 version 不再写死——发布 CI 已把 tag 注入
#   yuduan-hub.exe 的 PE FileVersion（goversioninfo，见 release-build.yml）。
#   优先用 -BuildVersion 显式值，否则一次性读 exe 的 FileVersion；缺失/异常回退 "unknown"。
#   本赋值在所有 Write-DeployResult / Fail-Deploy 调用点之前完成（函数按调用时取值）。
#   用普通语句而非「if 表达式 + try 输出捕获」，规避 PS 5.1 细微的输出语义歧义。
$script:DeployVersion = "unknown"
if ($BuildVersion) {
  $script:DeployVersion = $BuildVersion
} else {
  try {
    $fv = (Get-Item $hubExe).VersionInfo.FileVersion
    if ($fv) { $script:DeployVersion = $fv }
  } catch { }   # 读 PE 版本失败保持 "unknown"
}

# ---- 卸载：停止运行中的任务实例 + 删计划任务 + 删防火墙规则（配置与数据保留）----
# v0.4.9：先探测再执行——不存在的一律打灰色 [SKIP]（干净机器/重复执行不是错误，
# 消除现场误判"红色报错=部署失败"）。
if ($Remove) {
  cmd /c "schtasks /Query /TN $TaskName >nul 2>&1"
  if ($LASTEXITCODE -eq 0) {
    cmd /c "schtasks /End /TN $TaskName >nul 2>&1"     # 先停守卫循环包装进程（run-service.cmd）
    cmd /c "schtasks /Delete /TN $TaskName /F >nul 2>&1"
    Write-Host "[OK]   计划任务 $TaskName 已删除" -ForegroundColor Green
  } else {
    Write-Host "[SKIP] 计划任务 $TaskName 不存在（未注册过自启，无需删除）" -ForegroundColor DarkGray
  }
  foreach ($n in @("yuduan-hub-plain", "yuduan-hub-tls", "yuduan-disc-udp")) {
    netsh advfirewall firewall show rule name="$n" >$null 2>&1
    if ($LASTEXITCODE -eq 0) {
      netsh advfirewall firewall delete rule name="$n" | Out-Null
      Write-Host "[OK]   防火墙规则 $n 已删除" -ForegroundColor Green
    } else {
      Write-Host "[SKIP] 防火墙规则 $n 不存在（无需删除）" -ForegroundColor DarkGray
    }
  }
  Write-Host "已清理完成（配置与数据保留在 $installDir）"
  exit 0
}

# ---- 随机 32 字节 hex 密钥 ----
function New-HexKey {
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $bytes = New-Object byte[] 32
  $rng.GetBytes($bytes)
  ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

# 幂等写入 hub.env 的 KEY=VALUE（存在则替换，不存在则追加）；不改写其余行。
# 模型参考既有 YUDUAN_DB_DSN 的「过滤+追加」写法，封装为函数以便公网段复用。
function Set-HubEnvLine {
  param([string]$File, [string]$Key, [string]$Value)
  $lines = @(Get-Content $File -ErrorAction SilentlyContinue)
  $new = @()
  $hit = $false
  foreach ($l in $lines) {
    if ($l -match "^$Key=") { $new += "$Key=$Value"; $hit = $true }
    else { $new += $l }
  }
  if (-not $hit) { $new += "$Key=$Value" }
  Set-Content $File -Value $new -Encoding ASCII
}

# 删除 hub.env 中指定 KEY 的行（用于清空开关，如 -ClearAttestWhitelist）。
# 与 Set-HubEnvLine 互补：部署器是唯一受支持配置路径，关/清开关也必须经此处，
# 不能让用户手工改 hub.env（易因未重启 / 作用域错配失效）。
function Remove-HubEnvLine {
  param([string]$File, [string]$Key)
  if (-not (Test-Path $File)) { return }
  $lines = @(Get-Content $File -ErrorAction SilentlyContinue) | Where-Object { $_ -notmatch "^$Key=" }
  Set-Content $File -Value $lines -Encoding ASCII
}

$generated = $false
$hmacSecret = ""
if ($ResetConfig -and (Test-Path $envFile)) {
  Remove-Item $envFile -Force
  Write-Host "==> 已按 -ResetConfig 删除既有 hub.env（将重新生成全套密钥；各副端需重装以重新 claim）"
}
if (-not (Test-Path $envFile)) {
  $generated = $true
  $hmacSecret = New-HexKey
  $pepper = New-HexKey
  $signSeed = New-HexKey
  $repoPath = $repoDir -replace '\\', '\\'
  @"
# 御端中枢生产配置（由 register-task.ps1 自动生成；KEY=VALUE，逐行加载）
# 密钥均已随机生成；文件 ACL 已收紧到 SYSTEM + Administrators。
YUDUAN_HMAC_SECRET=$hmacSecret
YUDUAN_HMAC_ENFORCE=1
YUDUAN_PEPPER=$pepper
YUDUAN_SIGN_SEED=$signSeed
YUDUAN_REPO=$repoPath
"@ | Set-Content $envFile -Encoding ASCII
  Write-Host "已生成配置 $envFile（HMAC/PEPPER/SIGN_SEED 均为随机 32B hex）"
} else {
  # 已有配置：读出 HMAC 供副端同步
  foreach ($line in Get-Content $envFile) {
    if ($line -match '^YUDUAN_HMAC_SECRET=(.+)$') { $hmacSecret = $Matches[1].Trim() }
  }
  Write-Host "复用既有配置 $envFile"
}

# v0.4.29（F-07）：新生成或复用 hub.env 都幂等写入发现端口（默认 18242，可由 -DiscoveryPort 覆盖）。
# run-hub.cmd / run-service.cmd 加载整个 hub.env → 中枢与同目录副端天然注入；
# 防火墙段按此值放行 UDP，三端（中枢/副端/主端 GUI）须一致，存量 env 不覆盖故默认零回归。
Set-HubEnvLine $envFile "YUDUAN_DISCOVERY_PORT" "$DiscoveryPort"

# ---- 设备证明（v0.4.33 §9.2 + v0.4.34 N1 修复）：暴露强制证明开关与可信度量白名单到 hub.env ----
# 部署脚本是 hub.env 的单一配置源，但仅在显式传参时写该键（与 -Public 行为一致）：
#   - 强制校验开关解析优先级：$AttestRequire（旧别名，置 on）> $AttestState="on" > $AttestState="off"（写 0）> 留空（不改）。
#   - $AttestState="off" → 写 YUDUAN_ATTEST_REQUIRE=0（envBool 仅认 "1" 为真）；满足「部署器是唯一受支持路径」——可经部署器回退关闭，无需手工改 hub.env。
#   - -AttestTrustedMeasurements 提供则写（统一小写 64hex），否则保留既有；-ClearAttestWhitelist 先清再按显式值覆盖。
# 重启计划任务后生效；配置 API（GET /api/v1/config 的 info.attest_require）与启动日志可核验。
$attestOn = $false
if ($AttestRequire) { $attestOn = $true }
elseif ($AttestState.Trim() -eq "on") { $attestOn = $true }
elseif ($AttestState.Trim() -eq "off") { $attestOn = $false }
# 显式 on/off 时落盘（含 off=0）；留空则不动既有值
if ($AttestRequire -or $AttestState.Trim()) {
  if ($attestOn) {
    Set-HubEnvLine $envFile "YUDUAN_ATTEST_REQUIRE" "1"
    Write-Host "已写入设备证明强制校验开关（YUDUAN_ATTEST_REQUIRE=1）" -ForegroundColor Green
  } else {
    Set-HubEnvLine $envFile "YUDUAN_ATTEST_REQUIRE" "0"
    Write-Host "已关闭设备证明强制校验（YUDUAN_ATTEST_REQUIRE=0）；旧副端逐字节兼容放行" -ForegroundColor Green
  }
} else {
  Write-Host "[SKIP] 未指定 -AttestRequire / -AttestState：保持 hub.env 既有 YUDUAN_ATTEST_REQUIRE 不变" -ForegroundColor DarkGray
}
# 白名单：先处理清空开关，再按显式值覆盖（指定 -ClearAttestWhitelist 即删行；随后若再传 -AttestTrustedMeasurements 则以新值写回）
if ($ClearAttestWhitelist) {
  Remove-HubEnvLine $envFile "YUDUAN_ATTEST_TRUSTED_MEASUREMENTS"
  Write-Host "已清空设备证明可信度量白名单（删除 YUDUAN_ATTEST_TRUSTED_MEASUREMENTS）" -ForegroundColor Green
}
if ($AttestTrustedMeasurements.Trim()) {
  Set-HubEnvLine $envFile "YUDUAN_ATTEST_TRUSTED_MEASUREMENTS" $AttestTrustedMeasurements.Trim().ToLower()
  $tmCount = ($AttestTrustedMeasurements.Trim() -split ',' | Where-Object { $_.Trim() }).Count
  Write-Host "已写入设备证明可信度量白名单（条目数=$tmCount）" -ForegroundColor Green
}

# =====================================================================
# PostgreSQL 自动就绪（v0.4.22，第十三轮实测报告收口）
# =====================================================================
# 目标：一键部署不再要求现场先手工装 PG/建号建库——自动完成「检测→(必要时)安装→
#       建号建库→产出 DSN」，然后照常写入 hub.env 并继续部署。
# 优先级：
#   A. -DbDsn 参数 / 既有 hub.env 的 YUDUAN_DB_DSN —— 显式配置，尊重并跳过自动流程
#   B. 宿主机已有 PG（捆绑 pgsql\bin > PATH > C:\Program Files\PostgreSQL\*\bin
#      > postgresql* 系统服务）→ 直接复用；连接需口令时询问一次 postgres 口令
#   C. 未检出：同目录捆绑 zip（离线场景）→ 解压出 pgsql\
#   D. 仍无且 5432 空闲：自动下载 EDB 官方 Windows 便携包（版本固定，公网可达时）
#      → initdb → 注册 yuduan-pg 服务（仅监听 127.0.0.1，开机自启）→ 启动
#   E. 自动建号建库：CREATE ROLE yuduan + CREATE DATABASE yuduan（随机 24 位 hex
#      口令——纯 ASCII、无 cmd/URL 元字符，规避第十三轮「粘贴示例 DSN（中文密码）
#      致 no such host」事故），拼 DSN 写入 hub.env
#   F. 以上均不可行 → 回退交互询问 DSN（附防呆要点）
# 注意：本区域原生命令一律走 cmd /c + 2>nul（PS 5.1 EAP=Stop 会把 stderr 转
#       terminating error 中断部署，v0.2.5 实机教训），并临时降 EAP=Continue。
# =====================================================================

$PG_PORT = 5432
# EDB 官方 Windows x64 便携包（免安装、免交互；版本固定便于复现与离线核验）
$PG_VERSION_PIN = "16.9-1"
$PG_URL = "https://get.enterprisedb.com/postgresql/postgresql-$PG_VERSION_PIN-windows-x64-binaries.zip"
$PG_BUNDLE = Join-Path $installDir "pgsql-windows-x64-binaries.zip"

# v0.4.44（N7，第 24 轮报告）：阶段里程碑行统一带时间戳——云端/无人值守观测窗内
#   可判断卡在哪个阶段（本轮 WAN run >25min 无阶段可观测）。
function Write-Stage {
  param([string]$Msg, [string]$Color = "")
  if ($Color) {
    Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Msg) -ForegroundColor $Color
  } else {
    Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Msg)
  }
}

# v0.4.44（N6，第 24 轮报告第五节）：便携 PG 安装根目录与主安装目录解耦——
#   EDB 便携包的 initdb 在 re-exec / restricted-token 路径按【当前代码页】处理 argv，
#   非 ASCII 目录（中文安装路径）必失败（实测 initdb: could not re-execute with
#   restricted token: error code 2，路径中文被降为 '?'），换解压 API 无法绕开。
#   取值规则（报告方案①+③ 合并）：
#     ① 安装目录纯 ASCII          → 沿用 $installDir（与旧版路径完全一致，零行为变化）
#     ② 否则 %ProgramData%\yuduan-pg（ASCII 兜底）
#     ③ 再退 %SystemDrive%\yuduan-pg；两者皆非 ASCII（理论边界）→ $null，
#        Install-PortablePg 以 PG_PATH_NONASCII 结构化原因码早失败。
$script:PgHome = $null
foreach ($cand in @($installDir, (Join-Path $env:ProgramData "yuduan-pg"), "$env:SystemDrive\yuduan-pg")) {
  if ($cand -and ($cand -match '^[\x20-\x7E]+$')) { $script:PgHome = $cand; break }
}

function Find-PgBinDir {
  # 返回包含 psql.exe 的目录；未检出返回 $null
  $bundled = Join-Path $installDir "pgsql\bin\psql.exe"
  if (Test-Path $bundled) { return (Split-Path $bundled -Parent) }
  # v0.4.44（N6）：非 ASCII 安装目录的便携 PG 装在 $PgHome（与 installDir 解耦）。
  if ($script:PgHome -and $script:PgHome -ne $installDir) {
    $altBundled = Join-Path $script:PgHome "pgsql\bin\psql.exe"
    if (Test-Path $altBundled) { return (Split-Path $altBundled -Parent) }
  }
  $inPath = Get-Command "psql.exe" -ErrorAction SilentlyContinue
  if ($inPath) { return (Split-Path $inPath.Source -Parent) }
  $pf = Get-ChildItem "C:\Program Files\PostgreSQL\*\bin\psql.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
  if ($pf) { return $pf.DirectoryName }
  # postgresql* 系统服务（安装版可能装在非默认盘）：从服务可执行路径反推 bin 目录
  $svc = Get-CimInstance Win32_Service -Filter "Name LIKE 'postgresql%'" -ErrorAction SilentlyContinue |
         Select-Object -First 1
  if ($svc -and $svc.PathName) {
    if ($svc.PathName -match '^"([^"]+)"') { $p = $Matches[1] } else { $p = ($svc.PathName -split ' ')[0] }
    if (Test-Path $p) {
      $dir = Split-Path $p -Parent
      if (Test-Path (Join-Path $dir "psql.exe")) { return $dir }
      $parent = Split-Path $dir -Parent
      if (Test-Path (Join-Path $parent "bin\psql.exe")) { return (Join-Path $parent "bin") }
    }
  }
  return $null
}

function Invoke-Psql {
  # 经临时 SQL 文件执行（规避引号转义）。
  #   - 返回值 = 命令是否成功（退出码 0），【不代表查询有结果】；
  #   - $script:PgResult = 查询输出的 trim 结果（存在性判断必须看它，见 v0.4.35 #A）。
  # v0.4.23：加 -w（--no-password）——需要口令时立即失败而非在控制台等输入，
  # 杜绝隐窗/无人值守场景 psql 挂在密码提示上（第十四轮实测 300s 卡死诱因之一）。
  param([string]$BinDir, [string]$Sql, [string]$Db = "postgres")
  $script:PgResult = ""
  $sqlFile = Join-Path $env:TEMP "yd_pg.sql"
  Set-Content -Path $sqlFile -Value $Sql -Encoding ASCII
  $psql = Join-Path $BinDir "psql.exe"
  $out = cmd /c "`"$psql`" -U postgres -w -h 127.0.0.1 -p $PG_PORT -d $Db -tA -f `"$sqlFile`" 2>nul"
  $script:PgResult = ($out | Out-String).Trim()
  return ($LASTEXITCODE -eq 0)
}

function Grant-YuduanRole {
  # 自动建 yuduan 角色 + 库，返回拼好的 DSN；不可自动时返回 $null（回退交互）。
  param([string]$BinDir)
  try {
    # 连通性预检（trust/免密才可全自动；需要口令时：交互模式询问一次，非交互模式直接放弃）
    if (-not (Invoke-Psql -BinDir $BinDir -Sql "SELECT 1;")) {
      # v0.4.40（P1-3）(b)：可选口令逃生舱——-PgSuperPwdStdin 时从 stdin 读一行 postgres 口令，
      #   设 PGPASSWORD 后重试预检（复用原 359-365 的重试套路；口令绝不进命令行/日志）。
      #   仅在「仍然失败」时才置 PG_AUTH_REQUIRED 并回退 $null，由主流程据此自动降级自带 PG（a）。
      #   注意：成功后 PGPASSWORD 必须保留到下方建号/建库完成（后续 Invoke-Psql 仍需认证）。
      $pwdAuthed = $false
      if ($PgSuperPwdStdin) {
        $pgSuperPwd = [Console]::In.ReadLine()
        if ($pgSuperPwd -and $pgSuperPwd.Trim()) {
          $env:PGPASSWORD = $pgSuperPwd.Trim()
          $pwdAuthed = Invoke-Psql -BinDir $BinDir -Sql "SELECT 1;"
        }
      }
      if (-not $pwdAuthed) {
        if ($NonInteractive) {
          # v0.4.23（第十四轮问题1）：一键部署隐窗中绝不能等输入——明确降级，打印处置指引
          Write-Host "[WARN] 本机 PG 需要口令认证（或无 postgres 角色），非交互模式跳过复用。" -ForegroundColor Yellow
          Write-Host "       处置：加 -PgSuperPwdStdin 从 stdin 提供 postgres 口令，或改用 .\register-task.ps1 -DbDsn 'postgres://yuduan:密码@127.0.0.1:5432/yuduan?sslmode=disable' 重跑，" -ForegroundColor Yellow
          Write-Host "             亦将自动降级为自带 yuduan-pg（备用端口），无需手工干预。" -ForegroundColor Yellow
          $script:DeployReason = "PG_AUTH_REQUIRED"
          return $null
        }
        $pgSuperPwd = Read-Host "    本机 PG 需要口令认证，请输入 postgres 超级用户口令（回车跳过=走手工 DSN）"
        if ($pgSuperPwd.Trim()) {
          $env:PGPASSWORD = $pgSuperPwd.Trim()
          if (-not (Invoke-Psql -BinDir $BinDir -Sql "SELECT 1;")) { return $null }
        } else { return $null }
      }
    }
    # 角色已存在（口令未知）→ 无法拼 DSN，回退交互，绝不重置既有口令（防破坏存量部署）
    # v0.4.35 修复（一键部署成功率实测矩阵 #A）：存在性判断必须看【结果集】而非【退出码】——
    # 空库上 `SELECT 1 FROM pg_roles WHERE rolname='yuduan'` 返回 0 行但 psql 退出码仍为 0，
    # 旧逻辑 `if (Invoke-Psql ...)` 误判"角色已存在"直接放弃建号，致干净机一键部署 0% 成功。
    # 改判：$script:PgResult 非空（查到行）= 已存在才回退；空结果集（含查询失败）一律尝试建号。
    if ((Invoke-Psql -BinDir $BinDir -Sql "SELECT 1 FROM pg_roles WHERE rolname='yuduan';") -and $script:PgResult) { $script:DeployReason = "PG_ROLE_EXISTS_NO_PWD"; return $null }
    $pgPassword = (New-HexKey).Substring(0, 24)   # 随机 24 位 hex：纯 ASCII、无 cmd/URL 元字符
    if (-not (Invoke-Psql -BinDir $BinDir -Sql "CREATE ROLE yuduan LOGIN PASSWORD '$pgPassword';")) { return $null }
    # 库存在性同样看结果集：查到行（非空）= 已存在跳过；空结果集（含查询失败）= 需建库。
    # 旧逻辑 `-not (Invoke-Psql ...)` 在空库上恒为 false，CREATE DATABASE 永不被执行，DSN 指向不存在的库。
    if ((Invoke-Psql -BinDir $BinDir -Sql "SELECT 1 FROM pg_database WHERE datname='yuduan';") -and -not $script:PgResult) {
      if (-not (Invoke-Psql -BinDir $BinDir -Sql "CREATE DATABASE yuduan OWNER yuduan;")) {
        # 库没建成：清掉刚建的角色，避免留下半成品
        Invoke-Psql -BinDir $BinDir -Sql "DROP ROLE IF EXISTS yuduan;" | Out-Null
        return $null
      }
    }
    return "postgres://yuduan:$pgPassword@127.0.0.1:$PG_PORT/yuduan?sslmode=disable"
  } finally {
    # v0.4.40（P1-3）：无论成功/失败，清除 PGPASSWORD——口令绝不驻留进程环境，
    #   也确保后续降级到自带 trust PG 时不带任何残留口令（finally 覆盖全部 return 出口）。
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
  }
}

function Install-OwnPg {
  # 捆绑 zip（离线优先）→ 官方下载；成功返回 pgsql\bin 目录，失败返回 $null。
  # v0.4.40（P3-7）：离线包发现不再只认固定文件名——在【安装目录 + 其父目录】两层内
  #   （-Recurse -Depth 2，PS 5.0+）匹配 pgsql-*-binaries.zip，命中即用其真实路径。
  #   $PG_BUNDLE 是脚本级变量（定义于 PG 常量段），函数内普通赋值只建本地副本，故必须写 $script:；
  #   下方 Test-Path / curl -o / tar -xf 读到的才是新值。限定 installDir + 父目录，绝不整盘扫描。
  #   -ErrorAction SilentlyContinue：EAP=Stop 下目录不存在/权限不足不得中断部署。
  $pgSearchRoots = @($installDir, (Split-Path $installDir -Parent)) | Where-Object { $_ }
  $localHit = Get-ChildItem -Path $pgSearchRoots -Recurse -Depth 2 -Filter 'pgsql-*-binaries.zip' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($localHit) { $script:PG_BUNDLE = $localHit.FullName }
  if (-not (Test-Path $PG_BUNDLE)) {
    Write-Host "==> 宿主机未检出 PostgreSQL，自动下载官方便携包（约 314MB，仅首次，版本 $PG_VERSION_PIN）…"
    Write-Host "    （内网无公网？手工下载 $PG_URL 放到 $PG_BUNDLE 后重跑，或放任意 pgsql-*-binaries.zip）"
    # v0.4.42（N5）：offline-nobundle 快速失败——在重 600s 下载前，先用极短超时探一次
    #   PG 主机可达性。curl 明确"无法解析/无法连接"（exit 6/7，对应无公网 DNS 失败或路由
    #   不通）即判定离线，跳过 600s 下载直接置 PG_INSTALL_FAILED 快速返回（离线机不空等 10 分钟）。
    #   其余情况（含超时 exit 28 黑洞网络）一律放行走原逻辑真实下载（受 -m 600 约束），
    #   绝不因探活失败而抑制一次本可成功的下载（零误杀）。
    $probeExit = (& curl.exe -s -m 10 -o NUL -I "$PG_URL")
    $pe = $LASTEXITCODE
    if ($pe -eq 6 -or $pe -eq 7) {
      $script:DeployReason = "PG_INSTALL_FAILED"
      Write-Host "[WARN] PostgreSQL 主机不可达（curl exit=$pe，疑似无公网/离线），跳过下载直接失败。" -ForegroundColor Yellow
      return $null
    }
    # v0.4.40（P3-8）：总超时 1800s→600s（无公网/黑洞网络快速失败），保留 --connect-timeout 15。
    #   curl 默认进度条走 stderr（cmd /c 下被抑制、且 EAP=Stop 不允许原生 stderr）；改用 -s 静默 +
    #   -w 把「已下载字节/耗时」写到 stdout 作可见进度，并加前后 Write-Host 阶段标记。
    #   与自检段（控制台/鉴权脚本/登录接口三处 & curl.exe -w "%{http_code}"）一致用 & 直调：
    #   -w 的 %{...} 原样送达（避开 cmd 对 % 的展开）；-s 抑制全部原生 stderr，
    #   且 PG 自动就绪区域已临时降 EAP=Continue（见下方 try 段），双保险不中断部署。
    Write-Stage "[下载] 开始拉取 PostgreSQL 便携包（超时 600s）…"
    $dlStats = & curl.exe -L -s --retry 3 --retry-delay 2 --connect-timeout 15 -m 600 -o "$PG_BUNDLE" -w "已下载 %{size_download} 字节 / 耗时 %{time_total}s" $PG_URL
    $dlExit = $LASTEXITCODE
    Write-Stage "[下载] curl 结束（exit=$dlExit）：$dlStats"
    if ($dlExit -ne 0 -or -not (Test-Path $PG_BUNDLE)) {
      # v0.4.40（P3-8）：下载失败必须置结构化原因码——否则 Install-OwnPg 返回 $null 后
      #   主流程 Start-OwnPg 分支被短路（$pgBin 为 $null），末尾原因码聚合会把根因误报成 DSN_MISSING。
      $script:DeployReason = "PG_INSTALL_FAILED"
      Write-Host "[WARN] PostgreSQL 便携包下载失败（服务器可能无公网 / 600s 超时）。" -ForegroundColor Yellow
      Write-Host "       诊断：curl exit=$dlExit，$dlStats（0 字节或耗时≈600s 多为超时/黑洞网络）。" -ForegroundColor Yellow
      return $null
    }
  } else {
    Write-Host "==> 检出本地 PostgreSQL 便携包（离线安装，自动发现）：$PG_BUNDLE"
  }
  # v0.4.44（N6）：解压目标从 $installDir 改为 $script:PgHome（与主安装目录解耦，
  # 非 ASCII 安装路径下 PG 全套落在纯 ASCII 目录，initdb 才能活）。
  Write-Host "==> 解压 PostgreSQL 到 $script:PgHome\pgsql（首次约 1-2 分钟）…"
  # v0.4.41（N1 修复）：改用 .NET ZipFile 显式解压，彻底规避 `cmd /c tar -C <中文路径>`
  # 经 cmd.exe 传递非 ASCII 路径时的代码页（GBK vs UTF-8）错配卡死（实测中文目录 >240s
  # 未完成、ASCII 路径 68s）。.NET 路径为内部 UTF-16，无 cmd 代码页问题；tar 仅作
  # ASCII 路径兜底（保持快速路径），Expand-Archive 为二级兜底。
  $t0 = Get-Date
  $extractOk = $false
  try {
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem } catch {}
    [System.IO.Compression.ZipFile]::ExtractToDirectory($PG_BUNDLE, $script:PgHome)
    $extractOk = $true
    Write-Stage ("==> 解压完成（.NET ZipFile，用时 {0:N1}s）" -f ((Get-Date) - $t0).TotalSeconds) -Color "Green"
  } catch {
    Write-Host ("[WARN] .NET 解压失败（{0}），回退 tar/Expand-Archive…" -f $_.Exception.Message) -ForegroundColor Yellow
  }
  if (-not $extractOk) {
    cmd /c "tar -xf `"$PG_BUNDLE`" -C `"$script:PgHome`" 2>nul"
    if ($LASTEXITCODE -ne 0) { Expand-Archive -Path $PG_BUNDLE -DestinationPath $script:PgHome -Force }
  }
  if (-not (Test-Path (Join-Path $script:PgHome "pgsql\bin\initdb.exe"))) {
    # v0.4.40（P3-8）：与下载失败同口径置结构化原因码，避免末尾聚合误报成 DSN_MISSING。
    $script:DeployReason = "PG_INSTALL_FAILED"
    Write-Host "[WARN] 解压后未找到 pgsql\bin\initdb.exe（zip 结构异常或下载不完整）" -ForegroundColor Yellow
    return $null
  }
  return (Join-Path $script:PgHome "pgsql\bin")
}

function Start-OwnPg {
  # initdb（幂等）→ 注册 yuduan-pg 服务（开机自启）→ 启动 → pg_isready 确认。
  param([string]$BinDir)
  # v0.4.44（N6）：pgdata 跟随 $PgHome（纯 ASCII 根目录），不再放 $installDir 下。
  $pgdata = Join-Path $script:PgHome "pgdata"
  $initdb = Join-Path $BinDir "initdb.exe"
  $pgctl  = Join-Path $BinDir "pg_ctl.exe"
  $ready  = Join-Path $BinDir "pg_isready.exe"
  if (-not (Test-Path (Join-Path $pgdata "PG_VERSION"))) {
    Write-Stage "==> 初始化 PG 数据目录（initdb，仅首次）…"
    cmd /c "`"$initdb`" -D `"$pgdata`" -U postgres -E UTF8 -A trust" | Out-Null
    if (-not (Test-Path (Join-Path $pgdata "PG_VERSION"))) {
      Write-Host "[WARN] initdb 失败（数据目录 $pgdata 未生成 PG_VERSION）" -ForegroundColor Yellow
      return $false
    }
    # 安全基线：仅监听回环，不对局域网暴露
    Add-Content -Path (Join-Path $pgdata "postgresql.conf") -Value "listen_addresses = '127.0.0.1'" -Encoding ASCII
    Add-Content -Path (Join-Path $pgdata "postgresql.conf") -Value "port = $PG_PORT" -Encoding ASCII
    # 服务账户（pg_ctl register 默认 NETWORK SERVICE）需要数据目录完全控制，
    # 以及安装目录的读/遍历（否则服务启动时打不开 pgdata）
    icacls $pgdata /grant "NETWORK SERVICE:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
    icacls $script:PgHome /grant "NETWORK SERVICE:(OI)(CI)RX" | Out-Null
  }
  cmd /c "sc.exe query yuduan-pg >nul 2>&1"
  if ($LASTEXITCODE -ne 0) {
    cmd /c "`"$pgctl`" register -N yuduan-pg -D `"$pgdata`" -S auto" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Host "[WARN] yuduan-pg 服务注册失败（pg_ctl register exit=$LASTEXITCODE）" -ForegroundColor Yellow
      return $false
    }
  }
  cmd /c "sc.exe query yuduan-pg | findstr /C:`"RUNNING`" >nul 2>&1"
  if ($LASTEXITCODE -ne 0) { cmd /c "net start yuduan-pg >nul 2>&1" }
  for ($i = 0; $i -lt 30; $i++) {
    cmd /c "`"$ready`" -h 127.0.0.1 -p $PG_PORT >nul 2>&1"
    if ($LASTEXITCODE -eq 0) {
      Write-Stage "[OK]   PostgreSQL 已就绪（yuduan-pg 服务，仅监听 127.0.0.1:$PG_PORT，开机自启）" -Color "Green"
      return $true
    }
    Start-Sleep -Seconds 2
  }
  Write-Host "[WARN] PostgreSQL 60s 内未就绪（查 $pgdata\log 目录或事件查看器）" -ForegroundColor Yellow
  return $false
}

function Install-PortablePg {
  # v0.4.40（P1-3）：抽出「自带便携 PostgreSQL 安装」为可复用流程——
  #   既服务「未检出本机 PG」路径，也服务「复用本机 PG 需口令/角色已存在」的自动降级路径。
  #   成功返回 pgsql\bin 目录，失败返回 $null；选定端口写入 $script:PG_PORT。
  #   ★ 必须用 $script: 作用域：$PG_PORT 是脚本级变量（定义于 PG 常量段），函数内普通赋值只建本地副本，
  #     Invoke-Psql / Start-OwnPg / Grant-YuduanRole 读到的仍是旧值（同 P3-7 的 $PG_BUNDLE 坑）。
  $installPort = $PG_PORT
  # v0.4.36（#1）：评估 5432 占用，必要时选备用端口。
  #   根因：此前「5432 被占 → 直接跳过自动安装」导致干净机一键部署 0% 成功（实测矩阵 #1）。
  $portOut = cmd /c "netstat -ano | findstr /C:`":$PG_PORT `" | findstr /C:`"LISTENING`""
  if ($portOut) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='yuduan-pg'" -ErrorAction SilentlyContinue
    if ($svc) {
      Write-Host "[WARN] 端口 $PG_PORT 已被占用且已存在 yuduan-pg 服务，尝试复用现有 PG。" -ForegroundColor Yellow
    } elseif ($PgPort -gt 0) {
      Write-Host "[ERROR] 显式 -PgPort $PgPort 被占用，无法在其上安装 yuduan-pg。" -ForegroundColor Red
      $script:DeployReason = "PG_PORT_BUSY"
      $installPort = 0
    } else {
      $alt = $null
      foreach ($cand in 5433..5442) {
        $c = cmd /c "netstat -ano | findstr /C:`":$cand `" | findstr /C:`"LISTENING`""
        if (-not $c) { $alt = $cand; break }
      }
      if ($alt) {
        $installPort = $alt
        Write-Host "[INFO] 端口 5432 被非 PostgreSQL 进程占用，自动改用端口 $installPort 安装 yuduan-pg。" -ForegroundColor Cyan
      } else {
        Write-Host "[WARN] 端口 5432 被占用且 5433..5442 均不可用，跳过自动安装。" -ForegroundColor Yellow
        Write-Host "       请按教程 §八手工建号建库，稍后粘贴 DSN。"
        $installPort = 0
      }
    }
  }
  if ($installPort -gt 0) {
    # v0.4.44（N6）：无可用 ASCII 根目录（理论边界）→ 结构化原因码早失败，不空跑。
    if (-not $script:PgHome) {
      Write-Host "[ERROR] 安装目录与系统目录均含非 ASCII 字符：initdb 不支持非 ASCII 路径，便携 PG 无法安装。" -ForegroundColor Red
      Write-Host "        处置：将中枢安装目录改为纯 ASCII 路径（如 C:\yuduan-hub）后重跑。" -ForegroundColor Yellow
      $script:DeployReason = "PG_PATH_NONASCII"
      return $null
    }
    $script:PG_PORT = $installPort   # 贯穿 Invoke-Psql / Start-OwnPg / DSN（脚本级）
    $bin = Install-OwnPg
    if ($bin -and -not (Start-OwnPg -BinDir $bin)) {
      $script:DeployReason = "PG_INSTALL_FAILED"
      return $null
    }
    return $bin
  }
  return $null
}

# ---- PostgreSQL 持久化配置（v0.4.22：自动就绪 → 失败才回退交互）----
# 优先级：-DbDsn 参数 > 既有 hub.env 中的 YUDUAN_DB_DSN > 自动就绪 > 交互询问。
# 注意：DSN 经 run-hub.cmd 的 for /f 加载，密码请避开 %% ! ^ 等 cmd 元字符
#      （自动流程产出的 hex 口令已天然规避）。
$existingDsn = ""
foreach ($line in Get-Content $envFile) {
  if ($line -match '^YUDUAN_DB_DSN=(.+)$') { $existingDsn = $Matches[1].Trim() }
}
if (-not $DbDsn -and -not $existingDsn -and $Memory) {
  # v0.4.45（N11，第二十五轮实测报告）：显式 -Memory 且无既有 DSN → **跳过 PG 自动就绪**
  # 直接内存模式。此前仍先跑「宿主 PG 探测 → 便携 PG 下载 314MB + initdb + 建号」全流程，
  # 测试/演示场景被拖到 10 分钟级（实测 WAN 任务 11+ 分钟未发布地址）。
  Write-Host "[WARN] 显式 -Memory：跳过 PostgreSQL 自动就绪（不下载/不 initdb），中枢将以内存模式运行（重启丢数据，仅供测试）" -ForegroundColor Yellow
}
elseif (-not $DbDsn -and -not $existingDsn) {
  $prevEAP = $ErrorActionPreference
  $ErrorActionPreference = "Continue"   # 本区域原生命令 stderr 不允许中断部署
  try {
    Write-Host ""
    Write-Host "==> PostgreSQL 自动就绪：检测宿主机 PostgreSQL…"
    $pgBin = Find-PgBinDir
    # v0.4.40（P1-3）：$needPortable 统一驱动「自带便携 PG」流程——
    #   未检出本机 PG 时为 true；复用本机 PG 因口令/角色已存在失败时也会被置 true（自动降级）。
    $needPortable = -not $pgBin
    if ($pgBin) {
      Write-Host "    检出本机 PostgreSQL：$pgBin（复用，不重装）"
      $dsn = Grant-YuduanRole -BinDir $pgBin
      if ($dsn) {
        $DbDsn = $dsn
        Write-Host "[OK]   已自动创建 yuduan 角色/库（随机口令，直接写入 hub.env，不回显控制台）" -ForegroundColor Green
      } elseif ($script:DeployReason -in @("PG_AUTH_REQUIRED", "PG_ROLE_EXISTS_NO_PWD")) {
        # v0.4.40（P1-3）(a)：复用宿主机 PG 的死胡同 → 自动降级为自带便携 PG。
        #   绝不改动存量库（不重置既有 yuduan 口令），改在 5433..5442 备用端口装独立 trust 实例。
        #   Install-PortablePg 把选定端口写入 $script:PG_PORT，贯穿 Invoke-Psql / Start-OwnPg /
        #   DSN（Grant-YuduanRole 读脚本级 $PG_PORT 拼串）→ hub.env → 中枢连接 → 登录自检。
        Write-Host "[WARN] 复用本机 PG 失败（$script:DeployReason）：不改动存量库，自动降级为自带 yuduan-pg（备用端口）。" -ForegroundColor Yellow
        $needPortable = $true
        $script:DeployReason = "OK"   # 清掉复用阶段的根因，交由降级流程自己的原因码接管
      } else {
        Write-Host "[WARN] 未能全自动建号（角色已存在但口令未知 / PG 需口令认证未提供）——回退手工 DSN。" -ForegroundColor Yellow
      }
    }
    if (-not $DbDsn -and $needPortable) {
      $pgBin = Install-PortablePg
      if ($pgBin) {
        $dsn = Grant-YuduanRole -BinDir $pgBin
        if ($dsn) {
          $DbDsn = $dsn
          Write-Host "[OK]   已自动创建 yuduan 角色/库（随机口令，直接写入 hub.env，不回显控制台）" -ForegroundColor Green
        } else {
          Write-Host "[WARN] 自带 yuduan-pg 未能全自动建号——回退手工 DSN。" -ForegroundColor Yellow
        }
      }
    }
  } finally { $ErrorActionPreference = $prevEAP }
}
if (-not $DbDsn -and -not $existingDsn) {
  if ($Memory) {
    # 显式逃生舱：仅测试允许内存模式（重启丢数据）
    Write-Host "[WARN] 显式 -Memory：中枢将以内存模式运行（重启丢数据，仅供测试）" -ForegroundColor Yellow
  } elseif ($NonInteractive) {
    # v0.4.30（失败即中止）：一键部署默认要求 PG（上方自动就绪已尝试）；无 DSN 即中止，
    # 杜绝静默内存模式丢数据。仅测试可加 -Memory 重跑。
    Write-Host "        投产必须配置持久化：① 联网环境将自动拉起 yuduan-pg；② 或显式 .\register-task.ps1 -DbDsn 'postgres://yuduan:密码@127.0.0.1:5432/yuduan?sslmode=disable'；" -ForegroundColor Yellow
    Write-Host "        仅测试可用：加 -Memory 重跑以强制内存模式（重启丢数据）。" -ForegroundColor Yellow
    # v0.4.36（#5）：结构化原因码——优先用已捕获的根因（如 PG_INSTALL_FAILED / PG_PORT_BUSY / PG_AUTH_REQUIRED），
    # 否则归为 DSN_MISSING（完全没拿到 DSN）。
    $reason = if ($script:DeployReason -ne "OK") { $script:DeployReason } else { "DSN_MISSING" }
    Fail-Deploy -Reason $reason -Detail "未配置 PostgreSQL 且未能自动就绪：一键部署中止。"
  } else {
    Write-Host ""
    Write-Host "==> 持久化：当前为内存模式（重启丢数据、admin 密码复位、备份/集群不可用），投产必须配置 PostgreSQL。" -ForegroundColor Yellow
    Write-Host "    ⚠️ 防呆要点（第十三轮实测复盘）："
    Write-Host "      1) 下方示例只是模板——密码位必须替换为实际口令，直接粘贴示例必失败（no such host）；"
    Write-Host "      2) 密码必须纯 ASCII，含特殊字符须 URL 编码（@ : / 等）；"
    Write-Host "      3) PG 里必须已建 yuduan 角色与库（教程 §八：CREATE USER yuduan ...; CREATE DATABASE yuduan OWNER yuduan;）"
    Write-Host "    中枢启动自动建表（幂等），连接失败会启动报错退出（不会静默丢数据）。"
    Write-Host "    格式示例：postgres://yuduan:密码@127.0.0.1:5432/yuduan?sslmode=disable"
    Write-Host "    直接回车=中止部署（防误用内存模式）；输入 'memory' 可强制内存模式（仅测试）。"
    $dbInput = Read-Host "    粘贴 DSN 后回车启用持久化；或输入 memory 强制内存模式；直接回车中止"
    if ($dbInput.Trim()) { $DbDsn = $dbInput.Trim() }
    elseif ($dbInput.Trim().ToLower() -eq "memory") { Write-Host "[WARN] 显式选择内存模式（重启丢数据，仅供测试）" -ForegroundColor Yellow }
    else { Fail-Deploy -Reason "DSN_MISSING" -Detail "未提供 DSN：部署中止（防止静默内存模式丢数据）。" }
  }
}
if ($DbDsn) {
  $envLines = @(Get-Content $envFile) | Where-Object { $_ -notmatch '^YUDUAN_DB_DSN=' }
  $envLines += "YUDUAN_DB_DSN=$DbDsn"
  Set-Content $envFile -Value $envLines -Encoding ASCII
  if ($existingDsn) {
    Write-Host "[OK]   已按 -DbDsn 覆盖既有 PostgreSQL 持久化配置" -ForegroundColor Green
  } else {
    Write-Host "[OK]   已写入 PostgreSQL 持久化配置（YUDUAN_DB_DSN）；启动日志应出现「持久化后端：PostgreSQL」" -ForegroundColor Green
  }
} elseif ($existingDsn) {
  Write-Host "[OK]   保留既有 PostgreSQL 持久化配置" -ForegroundColor Green
} else {
  # 仅 -Memory 或交互显式选 memory 才到达此处（默认失败即中止已在上方拦截）
  Write-Host "[WARN] 未配置 PostgreSQL：中枢将以内存模式运行（重启丢数据，仅供测试）" -ForegroundColor Yellow
}

# ---- ACL 收紧：仅 SYSTEM + Administrators 可读（防普通用户/同机其他账户读取密钥）----
icacls $envFile /inheritance:r /grant:r "SYSTEM:(R,W)" "Administrators:(R,W)" | Out-Null
Write-Host "已收紧 $envFile 权限（仅 SYSTEM + Administrators）"

# ---- 私有 CA（存在 yuduan-ca.exe 时自动建 CA + 签服务器证书）----
$caExe = Join-Path $installDir "yuduan-ca.exe"
$caPem = Join-Path $installDir "certs\ca.pem"
if ((Test-Path $caExe) -and (-not (Test-Path $caPem))) {
  Write-Host "==> 自动建立私有 CA（certs\）+ 签发服务器证书"
  & $caExe init -dir (Join-Path $installDir "certs") 2>&1 | Out-Null
  if (Test-Path $caPem) {
    Write-Host "==> 私有 CA 就绪：中枢启动自动签发/续签；claim 端点可为副端签发客户端证书（mTLS）"
  } else {
    Write-Host "==> ⚠️ CA 建立失败（继续部署，中枢将用一次性自签证书）"
  }
} elseif (-not (Test-Path $caExe)) {
  Write-Host "==> ⚠️ 未找到 yuduan-ca.exe：私有 CA 未启用（mTLS 客户端证书签发不可用）"
  Write-Host "    中枢将用一次性自签证书；建议从发布包获取 yuduan-ca.exe 后重跑本脚本启用私有 CA。"
}

# ---- 数据目录 + 服务身份写权限（自定义安装路径时 SYSTEM 默认可能无写权限）----
New-Item -ItemType Directory -Force -Path $repoDir | Out-Null
icacls $installDir /grant "SYSTEM:(OI)(CI)M" | Out-Null

# ---- 服务启动包装（与 run-hub.cmd 同源：加载同目录 hub.env 后启动）----
# 崩溃守卫：hub 进程退出（崩溃/被杀）5 秒后自动重启；开机自启由计划任务保证。
# D-03 修复：脚本改用 %~dp0 动态解析自身路径，不硬编码安装目录——中文路径下
#   Set-Content -Encoding ASCII 会把非 ASCII 字符破坏成 '?'，导致 bat 找不到 exe；
#   %~dp0 由 cmd 在运行时按当前系统代码页解析，中文路径可正确工作。
# D-06 修复：hub 输出重定向到 data\hub.log（计划任务默认不捕获 stdout，否则零日志）。
$bat = Join-Path $installDir "run-service.cmd"
@"
@echo off
if not exist "%~dp0data" mkdir "%~dp0data"
for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%~dp0hub.env") do (
  if not "%%b"=="" set "%%a=%%b"
)
cd /d "%~dp0"
:loop
"%~dp0yuduan-hub.exe" >> "%~dp0data\hub.log" 2>&1
echo [%date% %time%] yuduan-hub exited, restarting in 5s...
ping -n 6 127.0.0.1 >nul
goto loop
"@ | Set-Content $bat -Encoding ASCII

# D-02 升级停旧：先停运行中的旧任务循环，避免旧进程继续持有旧 exe（替换后跑旧二进制）
# v0.4.9：停旧前先探测——无旧任务/无残留进程时打 [SKIP]，重装在干净机器上不再出现误导性输出
cmd /c "schtasks /Query /TN $TaskName >nul 2>&1"
if ($LASTEXITCODE -eq 0) {
  cmd /c "schtasks /End /TN $TaskName >nul 2>&1"
  Write-Host "==> 已停止旧任务实例（升级替换用）"
} else {
  Write-Host "[SKIP] 无旧计划任务实例（首次部署或已清理）" -ForegroundColor DarkGray
}
# D-08 修复（v0.4.2 实机）：/End 只停 run-service.cmd 守卫循环，其子进程 yuduan-hub.exe
#   可能成为孤儿继续持有 8080/8443（Windows 杀父不杀子）→ 重部署时新 hub 绑不上 8080
#   （回退 8081）或端口占用致确认失败。显式 taskkill 兜底清理任何残留 hub 进程。
$hubProc = Get-Process -Name "yuduan-hub" -ErrorAction SilentlyContinue
if ($hubProc) {
  $pids = ($hubProc | ForEach-Object { $_.Id }) -join ", "
  cmd /c "taskkill /IM yuduan-hub.exe /F >nul 2>&1"
  Write-Host "==> 已终止残留中枢进程（PID: $pids），端口 8080/8443 已释放"
} else {
  Write-Host "[SKIP] 无残留 yuduan-hub 进程（8080/8443 未被占用）" -ForegroundColor DarkGray
}
# v0.4.10（实测报告问题 2）：记录 hub.log 字节偏移——hub.log 是追加写，跨部署残留
# 上一实例的监听/就绪行会让「轮询就绪行」0 秒放行（实锤：本轮 WARN 根因）。
# 此后只扫描偏移之后的新增内容，旧实例的行永远不会误触发就绪判定。
$ydLogPath = Join-Path $installDir "data\hub.log"
$ydLogOffset = 0
if (Test-Path $ydLogPath) { $ydLogOffset = (Get-Item $ydLogPath).Length }

# ---- 注册计划任务（开机自启，SYSTEM 身份）----
# D-01 修复（v0.2.8 实机）：/TR 不得手写 \"$bat\"——PS 5.1 中反斜杠不是转义符。
# D-07 修复（v0.4.2 实机，决定性）：/TR 传含空格路径**必须显式带引号**。
#   v0.2.8 改为「直接传 $bat 让 PS 5.1 自动加引号」，但**本次实机证伪**：PS 5.1 对原生
#   schtasks 传含空格参数并不会自动加引号 → 任务定义存的是无引号
#   `E:\Program Files\...\run-service.cmd` → SYSTEM 以 cmd /c 执行时空格拆开，
#   `E:\Program` 被当命令 → 0x80070002（找不到文件）→ run-service.cmd 从未执行，
#   hub.log 从未创建，服务确认失败（实机：计划任务上次结果 -2147024894）。
#   正确做法：用单引号拼接双引号构造 '"路径"'，作为**单个 argv** 传给 schtasks，
#   任务定义即带引号，SYSTEM 执行 cmd /c "E:\Program Files\...\run-service.cmd" 正确。
# 注册失败必须显式退出（此前无条件打印"已注册"，误导）。
# EAP=Stop 下原生 stderr 会转 terminating error 中断脚本（v0.2.5 实机教训），
# 注册时临时降为 Continue 以读取 $LASTEXITCODE 并给出友好提示，随后恢复。
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$trCmd = '"' + $bat + '"'
schtasks /Create /TN $TaskName /TR $trCmd /SC ONSTART /RU SYSTEM /RL HIGHEST /F | Out-Null
$rcSchtasks = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
if ($rcSchtasks -ne 0) {
  Write-Host "==> ❌ 计划任务注册失败（schtasks exit=$rcSchtasks）：开机自启未生效"
  Write-Host "    常见原因：安装路径含空格/特殊字符、或权限不足。可改用 8.3 短路径或 NSSM 包装。"
  exit 1
}
Write-Host "计划任务 $TaskName 已注册（开机自启，SYSTEM 身份）"

# v0.4.7（实测报告问题 3）：schtasks /Create 默认 DisallowStartIfOnBatteries=true——
# 笔记本用电池开机时 BootTrigger 不触发，中枢不自启。注册后用 ScheduledTasks 模块放开
# 电池启动策略（服务器无电池不受影响；混合办公终端场景兜底）。失败仅 WARN 不阻断部署。
# v0.4.8（实测报告问题 2）：PS 5.1 的 CIM ScheduledTaskSettingsSet 对象只有
#   DisallowStartIfOnBatteries 属性——上一版赋值不存在的 AllowStartIfOnBatteries 属性
#   抛异常进 catch，实际未生效（任务 XML 仍为 true）。改为正确属性名 + 设置后回读断言。
try {
  $ydTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  $ydSettings = $ydTask.Settings
  $ydSettings.DisallowStartIfOnBatteries = $false
  $ydSettings.StopIfGoingOnBatteries = $false
  Set-ScheduledTask -TaskName $TaskName -Settings $ydSettings | Out-Null
  # 回读断言：设置后必须核实任务 XML 真的放开了（防属性名/权限静默失效）
  $ydChk = (Get-ScheduledTask -TaskName $TaskName).Settings
  if ($ydChk.DisallowStartIfOnBatteries -eq $false) {
    Write-Host "电池启动策略已放开（DisallowStartIfOnBatteries=false，已回读核实；笔记本电池开机也会自启）"
  } else {
    Write-Host "[WARN] 电池启动策略设置未生效（回读 DisallowStartIfOnBatteries=$($ydChk.DisallowStartIfOnBatteries)；服务器无影响，笔记本请手动核对）"
  }
} catch {
  Write-Host "[WARN] 电池启动策略设置失败（服务器场景无影响，笔记本场景请手动核对）：$_"
}

# D-01 装完即启动：注册后立即运行，不再要求手动 schtasks /Run
cmd /c "schtasks /Run /TN $TaskName >nul 2>&1"
# 确认以"hub 进程存活"为准（任务状态 Running 不代表 exe 已拉起/未崩溃）。
# v0.4.1 修复：hub 启动初始化（keystore/证书/监听）通常 >3s，原单次 3s 检查会误报
#   "服务启动确认失败"（实机：hub 11:05 已正常起跑并注册 agent，但 3s 窗口没抓到，
#   用户误以为服务没起来）。改为轮询重试（最多 16s），失败时读 hub.log 尾部作证据。
$started = $false
for ($i = 0; $i -lt 8; $i++) {
  Start-Sleep -Seconds 2
  $proc = tasklist /FI "IMAGENAME eq yuduan-hub.exe" 2>$null | Select-String -Pattern "yuduan-hub.exe"
  if ($proc) { $started = $true; break }
}
if ($started) {
  Write-Host "==> 服务已启动（D-01 装完即启动；yuduan-hub.exe 进程存活）"
} else {
  Write-Host "==> ❌ 服务启动确认失败：yuduan-hub.exe 未运行（已轮询约 16s）"
  Write-Host "    排查：1) 看 $installDir\data\hub.log  2) schtasks /Query /TN $TaskName"
  Write-Host "          3) 手动运行 $bat（前台观察报错）  4) 检查 hub.env 的 YUDUAN_HMAC_SECRET 是否配置"
  # 兜底证据：hub 可能已起跑但 tasklist 未及时反映（Defender 扫描/慢初始化），读日志尾部确认
  $logPath = Join-Path $installDir "data\hub.log"
  if (Test-Path $logPath) {
    $logTail = Get-Content $logPath -Tail 6 -ErrorAction SilentlyContinue
    if ($logTail) {
      Write-Host "    ---- hub.log 末尾（最近 6 行，若见「明文中枢监听/TLS 中枢监听」则 hub 实际已起跑）----"
      $logTail | ForEach-Object { Write-Host "    $_" }
    }
  }
}

# ---- 防火墙放行（幂等：先删旧规则再建，重复执行不报错）----
#   TCP 8080  = 明文 http+ws（主端/控制台）
#   TCP 8443  = TLS https+wss（副端）
#   UDP 发现  = 局域网自动发现广播（默认 18242，可配置，由 YUDUAN_DISCOVERY_PORT 覆盖）
# 发现端口以 hub.env 为准（与中枢/同目录副端加载的 env 一致；缺省回退 18242）
$discPort = "18242"
foreach ($line in Get-Content $envFile -ErrorAction SilentlyContinue) {
  if ($line -match '^YUDUAN_DISCOVERY_PORT=(\d+)\s*$') { $discPort = $Matches[1] }
}
Write-Host "==> 防火墙放行 TCP 8080 / TCP 8443 / UDP $discPort"
$rules = @(
  @{ Name = "yuduan-hub-plain";  Proto = "TCP"; Port = "8080" },
  @{ Name = "yuduan-hub-tls";    Proto = "TCP"; Port = "8443" },
  @{ Name = "yuduan-disc-udp";   Proto = "UDP"; Port = "$discPort" }
)
foreach ($r in $rules) {
  netsh advfirewall firewall delete rule name="$($r.Name)" | Out-Null
  netsh advfirewall firewall add rule name="$($r.Name)" dir=in action=allow protocol=$($r.Proto) localport=$($r.Port) | Out-Null
}
Write-Host "==> 防火墙规则就绪（主端/副端/自动发现均可入站）"

# ---- 同机副端联动：密钥自动同步（档位 A 的快速路径；跨机副端走广播 claim 自动获取）----
if ($AgentDir) {
  $agentScript = Join-Path $AgentDir "install-agent.ps1"
  if (-not (Test-Path $agentScript)) { Write-Error "找不到 $agentScript" }
  if (-not $hmacSecret) { Write-Error "既有 hub.env 中未读到 YUDUAN_HMAC_SECRET，无法同步副端" }
  Write-Host "==> 同机副端联动：安装并同步验签密钥"
  & $agentScript -Secret $hmacSecret
} else {
  # 敏感信息打码：完整密钥只落盘在 hub.env（ACL 已收紧），不打印到控制台/日志
  $masked = if ($hmacSecret.Length -gt 8) { $hmacSecret.Substring(0,8) + "…" } else { $hmacSecret }
  Write-Host ""
  Write-Host "副端密钥同步（三选一）："
  Write-Host "  1) 同机部署： .\register-task.ps1 -AgentDir <副端deploy目录>  —— 自动同步，零手动"
  Write-Host "  2) 跨机部署：什么都不填 —— 副端安装后自动广播 claim 获取密钥（中枢 TLS 就绪时走加密通道）"
  Write-Host "  3) 显式指定： .\install-agent.ps1 -Secret $masked（完整密钥见 $envFile，勿截图外传）"
}

# ---- 端到端功能自检（v0.4.4：装完即验，无需用户再查；覆盖用户"登录网络错误"类问题）----
# 原理：进程存活（上面确认）≠ 功能可用。这里逐环节验证「控制台页面 / 鉴权脚本 / 登录接口」，
# 并利用中枢新增的 [http] 访问日志判定请求是否到达后端。全部通过才提示"可登录"。
Write-Host ""
Write-Host "==> 端到端自检（① 控制台页面 ② 鉴权脚本 ③ 登录接口）"
$base = "http://127.0.0.1:8080"
$allPass = $true

# v0.4.8（实测报告问题 1）：实测「部署完成 → 登录可用」竞态窗口 ~40s（旧进程残留/慢
# 初始化），此前 21s 盲重试仍不足。hub 启动时打印就绪行，先轮询再测登录。
# v0.4.10（实测报告问题 2）：改为按字节偏移只扫【本轮新增】日志——上一实例残留的
# 监听行曾使 Tail 匹配 0 秒放行（③ WARN 根因）；hub 侧就绪行也已移到 Serve 前（真正可用）。
# 兼容：旧版本 hub 无就绪行，匹配新增内容里的监听行 / ASCII 片段（:8080）兜底。
# v0.4.11（实测报告问题 1）：v0.4.10 偏移量方案被新缺陷绕过——ReadAllBytes 以
# FileShare.Read 打开，与 run-service.cmd 的 >> 重定向写句柄共享冲突，每 2s 抛一次
# IOException 又被空 catch{} 吞掉，60s 轮询静默全失败。改为显式 FileStream+
# FileShare.ReadWrite 与写端共存；catch 输出轮次与异常诊断，禁止静默吞异常。
$readyWaited = $false; $readyHow = ""; $readyErrCount = 0
for ($i = 0; $i -lt 30; $i++) {
  if (Test-Path $ydLogPath) {
    try {
      $ydFs = [System.IO.File]::Open($ydLogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
      try {
        $ydLen = $ydFs.Length
        if ($ydLen -gt $ydLogOffset) {
          $ydBuf = New-Object byte[] ($ydLen - $ydLogOffset)
          [void]$ydFs.Seek($ydLogOffset, [System.IO.SeekOrigin]::Begin)
          [void]$ydFs.Read($ydBuf, 0, $ydBuf.Length)
          $ydNew = [System.Text.Encoding]::UTF8.GetString($ydBuf)
          if ($ydNew -match "内置 admin 账号就绪") { $readyWaited = $true; $readyHow = "admin seed 就绪行"; break }
          if ($ydNew -match "明文中枢监听|:8080") { $readyWaited = $true; $readyHow = "监听行"; break }
        }
      } finally { $ydFs.Dispose() }
    } catch {
      $readyErrCount++
      if ($readyErrCount -le 3 -or $readyErrCount % 5 -eq 0) {
        Write-Host "  [自检轮询] 第 $i 轮读取 hub.log 失败（将继续重试）: $($_.Exception.Message)"
      }
    }
  }
  Start-Sleep -Seconds 2
}
if ($readyWaited) {
  Write-Host "==> hub 就绪（hub.log 本轮新增内容确认：$readyHow，等待 $([int]($i*2))s）"
} else {
  Write-Host "[WARN] 60s 内未在 hub.log 本轮新增内容中观察到就绪行（旧版本 hub 无此行属正常），继续自检"
}

# v0.4.35 修复（一键部署成功率实测矩阵 #4）：自检端口必须取中枢【实际绑定】端口，而非硬编码 8080。
# 中枢在 8080 被占用时会回退 8081/8082/8083/18080（main.go listenPlainOrFallback），旧逻辑硬编码
# 8080 会让自检三项全 HTTP 000 却仍误判成功并提示错误地址。从 hub.log 本轮新增内容解析真实端口：
# 优先「明文中枢监听 :PORT」（main.go:364），其次回退提示「自动改用 :PORT」。
$actualPort = "8080"
if (Test-Path $ydLogPath) {
  try {
    $ydFs = [System.IO.File]::Open($ydLogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $ydLen = $ydFs.Length
      if ($ydLen -gt $ydLogOffset) {
        $ydBuf = New-Object byte[] ($ydLen - $ydLogOffset)
        [void]$ydFs.Seek($ydLogOffset, [System.IO.SeekOrigin]::Begin)
        [void]$ydFs.Read($ydBuf, 0, $ydBuf.Length)
        $ydNew = [System.Text.Encoding]::UTF8.GetString($ydBuf)
        if ($ydNew -match '明文中枢监听 :(\d+)') { $actualPort = $Matches[1] }
        elseif ($ydNew -match '自动改用 :(\d+)') { $actualPort = $Matches[1] }
      }
    } finally { $ydFs.Dispose() }
  } catch {}
}
$base = "http://127.0.0.1:$actualPort"
if ($actualPort -ne "8080") {
  Write-Host "==> 自检端口：中枢实际绑定 :$actualPort（8080 被占用已回退），自检探针与提示均使用该端口"
}

# ① 控制台页面 GET /
$htmlCode = & curl.exe -s -m 5 -o "$env:TEMP\yd_console.html" -w "%{http_code}" "$base/"
if ($htmlCode -eq "200") {
  # v0.4.5：显式 -Encoding UTF8。PS 5.1 无该参数时按系统 ANSI(GBK) 解码 UTF-8 页面，
  # 中文匹配串全失 → 误报 WARN（实机测试报告问题 4）。
  $page = Get-Content "$env:TEMP\yd_console.html" -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  if ($page -match "御端|yuduan|管理控制台|<title>") { Write-Host "[PASS] ① 控制台页面 GET / -> 200" }
  else { Write-Host "[WARN] ① GET / -> 200 但内容异常（可能非本平台页面，请人工确认）" }
} else { Write-Host "[FAIL] ① 控制台页面 GET / -> $htmlCode（预期 200）"; $allPass = $false }

# ② 鉴权脚本 GET /auth.js
$authCode = & curl.exe -s -m 5 -o NUL -w "%{http_code}" "$base/auth.js"
if ($authCode -eq "200") { Write-Host "[PASS] ② 鉴权脚本 GET /auth.js -> 200" }
else { Write-Host "[FAIL] ② 鉴权脚本 GET /auth.js -> $authCode（预期 200）"; $allPass = $false }

# ③ 登录接口 POST /api/v1/login（admin/admin123；401=鉴权正常仅密码非默认，不算失败）
# v0.4.5：部署瞬间服务可能尚未就绪（监听已起、路由/存储初始化未完）→ 单次请求误报 401/000
# v0.4.7（实测报告问题 1）：原重试遇 401 即 break，竞态窗口内 401 直接判 WARN——重试形同虚设。
# 改为仅 code=0 提前跳出；401/000 一律重试（7 次 × 3s ≈ 21s，覆盖启动竞态）。
# v0.4.14（实测报告问题 3）：hub 侧就绪行已改为「回环 HTTP 真实登录探针」后才打印，
# 正常路径就绪即真实可登录；此处重试预算仍提升到 20 次 × 3s ≈ 60s 作为双保险，
# 覆盖「旧实例残留占用 8080」等 hub 自身无法感知的现场情况。
# v0.4.16（实测报告问题 1，七轮误报根修）：2026-11-04 对照实验定位——v0.4.8→v0.4.14 持续
# 七轮的「③ WARN」根本不是中枢就绪竞态，而是 PS 5.1 以 -d $var 向 curl.exe 传 JSON 时
# 双引号被吞，实际 body 为非法 JSON → 中枢按鉴权返回 401 → 恒 WARN。改为把请求体写入
# 临时文件后用 --data-binary "@file" 发送（引号原样送达）；失败时打印实际发出的 body。
# 竞态耗尽后仍 401 → WARN（admin 密码非默认，鉴权正常）；耗尽后仍 000 → FAIL。
$loginBody = '{"username":"admin","password":"admin123"}'
$loginBodyFile = "$env:TEMP\yd_login_body.json"
Set-Content -Path $loginBodyFile -Value $loginBody -Encoding ASCII -NoNewline
$loginCode = $null; $loginJson = $null
for ($i = 1; $i -le 20; $i++) {
  $loginCode = & curl.exe -s -m 5 -o "$env:TEMP\yd_login.json" -w "%{http_code}" -X POST "$base/api/v1/login" -H "Content-Type: application/json" --data-binary "@$loginBodyFile"
  $loginJson = Get-Content "$env:TEMP\yd_login.json" -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  if ($loginCode -eq "200" -and $loginJson -match '"code":0') { break }
  if ($i -lt 20) { Start-Sleep -Seconds 3 }
}
if ($loginCode -eq "200" -and $loginJson -match '"code":0') {
  Write-Host "[PASS] ③ 登录接口 POST /api/v1/login -> 200 code=0（token 已签发，可登录）"
} elseif ($loginCode -eq "200" -and $loginJson -match '"code":401') {
  Write-Host "[WARN] ③ 登录接口可达（401=鉴权正常，admin 密码非默认或已改密；不影响部署，用实际账号登录）"
} else {
  Write-Host "[FAIL] ③ 登录接口 POST /api/v1/login -> HTTP $loginCode 响应 $loginJson"
  Write-Host "    实际发出 body: $(Get-Content $loginBodyFile -Raw -ErrorAction SilentlyContinue)（若与上行 JSON 不一致则为传参缺陷，请反馈）"
  $allPass = $false
}

if ($allPass) {
  Write-Stage "==> ✅ 自检全部通过：控制台可访问、可登录。浏览器打开 http://<中枢IP>:$actualPort" -Color "Green"
  # v0.4.44（V10a 观测提示）：默认（LAN）形态不自动信任 XFF——source_addr 记录直接对端；
  # 中枢若置于反代/CF 隧道后，须开启可信代理，否则台账源地址塌缩为 127.0.0.1（第 24 轮 V10a）。
  Write-Host "[提示] 当前为内网/默认形态：未开启 YUDUAN_TRUST_PROXY，source_addr 记录直接对端地址。"
  Write-Host "       中枢置于反代/CF 隧道后请改用 -Public（自动置 YUDUAN_TRUST_PROXY=1）或手工设置该变量。"
  # v0.4.35（一键部署成功率实测矩阵 #4）：落盘实际绑定端口，供 deploy.bat 末尾提示用，
  # 避免在 8080 被占用回退到 8081/8082/8083/18080 时仍打印错误的 8080 地址。
  try { Set-Content -Path (Join-Path $installDir "data\hub-port.txt") -Value $actualPort -Encoding ASCII -ErrorAction SilentlyContinue } catch {}
  # v0.4.36（#6）：机器可读成功结论（供外部编排判定部署结果）。
  Write-DeployResult -Success $true -HubPort ([int]$actualPort) -Reason "OK" -Detail "自检全部通过" | Out-Null
} else {
  Write-Host "==> ❌ 自检存在失败项（见上方 [FAIL]），排查："
  Write-Host "    1) 看 $installDir\data\hub.log 末尾——若请求行缺 [http] 记录则请求未到达（进程/端口/防火墙）；"
  Write-Host "      有 [http] 行则后端已处理（看 status 与响应 code）。"
  Write-Host "    2) netstat -ano | findstr :$actualPort 确认监听；tasklist | findstr yuduan-hub 确认进程。"
  # v0.4.35 修复（一键部署成功率实测矩阵 #4）：自检失败必须显式非零退出，否则 deploy.bat
  # 会误判成功并返回 0（port8080-occupied 用例曾因此 falsely 成功并提示错误地址）。
  # v0.4.36（#5）：结构化原因码 SELFCHECK_FAIL + 机器可读结论（#6）。
  Fail-Deploy -Reason "SELFCHECK_FAIL" -Detail "自检存在失败项，部署未达可用状态（详见上方 [FAIL]）。"
}

# =====================================================================
# 公网部署模式（v0.4.27）：在基础 LAN 部署完成之上，额外完成
#   ① 证书准备（acme 自动签发 / self 私有 CA 自签）
#   ② 写公网 env（YUDUAN_NET_MODE / TLS / PUBLIC_ADDR / DOMAIN / LOGIN_GUARD）
#   ③ 防火墙（确保 8443 放行；ACME 仅临时放开 80，签发后立即撤销）
#   ④ 重启计划任务使新 env 生效
#   ⑤ 打印副端 wss 端点与信任锚（best-effort）
# 不改变 LAN 默认行为；未传 -Public 时本段整体跳过。
# =====================================================================
if ($Public) {
  $certDir = Join-Path $installDir "certs"
  New-Item -ItemType Directory -Force -Path $certDir | Out-Null
  $certPath = $null; $keyPath = $null; $pin = ""

  if ($CertMode -eq "acme") {
    # ---- ACME：临时放行 :80 供 http-01 挑战 ----
    netsh advfirewall firewall delete rule name="yuduan-acme-80" | Out-Null
    netsh advfirewall firewall add rule name="yuduan-acme-80" dir=in action=allow protocol=TCP localport=80 | Out-Null
    Write-Host "==> [公网/ACME] 已临时开放 TCP :80 供证书签发（签发后撤销）"
    # ---- 定位 yuduan-acme（同目录优先，其次 PATH）----
    $acmeExe = $null
    foreach ($cand in @((Join-Path $installDir "yuduan-acme.exe"), (Join-Path $installDir "yuduan-acme"), "yuduan-acme", "yuduan-acme.exe")) {
      if (Get-Command $cand -ErrorAction SilentlyContinue) { $acmeExe = $cand; break }
    }
    if (-not $acmeExe) { Write-Error "未找到 yuduan-acme（请置于中枢目录或纳入 PATH）" }
    # ---- 签发（ACME 默认产出 certs/acme.fullchain.pem + certs/acme.key）----
    $acmeArgs = @("issue", "--domain", $Domain, "--email", $Email)
    if ($Staging) { $acmeArgs += "--staging" }
    $acmeOut = & $acmeExe @acmeArgs 2>&1 | Out-String
    Write-Host $acmeOut
    if ($acmeOut -match '(?im)(?:pin|spki|sha-?256)[^\n]*?([0-9a-f]{64})') { $pin = $Matches[1] }
    # ---- 撤销临时 :80 ----
    netsh advfirewall firewall delete rule name="yuduan-acme-80" | Out-Null
    Write-Host "==> [公网/ACME] 已撤销临时 TCP :80 规则" -ForegroundColor Green
    $certPath = Join-Path $certDir "acme.fullchain.pem"
    $keyPath  = Join-Path $certDir "acme.key"
  } else {
    # ---- self：复用现有 prepare-public-cert.*（私有 CA 签发）----
    $pubPs1 = Join-Path $PSScriptRoot "prepare-public-cert.ps1"
    $pubSh  = Join-Path $PSScriptRoot "prepare-public-cert.sh"
    $pubOut = ""
    if (Test-Path $pubPs1) {
      $pubOut = & powershell -NoProfile -ExecutionPolicy Bypass -File $pubPs1 -DnsNames $Domain -CertDir $certDir 2>&1 | Out-String
    } elseif (Test-Path $pubSh) {
      $pubOut = & bash "$pubSh" -dns "$Domain" -dir "$certDir" 2>&1 | Out-String
    } else {
      Write-Error "未找到 prepare-public-cert.ps1 / .sh（请随包提供）"
    }
    Write-Host $pubOut
    if ($pubOut -match '(?im)(?:pin|spki|sha-?256)[^\n]*?([0-9a-f]{64})') { $pin = $Matches[1] }
    $certPath = Join-Path $certDir "chain.pem"
    $keyPath  = Join-Path $certDir "key.pem"
  }

  # ---- 校验产物 ----
  if (-not (Test-Path $certPath) -or (Get-Item $certPath).Length -eq 0) {
    Write-Error "证书产物缺失或为空：$certPath"
  }
  if (-not (Test-Path $keyPath) -or (Get-Item $keyPath).Length -eq 0) {
    Write-Error "证书私钥产物缺失或为空：$keyPath"
  }

  # ---- 写公网 env（幂等 upsert，绝不改动既有 HMAC/PEPPER/SIGN_SEED/DB_DSN）----
  Set-HubEnvLine $envFile "YUDUAN_NET_MODE" "public"
  Set-HubEnvLine $envFile "YUDUAN_TLS_ADDR" ":8443"
  Set-HubEnvLine $envFile "YUDUAN_TLS_CERT" $certPath
  Set-HubEnvLine $envFile "YUDUAN_TLS_KEY" $keyPath
  Set-HubEnvLine $envFile "YUDUAN_PUBLIC_ADDR" "https://${Domain}:8443"
  Set-HubEnvLine $envFile "YUDUAN_PUBLIC_DOMAIN" $Domain
  Set-HubEnvLine $envFile "YUDUAN_LOGIN_GUARD" "1"
  # v0.4.41（N3）：公网/隧道形态中枢必过反代或 CF 隧道，源地址来自 XFF 首段而非
  # RemoteAddr；不采信则 source_addr 塌缩为 127.0.0.1（V10 实测）。公网形态强制开启
  # 可信代理（XFF 仅反代可写，安全），使台账服务端观测地址可信。
  Set-HubEnvLine $envFile "YUDUAN_TRUST_PROXY" "1"
  # 重写会重置 ACL，重新收紧到 SYSTEM + Administrators（与基础段一致）
  icacls $envFile /inheritance:r /grant:r "SYSTEM:(R,W)" "Administrators:(R,W)" | Out-Null
  Write-Host "==> [公网] 已写入公网配置到 $envFile（NET_MODE=public, TLS :8443）"

  # ---- 防火墙确保 :8443 放行（基础段已建 yuduan-hub-tls，此处幂等确认）----
  netsh advfirewall firewall delete rule name="yuduan-hub-tls" | Out-Null
  netsh advfirewall firewall add rule name="yuduan-hub-tls" dir=in action=allow protocol=TCP localport=8443 | Out-Null

  # ---- 重启计划任务使新 env 生效 ----
  cmd /c "schtasks /End /TN $TaskName >nul 2>&1"
  Start-Sleep -Seconds 1
  # v0.4.40：与基础流程 D-08 同口径——/End 可能留下孤儿 yuduan-hub.exe 占住
  # :8080/:8443，导致 /Run 拉起的新进程端口冲突、公网 env 不生效。显式兜底清理。
  cmd /c "taskkill /IM yuduan-hub.exe /F >nul 2>&1"
  Start-Sleep -Milliseconds 500
  cmd /c "schtasks /Run /TN $TaskName >nul 2>&1"

  # ---- 副端公开端点（best-effort）----
  $agentHub = "wss://${Domain}:8443/ws/agent"
  Write-Host ""
  Write-Host "=============================================================="
  Write-Host " 公网部署完成（net mode = public）"
  Write-Host "=============================================================="
  Write-Host " 副端联动（在副端环境 / install-agent 时设置其一）："
  Write-Host "   YUDUAN_HUB=$agentHub"
  if ($CertMode -eq "self") {
    Write-Host "   YUDUAN_TLS_CAFILE=$(Join-Path $certDir 'ca.pem')   <- 带外预置（私有 CA 根）"
    if ($pin) { Write-Host "   YUDUAN_TLS_PIN=$pin" }
  } else {
    Write-Host "   （ACME 受信任证书：副端无需 PIN/CAFILE，信任系统根即可）"
  }
  Write-Host " 主端登录页： https://${Domain}:8443"
  Write-Host "=============================================================="
}
