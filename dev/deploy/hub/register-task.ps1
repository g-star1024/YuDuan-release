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
#   5. 防火墙放行：自动放行 TCP 8080（明文）/ TCP 8443（TLS）/ UDP 18242（发现）。
#   6. 同机副端联动：-AgentDir 指向副端 deploy 目录时，自动调用
#      install-agent.ps1 -Secret <HMAC> —— 密钥自动同步，副端零手动填写。
#
# 用法（管理员 PowerShell，cd 到中枢安装目录）：
#   .\register-task.ps1                       # 生成配置 + 注册自启服务
#   .\register-task.ps1 -AgentDir D:\yuduan-agent\deploy\windows
#   .\register-task.ps1 -Remove               # 卸载服务（配置保留）
param(
  [switch]$Remove,
  # 重置：删除既有 hub.env 重新生成全套密钥（副端需重装以重新 claim）
  [switch]$ResetConfig,
  [string]$TaskName = "YuDuanHub",
  # 可选：同机副端部署目录（含 install-agent.ps1）；提供则自动同步密钥
  [string]$AgentDir
)
$ErrorActionPreference = "Stop"

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
#   UDP 18242 = 局域网自动发现广播
Write-Host "==> 防火墙放行 TCP 8080 / TCP 8443 / UDP 18242"
$rules = @(
  @{ Name = "yuduan-hub-plain";  Proto = "TCP"; Port = "8080" },
  @{ Name = "yuduan-hub-tls";    Proto = "TCP"; Port = "8443" },
  @{ Name = "yuduan-disc-udp";   Proto = "UDP"; Port = "18242" }
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
# 竞态耗尽后仍 401 → WARN（admin 密码非默认，鉴权正常）；耗尽后仍 000 → FAIL。
$loginBody = '{"username":"admin","password":"admin123"}'
$loginCode = $null; $loginJson = $null
for ($i = 1; $i -le 20; $i++) {
  $loginCode = & curl.exe -s -m 5 -o "$env:TEMP\yd_login.json" -w "%{http_code}" -X POST "$base/api/v1/login" -H "Content-Type: application/json" -d $loginBody
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
  $allPass = $false
}

if ($allPass) {
  Write-Host "==> ✅ 自检全部通过：控制台可访问、可登录。浏览器打开 http://<中枢IP>:8080"
} else {
  Write-Host "==> ❌ 自检存在失败项（见上方 [FAIL]），排查："
  Write-Host "    1) 看 $installDir\data\hub.log 末尾——若请求行缺 [http] 记录则请求未到达（进程/端口/防火墙）；"
  Write-Host "      有 [http] 行则后端已处理（看 status 与响应 code）。"
  Write-Host "    2) netstat -ano | findstr :8080 确认监听；tasklist | findstr yuduan-hub 确认进程。"
}
