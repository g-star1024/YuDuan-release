# 御端（YuDuan）副端 —— Windows 服务安装/卸载脚本（sc.exe 创建系统服务）。
#
# 用法（管理员 PowerShell）：
#   ./deploy/windows/install-agent.ps1               # 安装并启动
#   ./deploy/windows/install-agent.ps1 -Uninstall    # 停止并移除
#
# 前置：先构建二进制（Windows 主机或交叉编译）：
#   rustup target add x86_64-pc-windows-msvc
#   rustc -O --target x86_64-pc-windows-msvc src/main.rs -o target/agent.exe
# 注意（v0.4.40）：中枢端点优先从 %ProgramData%\YuDuan\agent-hub.json 读取，
#       该文件由 yuduan-agent.exe --set-hub <url> 写入，免重启即可热切换；
#       本脚本【不传 -HubUrl】时保留该文件（重装不抹掉运维已设的远端端点），
#       【传 -HubUrl】时清除该文件并改用 Machine 作用域的 YUDUAN_HUB。
#       日常改端点推荐直接用 --set-hub，不必重跑安装脚本。
# 可选 -OpenSsl：wss 生产必填，指向系统 openssl（如 Git for Windows 自带
#       C:\Program Files\Git\usr\bin\openssl.exe）；走明文 ws 无需设置。
# 示例：./install-agent.ps1 -HubUrl wss://hub.yuduan.internal:8443/ws/agent `
#              -Secret <HMAC> -OpenSsl "C:\Program Files\Git\usr\bin\openssl.exe"
#
# ── 副端驻留机制（2026-10-27 v0.1.3）─────────────────────────────
# 本脚本创建的即为「系统服务」：开机自启（start= auto）+ 失败自动重启
# （sc.exe failure ... actions=restart/5000）= 断联/崩溃守卫。
# 被控端二进制内部已实现 StartServiceCtrlDispatcherW 握手（win_service.rs），
# SCM 拉起后正确上报运行状态，不再出现 1053「服务未及时响应」。
# 此外二进制本身支持免 PowerShell 的原生安装模式（sc.exe 被策略禁用时的兜底）：
#   yuduan-agent.exe --install     # 创建服务（开机自启+失败自动重启），无需 ps1
#   yuduan-agent.exe --uninstall   # 停止并删除服务
#   yuduan-agent.exe --status      # 查询服务状态 + 端点/来源/最近错误（普通用户可读）
#   yuduan-agent.exe --set-hub <url>  # 切换中枢端点（免重启热切换，需管理员）
#   yuduan-agent.exe --help        # 查看全部管理命令
#   （服务名可用 YUDUAN_SERVICE_NAME 覆盖，默认 yuduan-agent）

param(
    [switch]$Uninstall,
    # 可选：覆盖脚本顶部的中枢地址/密钥，免改文件即可按现场部署
    [string]$HubUrl,
    [string]$Secret,
    # 可选：原生编码器 DLL 路径（阶段 4 能力依赖；不传则副端诚实回退 RAW_RGBA）
    [string]$EncoderLib,
    # 可选：系统 openssl 路径（wss 生产必填，如 Git for Windows 自带
    #       C:\Program Files\Git\usr\bin\openssl.exe；走明文 ws 无需设置）
    [string]$OpenSsl
)

$ErrorActionPreference = "Stop"

$ServiceName = "yuduan-agent"
$DisplayName = "YuDuan Agent"
$BinDst     = "$env:ProgramFiles\YuDuan\yuduan-agent.exe"
$LogFile    = "$env:ProgramData\YuDuan\agent.log"

# —— 按现场环境修改（也可用命令行参数覆盖）——
# 默认【不写死】中枢地址：副端启动时 UDP 广播自动发现（§8.4，安装即注册），
# 中枢 IP 变更（网段漂移/DHCP 续租）时断线重连会自动重探。
# 仅跨网段广播被隔离等场景才需要显式指定：./install-agent.ps1 -HubUrl ws://<IP>:8080/ws/agent
$SetHubExplicitly = [bool]$HubUrl
if (-not $Secret) {
    # 自动从中枢配置读取验签密钥（同机部署零手动；档位 A 快速路径）。
    # 探测顺序：本脚本目录旁 hub.env（副端包与中枢包同目录/相邻部署）→
    # ProgramData\yuduan-hub\hub.env（旧版中枢布局兼容）。
    $candidateEnvs = @(
        (Join-Path $PSScriptRoot "hub.env"),
        "$env:ProgramData\yuduan-hub\hub.env"
    )
    foreach ($envPath in $candidateEnvs) {
        if (Test-Path $envPath) {
            foreach ($line in Get-Content $envPath) {
                if ($line -match '^YUDUAN_HMAC_SECRET=(.+)$') { $Secret = $Matches[1].Trim(); break }
            }
            if ($Secret) {
                Write-Host "==> 已从中枢配置自动读取验签密钥：$envPath（零手动同步）"
                break
            }
        }
    }
}
if (-not $Secret) {
    # 兜底：跨机部署且未提供密钥。副端首启后仍可经广播 claim 自动获取
    # （中枢在线时），此处仅保留占位以不破坏既有安装流程。
    $Secret = "CHANGE-ME-AT-DEPLOY"
    Write-Host "==> ⚠️ 未提供 -Secret 且未找到中枢配置：先以占位密钥安装；"
    Write-Host "    副端启动后将自动广播 claim 获取真实密钥（中枢 HMAC_ENFORCE=1 时占位密钥期间指令会被拒）"
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Error "请以管理员身份运行 PowerShell"
    exit 1
}

if ($Uninstall) {
    Write-Host "==> 停止并移除服务 $ServiceName"
    # 停止/删除同样做 sc.exe → cmdlet 回退（受控环境常禁用 sc.exe）
    try {
        sc.exe stop $ServiceName | Out-Null
        Start-Sleep -Seconds 2
        sc.exe delete $ServiceName | Out-Null
    } catch {
        Write-Host "==> sc.exe 不可用，回退 Stop-Service/Remove-Service"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        # PS 5.1 无 Remove-Service cmdlet，改用 sc.exe delete 或 WMI
        try { sc.exe delete $ServiceName | Out-Null } catch {
            $svcObj = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($svcObj) { $svcObj.Delete() | Out-Null }
        }
    }
    Remove-Item $BinDst -Force -ErrorAction SilentlyContinue
    # 两级作用域彻底清除（setx 不带 /M 写的是 User 级，服务读不到——历史 bug 根源）
    foreach ($scopePath in @("HKCU\Environment", "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment")) {
        foreach ($n in @("YUDUAN_HUB", "YUDUAN_HMAC_SECRET", "YUDUAN_ENCODER_LIB", "YUDUAN_OPENSSL")) {
            reg delete $scopePath /v $n /f 2>$null | Out-Null
        }
    }
    # v0.4.40：卸载属彻底移除，agent-hub.json（--set-hub 端点）与
    # agent-status.json（运行快照）一并清除；重装路径（下方）则刻意保留端点，
    # 二者语义不同——报告 M8 的痛点正是重装把远端端点抹掉。
    foreach ($cfg in @("agent-config.json", "agent-hub.json", "agent-status.json")) {
        Remove-Item (Join-Path "$env:ProgramData\YuDuan" $cfg) -Force -ErrorAction SilentlyContinue
    }
    Write-Host "==> 已卸载（服务/环境变量/claim 配置/端点/状态均已清除；日志保留：$LogFile）"
    exit 0
}

# 二进制位置：发布包布局（同目录 yuduan-agent.exe）优先；否则回退开发目录布局
# （脚本在 rust/agent/deploy/windows/，target/ 在 rust/agent/target/，上溯三级）。
$src = Join-Path $PSScriptRoot "yuduan-agent.exe"
if (-not (Test-Path $src)) {
    $src = Join-Path $PSScriptRoot "..\..\target\agent.exe"
}
if (-not (Test-Path $src)) {
    Write-Error "未找到副端二进制（同目录 yuduan-agent.exe 或 $PSScriptRoot\..\..\target\agent.exe）；发布包请整体解压后再运行本脚本"
    exit 1
}

Write-Host "==> 安装二进制 -> $BinDst"
New-Item -ItemType Directory -Force -Path (Split-Path $BinDst) | Out-Null
Copy-Item $src $BinDst -Force

# —— 先清后写（一键部署核心）：旧服务/两级作用域旧环境变量/claim 落盘配置全部清零，
#    再按本次部署意图重新生成。杜绝旧部署残留（如 YUDUAN_HUB 指向不存在域名）导致连不上。——
Write-Host "==> 清除旧配置（旧服务 / User+Machine 两级 YUDUAN_* 环境变量 / claim 落盘）"
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    try { sc.exe stop $ServiceName | Out-Null } catch {}
    # v0.4.40 P2-5：不再固定 Start-Sleep 2s 就 sc delete。旧服务可能停在
    # STOP_PENDING（主循环阻塞在在线会话里，STOP 后 PID 不变），此时 delete 会撞
    # ERROR_SERVICE_MARKED_DELETE 1072 / 60s 窗口。改为有界轮询等真正 Stopped，
    # 最多 15s；超时才继续（后续由副端 --setup 内的残留清理兜底）。
    $deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 500
        $svcState = (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status
    } while ($svcState -and $svcState -ne 'Stopped' -and (Get-Date) -lt $deadline)
    try { sc.exe delete $ServiceName | Out-Null } catch { }
    Start-Sleep -Seconds 1
}
foreach ($scopePath in @("HKCU\Environment", "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment")) {
    foreach ($n in @("YUDUAN_HUB", "YUDUAN_HMAC_SECRET", "YUDUAN_ENCODER_LIB", "YUDUAN_OPENSSL")) {
        reg delete $scopePath /v $n /f 2>$null | Out-Null
    }
}
# 只删引导密钥配置 agent-config.json（DPAPI 加密的 HMAC 密钥）。
# v0.4.40：**保留 agent-hub.json**（--set-hub 写入的运维中枢端点）——重装脚本
# 不应抹掉远端/隧道中枢设置；端点由副端每轮重连从该文件读取，优先级高于 env。
Remove-Item "$env:ProgramData\YuDuan\agent-config.json" -Force -ErrorAction SilentlyContinue

Write-Host "==> 写入新配置（一律 Machine 作用域：服务/SYSTEM 与所有用户一致可读）"
# 统一用 setx /M（Machine 级）。历史版本不带 /M 写了 User 级，导致服务读不到、
# 且前台/服务两套值互相打架——此处连同两级残留一并清零后重写，根治。
$hubFile = Join-Path "$env:ProgramData\YuDuan" "agent-hub.json"
if ($SetHubExplicitly) {
    # v0.4.40：端点优先级 agent-hub.json > YUDUAN_HUB > UDP 发现。本次显式传
    # -HubUrl 表示要覆盖端点，故先清掉 --set-hub 写入的持久化端点文件，
    # 否则旧文件会压过新 env，出现「改了 -HubUrl 却不生效」。
    if (Test-Path $hubFile) {
        Remove-Item $hubFile -Force -ErrorAction SilentlyContinue
        Write-Host "==> 已清除旧持久化端点 agent-hub.json（本次 -HubUrl 覆盖）"
    }
    setx /M YUDUAN_HUB $HubUrl | Out-Null
    Write-Host "==> 已写入 YUDUAN_HUB=$HubUrl（显式指定，跳过自动发现）"
} else {
    if (Test-Path $hubFile) {
        Write-Host "==> 检出 --set-hub 持久化端点：$hubFile（保留，优先级高于 env / UDP 发现）"
    }
    Write-Host "==> 未指定 -HubUrl：保留已设端点；否则由副端 UDP 广播自动发现中枢（安装即注册）"
}
setx /M YUDUAN_HMAC_SECRET $Secret | Out-Null
# wss：v0.2.2+ 副端自动探测 Git for Windows / OpenSSL-Win64 等常见路径的 openssl，
# 一般无需显式指定；openssl 装在非常规位置时才用 -OpenSsl 指向。
if ($OpenSsl) {
    setx /M YUDUAN_OPENSSL $OpenSsl
    Write-Host "==> 已写入 YUDUAN_OPENSSL=$OpenSsl（wss 将用此二进制做 TLS 管道）"
} else {
    Write-Host "==> 未指定 -OpenSsl：wss 自动探测系统 openssl；探测不到时走明文 ws"
}
# 原生编码器 DLL（阶段 4 能力依赖）：未指定且默认路径不存在时，副端会诚实回退 RAW_RGBA
if (-not $EncoderLib) {
    $EncoderLib = "$env:TEMP\yuduan_enc_mf.dll"
}
if (Test-Path $EncoderLib) {
    setx /M YUDUAN_ENCODER_LIB $EncoderLib | Out-Null
    Write-Host "==> 已写入 YUDUAN_ENCODER_LIB=$EncoderLib"
} else {
    Write-Host "==> 警告：未找到 MF 编码器 $EncoderLib，副端将诚实回退 RAW_RGBA"
}

Write-Host "==> 创建服务（开机自启，失败自动重启）"
# 注意：sc.exe 的 = 后空格是语法要求
#
# ⚠️ 路径含空号的引号处理：这里用 ('"' + $Var + '"') 字符串拼接，
#    不要用反引号转义写法 `"`"$Var`"" —— 该写法在中文 Windows 的
#    Windows PowerShell 5.1（UTF-8 无 BOM 脚本按 ANSI 读取）下会报
#    「字符串缺少终止符」，整个脚本无法解析（实机安装阶段 5 时发现）。
#
# ⚠️ 创建方式：优先 sc.exe（可写 failure 恢复策略）；
#    若 sc.exe 被安全策略/受控环境禁用，回退到 PowerShell 原生
#    New-Service（仍能建服务，只是失败恢复策略需另行设置）。
$binPathQuoted = '"' + $BinDst + '"'
$displayQuoted = '"' + $DisplayName + '"'
$created = $false
try {
    $create = sc.exe create $ServiceName binPath= $binPathQuoted start= auto DisplayName= $displayQuoted obj= "LocalSystem"
    if ($LASTEXITCODE -eq 0) {
        $created = $true
        # 崩溃恢复策略：失败后 5s 重启
        sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    }
} catch {
    Write-Host "==> sc.exe 不可用（$($_.Exception.Message)），回退 New-Service"
}
if (-not $created) {
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        # PS 5.1 无 Remove-Service cmdlet，用 WMI 删
        $svcObj = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($svcObj) { $svcObj.Delete() | Out-Null }
        Start-Sleep -Seconds 2
    }
    New-Service -Name $ServiceName -BinaryPathName $binPathQuoted `
                -DisplayName $DisplayName -StartupType Automatic | Out-Null
    Write-Host "==> 已用 New-Service 创建（崩溃恢复策略未设置）"
}

Write-Host "==> 启动服务"
try {
    sc.exe start $ServiceName | Out-Null
} catch {
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 3
$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host ("==> 完成。状态：{0} = {1}（{2}）" -f $svc.Name, $svc.Status, $svc.StartType)
} else {
    Write-Host "==> 完成（未查询到服务状态）"
}
Write-Host "==> 日志路径：$LogFile（副端 stderr 重定向见 README）"
