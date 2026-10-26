# 御端（YuDuan）副端 —— Windows 服务安装/卸载脚本（sc.exe 创建系统服务）。
#
# 用法（管理员 PowerShell）：
#   ./deploy/windows/install-agent.ps1               # 安装并启动
#   ./deploy/windows/install-agent.ps1 -Uninstall    # 停止并移除
#
# 前置：先构建二进制（Windows 主机或交叉编译）：
#   rustup target add x86_64-pc-windows-msvc
#   rustc -O --target x86_64-pc-windows-msvc src/main.rs -o target/agent.exe
# 注意：安装后如需修改中枢地址/验签密钥，改下面 $HubUrl / $Secret 后重跑本脚本；
#       变量写在计算机作用域（Machine），服务重启后生效。

param(
    [switch]$Uninstall,
    # 可选：覆盖脚本顶部的中枢地址/密钥，免改文件即可按现场部署
    [string]$HubUrl,
    [string]$Secret,
    # 可选：原生编码器 DLL 路径（阶段 4 能力依赖；不传则副端诚实回退 RAW_RGBA）
    [string]$EncoderLib
)

$ErrorActionPreference = "Stop"

$ServiceName = "yuduan-agent"
$DisplayName = "YuDuan Agent"
$BinDst     = "$env:ProgramFiles\YuDuan\yuduan-agent.exe"
$LogFile    = "$env:ProgramData\YuDuan\agent.log"

# —— 按现场环境修改（也可用命令行参数覆盖）——
# 默认【不写死】中枢地址：副端启动时 UDP 广播自动发现（§8.4，安装即注册），
# 中枢 IP 变更（网段漂移/DHCP 续租）时断线重连会自动重探。
# 仅跨网段广播被隔离等场景才需要显式指定：./install-agent.ps1 -HubUrl ws://<IP>:18241/ws/agent
$SetHubExplicitly = [bool]$HubUrl
if (-not $Secret) { $Secret = "CHANGE-ME-AT-DEPLOY" }   # 必须与 Go 中枢 YUDUAN_HMAC_SECRET 一致

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
    setx YUDUAN_HUB "" | Out-Null
    setx YUDUAN_HMAC_SECRET "" | Out-Null
    setx YUDUAN_ENCODER_LIB "" | Out-Null
    Write-Host "==> 已卸载（日志保留：$LogFile）"
    exit 0
}

# 二进制位置：本脚本位于 rust/agent/deploy/windows/，因此 target/ 在 rust/agent/target/
# （即脚本目录上溯三级，而不是两级 —— 原写法 "..\target" 会落到 deploy\target\）
$src = Join-Path $PSScriptRoot "..\..\target\agent.exe"
if (-not (Test-Path $src)) {
    Write-Error "未找到 $src，请先构建：rustc -O --target x86_64-pc-windows-msvc src/main.rs -o target/agent.exe"
    exit 1
}

Write-Host "==> 安装二进制 -> $BinDst"
New-Item -ItemType Directory -Force -Path (Split-Path $BinDst) | Out-Null
Copy-Item $src $BinDst -Force

Write-Host "==> 写入环境变量（Machine 作用域，服务重启后生效）"
# 用 setx 而非 [Environment]::SetEnvironmentVariable：
#   后者在某些 Windows 沙箱/受控环境下写 Machine 作用域会直接终止宿主进程
#   （无异常、无 stderr），导致脚本半途而废。setx 走 setx.exe，可靠且行为一致。
if ($SetHubExplicitly) {
    setx YUDUAN_HUB $HubUrl | Out-Null
    Write-Host "==> 已写入 YUDUAN_HUB=$HubUrl（显式指定，跳过自动发现）"
} else {
    # 清掉可能残留的旧地址，确保走 UDP 自动发现（中枢 IP 漂移时自愈）
    setx YUDUAN_HUB "" | Out-Null
    Write-Host "==> 未指定 -HubUrl：副端将 UDP 广播自动发现中枢（安装即注册）"
}
setx YUDUAN_HMAC_SECRET $Secret | Out-Null
# 原生编码器 DLL（阶段 4 能力依赖）：未指定且默认路径不存在时，副端会诚实回退 RAW_RGBA
if (-not $EncoderLib) {
    $EncoderLib = "$env:TEMP\yuduan_enc_mf.dll"
}
if (Test-Path $EncoderLib) {
    setx YUDUAN_ENCODER_LIB $EncoderLib | Out-Null
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
