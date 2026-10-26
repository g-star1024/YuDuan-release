# 御端中枢 Windows 服务化自启（计划任务方式，开机 SYSTEM 身份运行）
# 用法：右键「使用 PowerShell 运行」，或 PowerShell 里  .\register-task.ps1
# 卸载：.\register-task.ps1 -Remove
param(
  [switch]$Remove,
  [string]$TaskName = "YuDuanHub"
)
$ErrorActionPreference = "Stop"

$hubExe = Join-Path $PSScriptRoot "yuduan-hub.exe"
if (-not (Test-Path $hubExe)) { Write-Error "找不到 $hubExe（请先解包完整目录）" }

# 数据/配置目录固定到 ProgramData（服务身份可写）
$dataDir = "C:\ProgramData\yuduan-hub"
$envFile = Join-Path $dataDir "hub.env"
New-Item -ItemType Directory -Force -Path "$dataDir\repo" | Out-Null

if ($Remove) {
  schtasks /Delete /TN $TaskName /F 2>$null
  Write-Host "已删除计划任务 $TaskName（数据保留在 $dataDir）"
  exit 0
}

if (-not (Test-Path $envFile)) {
  Copy-Item (Join-Path $PSScriptRoot "env.example") $envFile
  # 自动生成生产密钥（HMAC / pepper）
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $bytes = New-Object byte[] 32; $rng.GetBytes($bytes)
  $hmac = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
  $rng.GetBytes($bytes)
  $pepper = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
  (Get-Content $envFile) `
    -replace '^YUDUAN_HMAC_SECRET=$', "YUDUAN_HMAC_SECRET=$hmac" `
    -replace '^YUDUAN_PEPPER=$', "YUDUAN_PEPPER=$pepper" |
    Set-Content $envFile
  Write-Host "已生成配置 $envFile（副端侧需同步 YUDUAN_HMAC_SECRET）"
}

# 服务方式下的必要配置注入（计划任务用 bat 包装以加载 env 文件）
$bat = Join-Path $dataDir "run-service.cmd"
@"
@echo off
for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%envFile%") do (
  if not "%%b"=="" set "%%a=%%b"
)
cd /d "$dataDir"
"$hubExe"
"@ | Set-Content $bat -Encoding ASCII

schtasks /Create /TN $TaskName /TR "$bat" /SC ONSTART /RU SYSTEM /RL HIGHEST /F | Out-Null
Write-Host "计划任务 $TaskName 已注册（开机自启，SYSTEM 身份）"
Write-Host "立即启动： schtasks /Run /TN $TaskName"
Write-Host "日志：任务运行时为控制台窗口；建议生产改用 NSSM 包装为真正 Windows 服务"
Write-Host "防火墙放行：netsh advfirewall firewall add rule name=\"yuduan-hub\" dir=in action=allow protocol=TCP localport=18241"
Write-Host "           netsh advfirewall firewall add rule name=\"yuduan-disc\" dir=in action=allow protocol=UDP localport=18242"
