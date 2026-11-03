# 御端（YuDuan）重装清理脚本 v1.0（随中枢包分发，需以管理员运行）
#
# 用途：重装/换版本前清理旧环境（计划任务、防火墙规则、残留进程、副端服务、环境变量）。
# 设计：先探测再执行——不存在的一律打灰色 [SKIP]，不产生红色 NativeCommandError 噪音
#   （此前现场手拼清理脚本时，schtasks/taskkill 对不存在目标报错，被误判为部署失败）。
# 原则：只清理运行态与注册项，不删除配置与数据（hub.env、data\ 目录原样保留）。
# 用法：
#   .\cleanup.ps1            # 清理中枢 + 副端（本机都清）
#   .\cleanup.ps1 -Hub       # 只清中枢
#   .\cleanup.ps1 -Agent     # 只清副端
param(
  [switch]$Hub,
  [switch]$Agent,
  [string]$HubTaskName = "YuDuanHub",
  [string]$AgentServiceName = $(if ($env:YUDUAN_SERVICE_NAME) { $env:YUDUAN_SERVICE_NAME } else { "yuduan-agent" })
)

$ErrorActionPreference = "Stop"

# 清理目标：未显式指定 -Hub/-Agent 时默认两个都清
if (-not $Hub -and -not $Agent) { $Hub = $true; $Agent = $true }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Warning "当前不是管理员身份：计划任务/服务/防火墙的清理会失败。请右键『以管理员身份运行』。"
}

function Skip([string]$msg) { Write-Host "[SKIP] $msg" -ForegroundColor DarkGray }
function Done([string]$msg) { Write-Host "[OK]   $msg" -ForegroundColor Green }

# 原生命令统一经 cmd /c 内部重定向（PS 5.1 EAP=Stop 会把原生 stderr 转 terminating error，v0.2.5 实机教训）
function Invoke-Native([string]$cmdLine) {
  cmd /c "$cmdLine >nul 2>&1"
  return ($LASTEXITCODE -eq 0)
}

Write-Host "==> 御端重装清理（配置与数据保留）"

# ---------- 中枢 ----------
if ($Hub) {
  Write-Host ""
  Write-Host "---- 中枢 ----"

  # 1) 计划任务（先探测：不存在是干净机器的常态，不是错误）
  if (Invoke-Native "schtasks /Query /TN $HubTaskName") {
    Invoke-Native "schtasks /End /TN $HubTaskName" | Out-Null    # 先停守卫循环包装进程
    if (Invoke-Native "schtasks /Delete /TN $HubTaskName /F") {
      Done "计划任务 $HubTaskName 已删除"
    } else {
      Write-Warning "计划任务 $HubTaskName 停止成功但删除失败（schtasks exit=$LASTEXITCODE），请手动核对"
    }
  } else {
    Skip "计划任务 $HubTaskName 不存在（本机未注册过中枢自启，无需清理）"
  }

  # 2) 防火墙规则（三条：明文/TLS/UDP 发现；规则名无空格，不加引号以规避 cmd /c 嵌套引号剥离）
  foreach ($rule in @("yuduan-hub-plain", "yuduan-hub-tls", "yuduan-disc-udp")) {
    if (Invoke-Native "netsh advfirewall firewall show rule name=$rule") {
      if (Invoke-Native "netsh advfirewall firewall delete rule name=$rule") {
        Done "防火墙规则 $rule 已删除"
      } else {
        Write-Warning "防火墙规则 $rule 删除失败，请手动核对"
      }
    } else {
      Skip "防火墙规则 $rule 不存在（无需清理）"
    }
  }

  # 3) 残留 hub 进程（PowerShell 原生探测，无 stderr 噪音）
  $hubProc = Get-Process -Name "yuduan-hub" -ErrorAction SilentlyContinue
  if ($hubProc) {
    $pids = ($hubProc | ForEach-Object { $_.Id }) -join ", "
    $hubProc | Stop-Process -Force -ErrorAction SilentlyContinue
    Done "残留中枢进程已结束（PID: $pids）"
  } else {
    Skip "无残留 yuduan-hub 进程（本就未运行，无需终止）"
  }

  # 4) YUDUAN_* 环境变量（User/Machine 两级作用域；.NET API 探测，无 stderr）
  $envCleared = $false
  foreach ($scope in @([System.EnvironmentVariableTarget]::User, [System.EnvironmentVariableTarget]::Machine)) {
    foreach ($n in @("YUDUAN_HMAC_SECRET","YUDUAN_HMAC_ENFORCE","YUDUAN_PEPPER","YUDUAN_SIGN_SEED","YUDUAN_SIGN_SEED_FILE","YUDUAN_HUB")) {
      $v = [Environment]::GetEnvironmentVariable($n, $scope)
      if ($null -ne $v) {
        [Environment]::SetEnvironmentVariable($n, $null, $scope)
        $scopeName = if ($scope -eq [System.EnvironmentVariableTarget]::User) { "用户" } else { "系统" }
        Done "已清除环境变量 $n（$scopeName 作用域）"
        $envCleared = $true
      }
    }
  }
  if (-not $envCleared) {
    Skip "无 YUDUAN_* 残留环境变量（两级作用域均干净）"
  }
}

# ---------- 副端 ----------
if ($Agent) {
  Write-Host ""
  Write-Host "---- 副端 ----"

  # 1) 残留副端进程
  $agentProc = Get-Process -Name "yuduan-agent" -ErrorAction SilentlyContinue
  if ($agentProc) {
    $pids = ($agentProc | ForEach-Object { $_.Id }) -join ", "
    $agentProc | Stop-Process -Force -ErrorAction SilentlyContinue
    Done "残留副端进程已结束（PID: $pids）"
  } else {
    Skip "无残留 yuduan-agent 进程（本就未运行，无需终止）"
  }

  # 2) 副端系统服务
  $svc = Get-Service -Name $AgentServiceName -ErrorAction SilentlyContinue
  if ($svc) {
    if ($svc.Status -ne "Stopped") {
      Invoke-Native "net stop $AgentServiceName /y" | Out-Null
    }
    if (Invoke-Native "sc delete $AgentServiceName") {
      Done "副端服务 $AgentServiceName 已删除"
    } else {
      Write-Warning "副端服务 $AgentServiceName 删除失败（sc exit=$LASTEXITCODE），可能权限不足，请以管理员重跑"
    }
  } else {
    Skip "副端服务 $AgentServiceName 不存在（本机未安装过副端服务，无需清理）"
  }
}

Write-Host ""
Write-Host "==> 清理完成（hub.env 与 data\ 目录未动；重装请继续按部署指引执行 register-task.ps1 / 副端安装）"
