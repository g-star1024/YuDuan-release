# 御端（YuDuan）中枢 Windows 服务器测试指引

> 版本：**v0.4.11**（2026-11-03）
> 交付对象：Windows 服务器现场实施/测试人员
> 说明：本指引用于在 Windows 服务器上部署并验证御端中枢（Hub）。请按顺序执行，
> 每步把「实际结果」记录到末尾的《测试结果回传表》，连同指定的证据文件一起返回。

---

## 0. 测试目的

验证 v0.4.11 中枢在 Windows 服务器上**装完即能跑、功能可用、故障可定位**，覆盖：

- 部署安装（一键注册 + 开机自启）
- 部署后**自动端到端自检**（v0.4.4 新增）
- 控制台登录与核心 API
- 防火墙、重启保活、访问日志
- 副端接入（可选，如有副端包）

---

## 1. 前置条件与材料

### 1.1 服务器要求

| 项 | 要求 |
|---|---|
| 操作系统 | Windows Server 2016 / 2019 / 2022（建议 2019+） |
| 权限 | 需要**管理员** PowerShell（右键「以管理员身份运行」） |
| 网络 | 局域网可达；需放行 TCP 8080 / TCP 8443 / UDP 18242（默认 18242、可配置，由 `YUDUAN_DISCOVERY_PORT` 覆盖；部署脚本自动做） |
| 磁盘 | 建议 ≥ 2GB 可用（含软件仓库 data\repo） |
| 时间同步 | 服务器时间与客户端尽量一致（令牌有时间戳校验） |

### 1.2 需要准备的文件（从 Release v0.4.11 下载）

| 用途 | 文件名 |
|---|---|
| 中枢（必测） | `YuDuan-hub_v0.4.11_windows_amd64.zip` |
| 副端（可选） | `YuDuan-agent_v0.4.11_windows.exe` |
| 主端（可选） | `YuDuan-main_v0.4.11_windows.exe` |

> 下载地址：`https://github.com/g-star1024/YuDuan-release/releases/tag/v0.4.11`
> （如从其他渠道拿到的包，先确认文件名带 `v0.4.11`）

### 1.3 记录环境信息（T0，先填好）

| 项 | 值（测试时填写） |
|---|---|
| 服务器主机名 | |
| 服务器内网 IP | |
| 操作系统版本 | |
| 中枢安装目录（建议 `D:\yuduan-hub` 或 `C:\yuduan-hub`，**避免中文/含空格路径**） | |
| 测试日期 / 测试人 | |
| 是否配置了 PostgreSQL（`hub.env` 里有无 `YUDUAN_DB_DSN`） | 是 / 否 |

---

## 2. 安装部署（T1）

> ⚠️ **关键**：如果该目录已有旧版中枢，务必**整包替换**（把整个旧目录的 exe / ps1 / cmd 全删掉，
> 换成新包解压出的所有文件），**不要只覆盖单个文件**——旧脚本和旧 exe 混用会出问题。

> 🔴 **投产阻断项（v0.4.4 实测确认）**：不配置 `YUDUAN_DB_DSN` 时中枢运行在**内存存储模式**——
> 中枢进程每次重启（含崩溃自动重启、开机自启）都会**丢失全部运行数据且 admin 密码复位为 admin123**。
> **功能测试可以不配 PG**（数据丢失不影响验证结论），但**下发给真实员工终端前必须**：
> 安装 PostgreSQL，并在 `hub.env` 中设置 `YUDUAN_DB_DSN=postgres://用户:密码@127.0.0.1:5432/yuduan?sslmode=disable`（v0.4.0+ 支持 URL 形式），
> 重启中枢后用 `YUDUAN_DB_DSN 是否仍存在 + 重启后设备数据是否保留` 验证持久化生效。

### 2.1 解压

将 `YuDuan-hub_v0.4.11_windows_amd64.zip` 解压到目标安装目录，确认里面有这些文件：

```
yuduan-hub.exe        ← 中枢主程序（9.3MB，含内嵌控制台 + [http] 访问日志）
yuduan-ca.exe         ← 私有 CA 工具（3.6MB）
register-task.ps1     ← 部署编排脚本（388 行，含端到端自检）
run-hub.cmd           ← 前台运行入口
deploy.bat            ← 一键部署入口
env.example           ← 配置模板
README-deploy.md      ← 部署文档
cleanup.ps1           ← 重装/升级前一体化清理工具（v0.4.9 起随包附带，用法见 2.4）
```

### 2.2 执行部署

**管理员 PowerShell**，`cd` 到安装目录，执行：

```powershell
cd D:\yuduan-hub          # 换成你的实际目录
.\register-task.ps1
```

> 不要用 `run-hub.cmd`（那是前台跑，窗口一关进程就停）。**服务化必须用 `register-task.ps1`**。

### 2.3 观察部署输出（T2 自检）

脚本会自动完成：生成配置 `hub.env` → 收紧权限 → 建私有 CA → 注册计划任务
`YuDuanHub`（开机自启，SYSTEM 身份）→ 立即启动 → 放行防火墙 → **端到端自检**。

**把脚本完整输出原样截图/复制**，重点看末尾自检部分，应类似：

```
==> 端到端自检（① 控制台页面 ② 鉴权脚本 ③ 登录接口）
[PASS] ① 控制台页面 GET / -> 200
[PASS] ② 鉴权脚本 GET /auth.js -> 200
[PASS] ③ 登录接口 POST /api/v1/login -> 200 code=0（token 已签发，可登录）
==> ✅ 自检全部通过：控制台可访问、可登录。浏览器打开 http://<中枢IP>:8080
```

**判读：**
- **三项全 `[PASS]`** → 部署成功，跳到 T3。
- **出现 `[FAIL]`** → 直接跳到第 6 节「故障排查」，把自检输出 + 排查结果一起回传，**不要自行反复重装**。

### 2.4 重装 / 换版本前清理（v0.4.10 起）

重装或升级前清理旧环境，**统一用包内自带的 `cleanup.ps1`，不要手拼清理命令**：

```powershell
.\cleanup.ps1          # 中枢 + 副端一起清（本机都装了的情况）
.\cleanup.ps1 -Hub     # 只清中枢
```

- 脚本**先探测再执行**：要清的对象不存在时输出灰色 `[SKIP]`（如 `[SKIP] 计划任务 YuDuanHub 不存在`）——**`[SKIP]` 是正常输出，不是报错**，干净机器上应看到一串 [SKIP]。
- 红色输出只应是 `Write-Warning`（带明确文字说明），出现时原样回传。
- 配置与数据（`hub.env`、`data\` 目录）一律不动；确认要重置配置再用 `register-task.ps1 -ResetConfig`。

---

## 3. 控制台登录验证（T3）

1. 在**服务器本机**浏览器打开：`http://127.0.0.1:8080`
   （用 127.0.0.1 避免系统代理干扰；跨机测试用 `http://<服务器内网IP>:8080`）
2. 用默认账号登录：`admin` / `admin123`
   - 首次登录若强制改密，改密后记住新密码（后续 API 测试要用）。
   - 若提示「无法连接」→ 见第 6 节；若提示密码错误 → 说明 admin 已被改过，用实际账号。

**记录：** 是否成功登录进入控制台首页？登录页/首页各截图一张。

---

## 4. 核心 API 验证（T4）

在**管理员 PowerShell** 执行（验证登录拿 token + 各接口能否访问，**不依赖浏览器**）：

```powershell
# ① 登录拿 token（把 <密码> 换成实际密码；默认 admin123）
$login = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/login" -Method Post `
  -ContentType "application/json" -Body '{"username":"admin","password":"admin123"}'
$token = $login.token
"LOGIN code=$($login.code) role=$($login.role) token_len=$($token.Length)"

# ② 设备列表（现状约定：成功响应直接返回业务字段，无 code 信封）
$dev = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/devices" `
  -Headers @{Authorization="Bearer $token"}
"DEVICES total=$($dev.total) count=$($dev.devices.Count)"

# ③ 审计日志（预期 HTTP 200 + total/events 字段）
$audit = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/audit" `
  -Headers @{Authorization="Bearer $token"}
"AUDIT total=$($audit.total) events=$($audit.events.Count)"

# ④ 告警中心（预期 HTTP 200 + alerts/unread 字段）
$alerts = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/alerts" `
  -Headers @{Authorization="Bearer $token"}
"ALERTS alerts=$($alerts.alerts.Count) unread=$($alerts.unread)"

# ⑤ 未带 token 访问设备列表（预期 HTTP 401，验证鉴权生效）
try {
  $n = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/devices"
  "NOAUTH code=$($n.code)   ← 若返回数据则鉴权有问题！"
} catch {
  "NOAUTH -> $($_.Exception.Response.StatusCode.value__)  ← 预期 401，鉴权生效"
}
```

**记录：** 五条输出原样复制回传。`①` 应为 `code=0`（登录有 code 信封）；`②③④` 应为 HTTP 200 且返回真实业务字段（`total`/`events`/`alerts`——**成功响应无 code 信封是现状约定，不是缺陷**，勿按 `code=0` 判读）；`⑤` 应为 HTTP `401`（v0.4.5 起为真实 HTTP 401，包体仍为 `{"code":401}`；v0.4.4 为 HTTP 200 + 包体 code=401，两种都算鉴权生效）。

---

## 5. 防火墙 / 重启保活 / 日志验证（T5）

### 5.1 防火墙（从另一台局域网机器访问）

在**另一台**同网段电脑的浏览器访问 `http://<服务器内网IP>:8080`。
- 能打开控制台登录页 → 防火墙放行正常。
- 打不开 → 在服务器上检查 `netsh advfirewall firewall show rule name="yuduan-hub-plain"` 是否存在。

### 5.2 重启保活（建议做，验证开机自启）

1. **重启服务器**，重启后等待约 30 秒。
2. 重新用 `http://127.0.0.1:8080` 访问控制台。
3. 检查进程与任务：
   ```powershell
   tasklist | findstr /i yuduan-hub
   schtasks /query /tn YuDuanHub /v | findstr /i "状态 Status"
   ```
   - 能打开控制台 + 进程在 → **重启保活通过**（核心验收项）。
   - 打不开 → 记录 `schtasks` 输出与 `data\hub.log` 末尾，回传。

### 5.3 访问日志（验证 `[http]` 记录，v0.4.4 关键能力）

```powershell
Get-Content "D:\yuduan-hub\data\hub.log" -Tail 40 | Select-String "\[http\]"
```

**记录：** 能看到类似 `[http] 127.0.0.1:xxxxx POST /api/v1/login -> 200 (54ms)` 的行即为正常。
- **无任何 `[http]` 行但页面能开** → 异常，需回传。
- **有 `[http]` 行** → 证明请求确实到达后端，日志可用于后续故障定位。

---

## 6. 副端接入验证（T6，可选：有副端包才做）

> 副端 = 被管终端上的 Agent。此处验证「Agent 注册 → 中枢看到设备 → 下发指令」最小闭环。

1. 在**另一台 Windows 终端**（或被管虚拟机）放 `YuDuan-agent_v0.4.11_windows.exe`。
2. 若该终端与中枢同网段：直接双击运行（或 `.\YuDuan-agent_v0.4.11_windows.exe`），
   它会 UDP 广播自动发现中枢并 claim 注册。
   若不同网段（广播被隔离）：先设中枢地址，如
   `$env:YUDUAN_HUB = "ws://<服务器内网IP>:8080/ws/agent"` 再运行。
   > **v0.4.11 升级注意**：旧版安装器曾把已装二进制设为只读（升级覆盖时报「拒绝访问
   > os error 5」）。v0.4.11 起 `--setup` 会自动清除旧版只读属性再复制（升级自愈），
   > 直接覆盖安装即可，无需再手工 `attrib -r`。
3. 等约 10 秒，在中枢控制台「设备台账」页应能看到该终端上线；或在服务器跑：
   ```powershell
   $login = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/login" -Method Post `
     -ContentType "application/json" -Body '{"username":"admin","password":"admin123"}'
   $dev = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/devices" `
     -Headers @{Authorization="Bearer $($login.token)"}
   # v0.4.10 勘误：响应形如 {devices:[...],total:N}（此前误写 $dev.data/$_.status 旧 schema）
   $dev.devices | ForEach-Object { "DEVICE $($_.id) $($_.hostname) online=$($_.online) ver=$($_.agent_version)" }
   ```

**记录：** 设备列表是否出现该终端、`online` 是否为 `true`；`agent_version` 应显示副端实际版本（如 0.4.11），不再是 0.1.0-rust。截图设备台账页。

---

## 7. 故障排查（仅当自检 `[FAIL]` 或功能异常时）

**先做这三条，把输出回传，不要反复重装：**

```powershell
# ① 进程是否在跑
tasklist | findstr /i yuduan-hub

# ② 8080 是否被 yuduan-hub.exe 监听
netstat -ano | findstr :8080

# ③ 计划任务状态（上次结果）
schtasks /query /tn YuDuanHub /v | findstr /i "状态 上次"
```

**判读：**
- ①无进程 + ②无监听 → 中枢没跑。看 `data\hub.log` 末尾（有无报错），并确认安装目录无中文/空格路径。
- hub.log 出现 `内置 admin 账号就绪（seed 完成，可登录）` = 登录已可用（v0.4.10 起）；部署脚本自检按日志偏移只扫本轮新增行（旧实例残留行不会误触发），且以 `FileShare.ReadWrite` 共享读打开日志（v0.4.11 修复：此前读句柄与 `>>` 重定向写句柄冲突导致轮询静默全失败），先等这一行再测登录，若 60s 未见此行请把 hub.log 完整尾部回传。
- ①有进程但 ②无 8080 → 进程起了但没监听（可能端口被别的程序占了，看 `netstat` 完整输出）。
- ②8080 被**非 yuduan-hub.exe 的 PID** 占用 → 端口冲突，`taskkill /PID <占用PID> /F` 后重跑 `.\register-task.ps1`。
- ③上次结果非 0 → 计划任务没起来，把 `schtasks` 完整输出回传。

---

## 8. 测试结果回传表（T7 — 核心交付物）

> **这表是你要返回的核心**。测试人逐行填写「实际结果」，连同证据文件一起回传。

| 编号 | 测试项 | 预期结果 | 实际结果（测试人填） | 结论 |
|---|---|---|---|---|
| T1 | 部署安装 | 无报错，生成 `hub.env`，任务 `YuDuanHub` 已注册 | | 通过/失败 |
| T2 | 端到端自检 | ①②③ 全 `[PASS]` | | 通过/失败 |
| T3 | 控制台登录 | admin/admin123 进入首页 | | 通过/失败 |
| T4-① | 登录拿 token | `code=0`，token_len>0 | | 通过/失败 |
| T4-② | 设备列表 API | HTTP 200，`total`/`devices` 字段（无 code 信封） | | 通过/失败 |
| T4-③ | 审计 API | HTTP 200，`total`/`events` 字段（无 code 信封） | | 通过/失败 |
| T4-④ | 告警 API | HTTP 200，`alerts`/`unread` 字段（无 code 信封） | | 通过/失败 |
| T4-⑤ | 无 token 访问 | HTTP `401` + 包体 `code=401` | | 通过/失败 |
| T5-1 | 跨机访问 8080 | 控制台页面可开 | | 通过/失败 |
| T5-2 | 重启保活 | 重启后自动起来 | | 通过/失败 |
| T5-3 | 访问日志 | `hub.log` 有 `[http]` 行 | | 通过/失败 |
| T6 | 副端接入（可选） | 设备列表出现、online | | 通过/失败 |

**结论判定：** T1–T5 全部通过 → 部署验收通过，可交付；任一失败 → 按第 7 节排查后回传。

---

## 9. 需要回传的信息/文件清单

1. **环境信息表**（第 1.3 节填写完整）
2. **`register-task.ps1` 部署输出**（T1–T2，完整文本）
3. **T4 五条 API 输出**（原样文本）
4. **T5-3 `[http]` 日志片段**（最近 5–10 行）
5. **截图**：登录页、控制台首页、（副端接入时）设备台账页
6. **若失败**：`schtasks` 完整输出、`netstat -ano | findstr :8080`、`data\hub.log` 末尾 40 行
7. **`hub.env` 的脱敏摘要**（只回传：是否有 `YUDUAN_DB_DSN`、`YUDUAN_HMAC_ENFORCE` 值；
   **不要回传完整密钥**——`YUDUAN_HMAC_SECRET`/`YUDUAN_PEPPER`/`YUDUAN_SIGN_SEED` 属机密，切勿外传/截图）

> ⚠️ **保密提醒**：`hub.env` 内含随机密钥，ACL 已收紧为仅 SYSTEM + Administrators 可读。
> 回传时**只报「有无 DSN / HMAC_ENFORCE 值」**，绝不回传或截图密钥原文。

---

*文档结束。测试人完成后，把第 8 节回传表 + 第 9 节清单打包回传，由开发方按证据逐项判定。*
