# 副端（Agent）说明

副端运行在每台员工电脑上，M2–M5 已实现参考实现并通过 macOS 实测。

## 当前实现（Go 参考 Agent）
- 文件：`cmd/agent/main.go` + `cmd/agent/rc.go`（远程控制） + `cmd/agent/swdist.go`（软件分发） + `internal/collect`
- 行为：
  - 启动后通过 `ws://hub/ws/agent` 注册（携带资产指纹），获取 `device_id + token`；
  - 每 30s 心跳；长连接断开自动 5s 重连；
  - 接收 `command`，支持 `shell`、`collect`、`sw_install`；结果回传 `result`。
  - 资产采集覆盖：hostname / os / os_version / arch / cpu / 内存 / 磁盘 / 序列号 / MAC / IP / 负载。

## M4 远程控制（参考实现）
- `rc.go`：收到 `rc_request` → 被控端弹**远端提示**（macOS 通知，员工可拒绝）+ 回报 `rc_event(consent_required)` → 启动屏幕采集循环（macOS `screencapture` 真实采集→JPEG；Linux `scrot`/`import`；Windows 合成帧），每 500ms 发 `rc_frame` → 收到 `rc_input` 回执（macOS 最佳努力键入注入）→ `rc_stop` 结束。
- 说明：捕获/输入注入为平台原生能力，**Rust 生产版**将在对应平台模块落地（含鼠标注入、全键、防篡改）。MVP 用中枢中继 + JPEG base64，生产演进为 P2P + H.264/H.265（见 `proto/protocol.md` §4/§5/§8）。

## M5 软件分发（参考实现）
- `swdist.go`：收到 `sw_install{software_url, platform, pkg_name}` → 下载 → 按扩展名静默安装/解包 → 回报 `result`。
- 平台命令已写明：`.pkg`→`installer -target /`；`.zip`→解包；`.msi`→`msiexec /qn`；`.exe`→`/S`；`.deb`→`dpkg -i`；`.rpm`→`rpm -i`（真实静默命令见代码注释，生产 Rust 副端实现）。

## 平台差异收敛
所有平台返回同一 `collect.Asset` 结构，平台分支内聚在 `collect.go` 与 `rc.go`/`swdist.go`，便于 Rust 重写时一一对应。
- macOS：已实测（注册/采集/远控/分发）。
- Linux/Windows：分支已写，待对应平台实跑验证。

## 重要决策（已确认）
- 铁律要求生产副端用 **Rust**；M2–M5 用 Go 参考 Agent 快速打通协议，逻辑与 Rust 版等价。后续 Rust 重写时字段与流程保持一致即可平移（用户 2026-10-22 确认）。
- 全链路 TLS + 指令 HMAC 签名（铁律 4）+ PostgreSQL 持久化，收口到后续安全/存储里程碑（用户确认延后）。
