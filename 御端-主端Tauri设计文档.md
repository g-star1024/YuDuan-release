# 御端 · 主端桌面客户端（Tauri）设计文档 v1.0

> 状态：**立项设计稿，待评审拍板**（未开工实现）。
> 日期：2026-10-24 ｜ 前置依赖：M2–M6 + 安全基座 + P2P 二进制媒体环（均已完成）。

## 1. 为什么要做（问题陈述）

当前「主端」是两个形态，各有硬缺口：

| 形态 | 能力 | 硬缺口 |
|---|---|---|
| 浏览器控制台（console/*.html） | 资产/指令/分发/远控（JPEG + WebCodecs） | 浏览器无法监听裸 TCP，**永远走 relay**，P2P 直连的主端侧落不了地 |
| p2pviewer CLI | e2e 验证工具（P2P/relay 双路径） | 面向联调，不面向运维人员 |

**结论：P2P 直连（协议 §8.3 的核心性能目标）只有桌面客户端能真实用上。**
这是主端 Tauri 化的第一驱动力；其次是把运维日常操作从浏览器标签页升级为常驻应用。

## 2. 目标与非目标

**目标（P1）**
1. 媒体环主端落地：**P2P 直连监听方**（TCP listener + ICE-lite offer/candidate 广播）+ relay 双路径，复用现有 24B 帧协议（§8.3），零协议改动。
2. 原生解码渲染：h264/h265 经系统解码器（macOS VideoToolbox / Windows MF / Linux VAAPI）解到 GPU 表面直绘，替代浏览器 WebCodecs 的兼容性上限。
3. 全管理面：资产台账、指令下发、软件分发、远控合规提示、审计查询（复用 hub REST + WS API，不改 hub）。
4. 安全对齐：mTLS 客户端证书 + SPKI pin（复用 §8.3.13 私有 CA `issue-client`），令牌/keychain 存储。

**非目标（本期不做）**
- 不替换/不删浏览器控制台（两者并存，控制台仍是轻量入口）。
- 不做信创/国产化适配（延后）。
- 不做主端侧多屏拼接、会话录制回放 UI（录像回放已有 recreplay CLI，GUI 化另立项）。

## 3. 技术选型与理由

| 项 | 选择 | 理由 |
|---|---|---|
| 框架 | **Tauri 2**（Rust core + WebView 前端） | 与副端同为 Rust（团队单语言栈）；体积/内存远小于 Electron；官方多窗口/托盘/自更新齐备 |
| 前端 | React + TypeScript + Vite | 现有 console/*.html 的渲染/统计逻辑可直接迁移组件化 |
| 解码 | Tauri Rust 侧解码 → 共享纹理/视频帧直绘 | 用系统硬件解码器，绕开 WebView WebCodecs 的 codec 支持面限制 |
| TCP 媒体 | Rust std TcpListener/TcpStream | 与副端 rc_media.rs 同构（4B 长度前缀分帧 + 24B 头），代码可参考移植 |
| 打包 | Tauri bundler（dmg/msi/AppImage） | 与现有分发体系（M5 软件仓库）天然对接 |

## 4. 架构与模块划分

```
┌─ 主端 App（Tauri 2）─────────────────────────────┐
│  WebView 前端（React）                            │
│   ├─ 资产/指令/分发/审计页（迁移自 console）        │
│   ├─ 远控 Viewer 窗口（canvas 直绘 + 输入采集）     │
│   └─ 设置（hub 地址 / 证书 / 主题）                 │
│           │ Tauri invoke / event                   │
│  Rust core ─────────────────────────────────────  │
│   ├─ hub_client：REST + WS（控制面，含 mTLS/pin）   │
│   ├─ media：P2P listener + 24B 帧编解码 + ICE-lite  │
│   ├─ decoder：系统解码器 FFI（VT/MF/VAAPI）→ 帧回调  │
│   ├─ input：键鼠事件 → rc_input 序列化              │
│   ├─ qos：RTT 探测 + 丢包统计 + 码率/帧率反馈（§8.3.15）│
│   └─ secure：keychain 存凭据、剪贴板、合规事件流      │
└──────────────────────────────────────────────────┘
```

**模块间契约**：前端只经 Tauri command/event 与 core 通信；媒体帧经解码后以
GPU 纹理句柄或 RGBA 帧送前端 canvas（首选 Tauri 2 的 `tauri-plugin-` 视频/纹理通道，
退化为 RGBA + putImageData，口径与 rc.html raw_rgba 路径一致）。

## 5. 关键设计点

1. **P2P 媒体环主端侧**（对齐 §8.3 ICE-lite 单侧监听模型）：
   - viewer 监听 0.0.0.0:媒体端口 → `rc_offer`（批量候选：枚举非回送 IPv4）+
     `rc_candidate`（增量）；副端 dial_direct 直连。
   - 端口策略：默认 0（系统分配），设置页可固定；防火墙提示一次性引导。
   - 直连升级过程事件流（media_selected 升级路径）在 Viewer 状态栏展示（与副端
     日志口径一致，可排障）。
2. **解码器矩阵**：与副端编码器矩阵镜像——macOS VTDecodeSession / Windows
   MF（Sync MFT reader）/ Linux VAAPI；不可用时诚实回退「帧统计模式」（不造假画面）。
   复用 encoder-* 的验证方法论（C-ABI 直测 harness 先行）。
3. **QoS 闭环**：主端为策略发起方（§8.3.9/11/15 已在 p2pviewer/rc.html 验证），
   迁移为 Rust core 常驻任务：渲染耗时统计 + seq 缺口丢包率 + RTT 探测 → 周期
   rc_qos。逻辑与 rc.html 同参数（阈值不改，避免副端策略两侧口径漂移）。
4. **安全**：
   - wss + 客户端证书（私有 CA `issue-client`，证书落 keychain/证书库）；
   - SPKI pin 校验（与副端 tls.rs 同算法）；
   - operator 凭据经 OS keychain（macOS Security / Win Credential Manager），
     禁止明文落盘。
5. **远控合规**：发起端展示 consent 流事件（consent_required/granted/denied），
   拒绝即断开媒体——与副端合规事件（铁律）对齐。

## 6. 里程碑（建议 4 段，可独立验收）

| 阶段 | 范围 | 验收口径 |
|---|---|---|
| T-1 骨架 | Tauri 工程 + 登录 + 资产/指令页迁移 + hub_client | 真实 hub 上完成注册设备查看/指令下发（curl 同口径） |
| T-2 媒体 relay 路径 | 24B 帧解码 + JPEG/RAW 渲染 + 输入注入 + QoS | 与 macOS 副端 relay 会话 30fps 稳定，参数与 rc.html 一致 |
| T-3 P2P 直连 + 原生解码 | listener/ICE-lite + VT 解码（macOS 先行） | 直连升级事件可观测；h264 1080p 解码渲染，CPU 低于 JPEG 路径 |
| T-4 打包分发 | dmg/msi + 自更新 + mTLS/pin 接入 | 通过 M5 仓库分发到测试机完成安装并注册 |

体量估计：T-1 ≈ 1 周；T-2 ≈ 1–1.5 周；T-3 ≈ 2 周（解码器 FFI 占大头）；T-4 ≈ 0.5–1 周。

## 7. 风险与对策

| 风险 | 对策 |
|---|---|
| Tauri WebView 各平台 WebCodecs 差异 | 解码放 Rust 侧（本设计即此取向），WebView 仅做画布 |
| P2P 需要监听端口的权限/防火墙摩擦 | 安装引导页一次性提示；候选广播多地址提高首跳成功率 |
| 三平台解码器 FFI 工作量大 | 按实测顺序 macOS→Windows→Linux 分期；先 JPEG 路径保底全平台可用 |
| 与 rc.html 的 QoS/校验逻辑双实现漂移 | 阈值常量单点定义（Rust core），注释标注「与副端 loss_cap_fps/rtt_cap_fps 同源，改动须双侧同步」 |

## 8. 待拍板问题（评审焦点）

1. **是否按 4 阶段推进**（还是先只做 T-1+T-2 验证形态再续）？
2. **解码优先级**：macOS VT 先行是否可接受（Windows MF / Linux VAAPI 随后）？
3. **与浏览器控制台的边界**：远控入口是否收敛到 Tauri 主端（控制台保留远控但提示推荐主端）？
4. 应用命名/图标（复用 logo-yuduan.svg 生成 icns/ico）。

## 9. T-4 落地结论（2026-10-25 凌晨实施）

> §8 待拍板问题 1/2/4 已由用户拍板（4 阶段推进 / VT 先行 / 图标复用 logo mark）；3 已由
> 「远控入口收敛到 Tauri 主端」拍板。本节为 T-4 实施记录。

### 9.1 自更新：采纳方案 B —— 不做公网 updater，升级包走 M5 软件仓库分发

- **决策依据**：铁律 1（局域网 ONLY）——Tauri 官方 updater 默认从公网拉取更新清单与
  安装包，与「禁止公网穿透/公网依赖」冲突；M5 仓库已具备上传/平台标注/SHA-256/Ed25519
  签名/按设备分发/状态回报全链，零新增基础设施、零新增攻击面。
- **主端实现**（轻量检查 + 引导，不自动安装）：
  - `hub_client::software_list`（GET /api/v1/software）+ `latest_update`（包名
    `yuduan-main` + 平台匹配 [macos/windows/linux/any] + 语义化版本比较，纯函数含单测）；
  - `hub_check_update` command：前端「检查更新」按钮 → 有新版提示
    「请通过 中枢控制台 → 软件分发 下载安装包」（不自动下载/替换自身，管理员手动分发）。
- **版本口径**：本地版本取编译期 `CARGO_PKG_VERSION`（与 tauri.conf.json/package.json
  三处同步维护，发版脚本校验）。

### 9.2 打包

- `npm run tauri build`（targets: app + dmg）；多 bin 工程需在 Cargo.toml 显式
  `default-run = "yuduan-main"`（tauri CLI 定位主二进制）。
- 产物：`main/src-tauri/target/release/bundle/{macos,YuDuan.app,dmg}`。
- 未做代码签名/公证（内网分发无 Gatekeeper 强需求；后续可接企业证书）。
