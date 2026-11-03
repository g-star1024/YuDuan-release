# 御端生产副端（Rust 版）

> 依据项目铁律：生产副端用 Rust 重写（捕获/注入/系统服务/防篡改等原生模块）。
> 本目录为 Rust 生产副端的**参考实现**，与 Go 参考副端（`dev/cmd/agent`）协议等价、可互通。

## 硬约束：零依赖、离线构建

本机/受限环境无法访问 crates.io，因此**不使用任何第三方 crate，仅依赖 Rust 标准库**：

- 手写 WebSocket 客户端（TCP + 握手 + 掩码帧；wss 经 `openssl s_client` 子进程管道代理做 TLS）
- 手写极简 JSON 解析/序列化（无 serde）
- 资产采集经系统命令与 `/proc`、`sysctl` 等（跨 macOS / Linux / Windows）
- SHA-256 / HMAC-SHA256 / base64 / argon2 相关原语均为纯 std 实现（内置 FIPS 180-4、RFC 4231 官方向量自测）

## 构建与测试

不要用 `cargo build`（会因更新 registry 失败），直接用 rustc 离线编译：

```bash
rustc -O src/main.rs -o target/agent        # 发布构建
rustc --test src/main.rs -o /tmp/agent_test && /tmp/agent_test   # 单元测试（13 项）
```

## 模块划分

| 模块 | 职责 |
| --- | --- |
| `main.rs` | 入口、资产采集、WebSocket 客户端（ws/wss）、信封、指令分发、心跳/重连 |
| `sha256.rs` | SHA-256 / HMAC-SHA256 / hex / base64 / 恒定时间比较（FIPS 180-4 + RFC 4231 向量验证） |
| `secure.rs` | 指令 HMAC 验签（铁律 4）+ nonce 防重放 + ±300s 时间窗，与 Go 中枢规范串逐字节一致 |
| `httpget.rs` | 极简 HTTP/1.1 GET（Content-Length/chunked，解析 Content-Disposition 建议文件名） |
| `swdist.rs` | M5 软件分发：下载 → 按扩展名分派 → 平台静默安装（macOS pkg/zip/dmg、Linux deb/rpm/sh、Windows msi/exe） |
| `rc.rs` | M4 远控：screencapture/scrot 采集 + CoreGraphics FFI（CGEvent）键鼠注入 + 合规远端提示 |

## 与 Go 中枢的互通（已实测，`dev/e2e_rust.py` 12/12）

对接 `dev/cmd/hub` 中枢，控制面协议见 `dev/proto/protocol.md` 与 `dev/internal/proto/proto.go`：

- ✅ WebSocket 握手 / `register` 注册（回传 token 复用设备身份）/ `heartbeat`（30s）
- ✅ `command`：`shell`、`collect`、`sw_install` 已实现，`result` 回执正常
- ✅ **HMAC 验签互通**：hub 签名 → 副端验签执行；密钥不匹配 → 拒绝并回执 failed（不执行）
- ✅ **wss（TLS）**：`openssl s_client` 管道代理，实测注册 + 指令全通；`YUDUAN_TLS_CAFILE` 可开启严格证书校验
- ✅ **M4 远控**：rc_ready → rc_frame（实测 macOS 3584×2240 JPEG，2.3MB/帧）→ rc_input → rc_stop
- ✅ 资产采集：hostname / os / os_version / arch / cpu / mem / disk / serial / mac / ip

实测输出示例（macOS）：

```
[agent] WebSocket 握手成功: wss://127.0.0.1:8443/ws/agent（验签 已启用）
[agent] 注册成功 device_id=... token=... ok=true
[agent] 已回 result task=... state=success
```

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `YUDUAN_HUB` | `ws://127.0.0.1:8080/ws/agent` | 中枢地址，支持 `ws://` 与 `wss://` |
| `YUDUAN_HMAC_SECRET` | 空（开发态放行） | 指令验签密钥，**必须与 Go 中枢 `YUDUAN_HMAC_SECRET` 一致**；配置后验签失败/重放/超时窗一律拒绝 |
| `YUDUAN_TLS_CAFILE` | 空 | wss 证书校验 CA 文件；设置后启用严格校验（缺省接受自签名，仅限受信局域网） |

## 系统服务化（deploy/）

| 平台 | 清单 | 安装脚本 |
| --- | --- | --- |
| macOS | `deploy/launchd/com.yuduan.agent.plist`（LaunchDaemon，已过 `plutil -lint`） | `sudo ./deploy/install-macos.sh [--uninstall]` |
| Linux | `deploy/systemd/yuduan-agent.service`（开机自启 + 崩溃重启） | `sudo ./deploy/install-linux.sh [--uninstall]` |
| Windows | （sc.exe 创建，`LocalSystem`，失败恢复策略） | `./deploy/windows/install-agent.ps1 [-Uninstall]`（需先交叉编译 `--target x86_64-pc-windows-msvc`） |

安装后按现场修改中枢地址与验签密钥（plist / `systemctl edit` / 脚本顶部变量）。

## 与 Go 参考副端的分工

- **Go 参考副端**（`dev/cmd/agent`）：打通协议与平台无关逻辑，开发快，逻辑与本 Rust 版等价，便于平移。
- **Rust 生产副端**（本目录）：面向生产的原生模块（捕获/注入/服务化/防篡改）最终落地处。

## 待办（生产化 P2）

| 项 | 说明 |
| --- | --- |
| 证书固定 / mTLS | 当前 wss 缺省接受自签名（局域网信任模型）；生产应配置 CA 或固定服务端证书指纹 |
| H.264/H.265 二进制帧 | 远控当前为 JPEG base64（与 Go 参考一致）；生产目标见 `dev/proto/protocol.md` §4/§5/§8 |
| Linux/Windows 输入注入 | macOS 已用 CoreGraphics FFI 真实注入；Linux 需 XTest/uinput、Windows 需 SendInput（当前仅记录日志） |
| 安装包签名校验 | sw_install 当前按扩展名分派安装；生产需校验包签名/哈希（防中间人篡改） |
