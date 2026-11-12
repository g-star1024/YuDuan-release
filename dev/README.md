# 御端 · 研发目录（dev）

> M1 设计冻结产物 + M2–M6 可运行实现 + 安全基座 + Rust 生产副端。本文是研发入口。

## 里程碑状态

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M1 设计冻结 | ✅ | 协议 `proto/protocol.md`、Schema `proto/schema.sql`、接口契约 `agent/INTERFACES.md` |
| M2 底座联调 | ✅ 可运行 | 注册/心跳/指令端到端打通（macOS 实测） |
| M3 资产管理 | ✅ 基础版 | 跨平台采集 + 台账 + 报表（macOS 实测；Linux/Win 待实跑） |
| M4 远程控制 | ✅ 基础版 | 中枢中继 + 真实屏幕采集 + viewer + 输入 + 远端提示合规（macOS 实测） |
| M5 软件分发 | ✅ 基础版 | 仓库上传 + 按设备静默分发 + 状态回报（macOS 实测解包） |
| M6 管理与审计 | ✅ 基础版 | RBAC 登录/门禁 + 审计落库 + AD/LDAP 同步 + 高可用设计（`HA.md`）（macOS 实测） |
| 安全里程碑 | ✅ 基础版 | TLS(https/wss) + HMAC 指令签名/验签 + argon2id 口令 + 强制改密 + PG 连接池/参数化 + WORM 审计（macOS + 本地 PG 实测） |
| Rust 生产副端 | ✅ 参考互通版 | `rust/agent` 纯 std、rustc 离线编译；HMAC 验签 / sw_install / 远控 / wss / 系统服务化全部落地并互通实测 |
| 多中枢总线 | ✅ 基础版 | PG outbox + `FOR UPDATE SKIP LOCKED` 认领去粘性，双 Hub 跨实例指令实测通过 |

## 目录结构

```
dev/
├── go.mod                  # Go module: yuduan（零外部依赖）
├── internal/
│   ├── proto/              # 控制面消息信封与载荷（对齐 proto/protocol.md，含 nonce）
│   ├── ws/                 # 最小化 WebSocket（标准库，支持 ws/wss）
│   ├── store/              # 设备/账号/审计仓储：内存 + PostgreSQL 两种实现
│   ├── collect/            # 跨平台资产采集（M3）
│   ├── crypto/             # 安全基座：HMAC 指令签名/验签、登录令牌、口令摘要
│   ├── auth/               # RBAC 角色/权限 + 登录鉴权服务
│   ├── audit/              # 审计事件与 Auditor 接口
│   ├── directory/          # AD/LDAP 目录同步引擎（File/LDAP 两种源）
│   ├── pg/                 # 零依赖 PostgreSQL v3 客户端
│   ├── tlsutil/            # 证书：私有 CA（根/服务器/客户端签发 + SPKI pin）+ 自签兜底
│   └── hub/                # 中枢：长连接纳管 / RBAC REST / 指令签名下发 / 报表 / 远控中继 / 软件仓库 / 审计 / 目录同步
├── cmd/
│   ├── hub/                # 中枢入口（env 配置存储/安全/目录同步/TLS）
│   └── agent/              # 副端参考 Agent 入口（Go，生产以 Rust 重写）
│       ├── main.go         # 注册/心跳/指令分发 + HMAC 验签
│       ├── rc.go           # M4 远程控制：采集 / 输入 / 远端提示
│       └── swdist.go       # M5 软件分发：下载 / 静默安装 / 回报
├── console/
│   ├── index.html          # 管理控制台（资产 + 指令 + 导航）
│   ├── rc.html             # M4 远程控制 viewer
│   ├── software.html       # M5 软件分发
│   ├── login.html          # M6 登录页
│   ├── audit.html          # M6 审计查询
│   └── auth.js             # M6 Bearer 注入 + 401 跳登录
├── HA.md                   # M6 高可用与合规上线设计
├── directory-sample.json   # AD/LDAP 目录同步样例
├── e2e_m6.py               # M6/安全端到端验证脚本（35 项：登录/RBAC/强制改密/argon2id/WORM/HMAC/TLS）
├── e2e_rust.py             # Rust 生产副端端到端验证（12 项：ws/wss/HMAC/sw_install/远控）
├── e2e_pg.py               # PostgreSQL + 多中枢总线端到端验证（17 项：连接池/参数化/去粘性/WORM 触发器/持久化）
├── e2e_vt_encoder.py       # 真实原生编码器端到端验证（10 项：h264/h265 真码流 + P 帧 + ffmpeg 零错误解码 + QoS 限帧）
├── encoder-vt/             # macOS VideoToolbox 原生编码器动态库 + 直测 fixture（见 encoder-vt/README.md）
├── encoder-vaapi/          # Linux VAAPI 原生编码器库（§8.3.14；离线语法自检 + 目标机构建脚本）
├── encoder-mf/             # Windows Media Foundation 原生编码器库（§8.3.14；同上）
├── fixtures/               # 编码器验证桩（yuduan_enc_stub.c，§8.3.4 契约形状）
├── cmd/ca/                 # 私有 CA 管理工具（init / issue-server / issue-client / pin / check）
├── cmd/recreplay/          # 加密录像回放工具（.yrec 解密导出 + ffmpeg 外部校验）
├── proto/                  # M1 冻结：通信协议 + 数据库 Schema
├── agent/INTERFACES.md     # M1 冻结：副端跨平台接口契约
├── hub/README.md           # 中枢说明
├── agent/README.md         # 副端说明（含 Rust 平移说明）
├── console/README.md       # 控制台说明
└── deploy/README.md        # 部署运维说明
```

仓库根目录另有 `rust/agent/`：Rust 生产副端（纯 std，rustc 离线编译）。

## 本地构建与验证

```bash
cd dev
go build -o bin/hub ./cmd/hub
go build -o bin/agent ./cmd/agent

# 终端 1：启动中枢（默认明文 :8080 + TLS :8443；内置演示账号 admin/admin123）
./bin/hub
# 终端 2、3…：启动多个副端（模拟多台员工电脑）
./bin/agent
# 管理控制台：浏览器打开 http://127.0.0.1:8080/ （先跳登录页；资产/指令/远控/分发/审计导航）
# 或 REST（需 Bearer 令牌）：
curl http://127.0.0.1:8080/api/v1/devices
curl http://127.0.0.1:8080/api/v1/report
```

### M6 / 安全 / 持久化运行（环境变量）

```bash
# PostgreSQL 持久化 + HMAC 强制 + AD 目录同步 + TLS
YUDUAN_DB_DSN="host=127.0.0.1 port=5432 user=postgres dbname=yuduan" \
YUDUAN_HMAC_SECRET="<secret>" YUDUAN_HMAC_ENFORCE=1 \
YUDUAN_DIR_FILE="$(pwd)/directory-sample.json" \
./bin/hub

# 端到端验证（登录/RBAC/强制改密/argon2id/WORM/HMAC/TLS，35 项）
python3 e2e_m6.py
# Rust 生产副端互通（注册/验签/sw_install/wss/远控，12 项；需先构建 rust/agent）
python3 e2e_rust.py
# PostgreSQL + 多中枢总线（连接池/参数化/去粘性/WORM 触发器/持久化，17 项；自动 initdb 本地实例）
python3 e2e_pg.py
# 真实原生编码器全链路（VideoToolbox h264/h265 真码流 + P 帧 + ffmpeg 解码校验，9 项）
python3 e2e_vt_encoder.py
```

> e2e 脚本默认用 8080（环境占用时设置 `YUDUAN_E2E_PORT=18100` 绕开；`e2e_vt_encoder.py` 固定使用 18100）。

### Rust 生产副端

```bash
cd ../rust/agent
rustc -O src/main.rs -o target/agent     # 离线编译（勿用 cargo build）
YUDUAN_HUB=ws://127.0.0.1:8080/ws/agent ./target/agent
```

## 架构（M2–M6 切片）

- 副端 Agent 通过 `ws(s)://hub/ws/agent` 注册、心跳、接收指令、回传结果。
- 主端（Web 控制台，后续 Tauri/React 包装）经 `REST /api/v1/*` 管理；先登录取 Bearer 令牌，接口按 RBAC 角色门禁（admin/operator/viewer）。
- 远控 viewer 经 `ws://hub/ws/viewer` 接入，画面/输入由中枢居中中继（局域网不出公网）。
- 指令（shell / collect / sw_install）由中枢经长连接同步下发，**关键指令带 HMAC-SHA256 签名 + nonce**，Agent 验签后执行，结果经同一连接回传，中枢以 taskID 关联返回。
- 多中枢：有 `YUDUAN_DB_DSN` 时指令先落 PG `cmd_outbox`，由**持有该设备长连接的任意实例**以 `FOR UPDATE SKIP LOCKED` 认领执行（去粘性），NOTIFY + 300ms 轮询双兜底；hub 节点 5s 心跳登记于 `hub_nodes`。
- 存储：有 `YUDUAN_DB_DSN` 走 PostgreSQL（连接池 4/8、参数化查询、WORM 审计链 + 禁改删触发器），否则内存。
- 账号安全：argon2id 口令（`m=64MiB,t=3,p=4` + pepper），admin 首次登录强制改密（4033 门禁），旧格式透明升级。
- 目录同步：AD/LDAP 用户按「组→角色」映射 upsert 为 RBAC 账号。
- 软件仓库：上传落盘 `data/repo/`，Agent 经 HTTP 拉取后按平台静默安装。

## 已知边界（非生产等价）

- **安全**：TLS 已支持（自签证书，:8443；Rust 副端 wss 经 openssl 管道，可配 `YUDUAN_TLS_CAFILE` 严格校验）；HMAC 指令签名/验签已实现（`YUDUAN_HMAC_ENFORCE=1` 强制）。生产需内网 CA 证书、密钥入 KMS、证书固定/mTLS（见 `HA.md` 合规清单）。
- **存储**：零依赖 PG 客户端已具备连接池 + 扩展协议参数化查询；生产如需更完整能力可换 pgx/lib/pq。
- **副端语言**：Go 参考 Agent（`cmd/agent`）与 Rust 生产副端（`rust/agent`）协议等价、已互通；Rust 版 HMAC 验签 / sw_install / 远控 / 系统服务化 / wss 已全部落地（`rust/agent/README.md`）。
- **平台实测**：macOS 已实测（注册/采集/远控/分发/安全/Rust 互通）；本地 PostgreSQL 实测持久化 + 双 Hub 总线。Linux / Windows 分支已写，需在对应平台验证。
- **远控画质**：MVP 用 JPEG base64 中枢中继；生产演进为 P2P 直连 + H.264/H.265 二进制帧（protocol.md §4/§5/§8）。

详见根目录《终端统一管理平台-技术开发文档.md》《开发计划与排期.md》与 `dev/HA.md`。

## 私有 CA（内网 TLS 信任锚，§5）

内网部署推荐自建根 CA（零成本、企业自主掌控，替代一次性自签）：

```bash
cd dev
go build -o bin/ca ./cmd/ca

# 1) 建根 CA + 签发中枢服务器证书（SAN：localhost/127.0.0.1 + -dns/-ip 补充内网名/IP）
./bin/ca init -dir certs -dns hub.office.local -ip 10.0.0.5

# 2) 启动中枢：检测到 certs/ca.pem 自动走 CA 模式（缺证书自动签发 + 到期告警，优先下发 chain.pem 全链）
./bin/hub

# 3) 副端接入（二选一，推荐 PIN）：
#    公钥固定（RFC 7469 SPKI）：YUDUAN_TLS_PIN=$(./bin/ca pin -cert certs/cert.pem)
#    链式严格校验：YUDUAN_TLS_CAFILE=/path/to/certs/ca.pem
# 4) mTLS 设备通道（可选）：YUDUAN_CLIENT_CA=certs/ca.pem 时中枢开 :8444 强制客户端证书
./bin/ca issue-client -dir certs -cn <设备ID>
# 副端追加：YUDUAN_CLIENT_CERT=certs/client-<id>.pem YUDUAN_CLIENT_KEY=certs/client-<id>.key

# 5) 运维：到期检查（<30 天退出码 1，可挂 cron 告警）；轮换服务器证书（1 年有效）
./bin/ca check -dir certs
./bin/ca issue-server -dir certs -dns hub.office.local -ip 10.0.0.5
```

要点：`ca.key` 离线保管（仅签发用，不落生产机）；根 CA 有效期 10 年、叶证书 1 年；
`GenerateRootCA` 幂等（绝不覆盖已有根，覆盖=全网信任重置）；pin 口径与副端
`rust/agent/src/tls.rs` 一致（SHA256(SPKI DER) hex 小写）。端到端实测见
`.workbuddy/memory/2026-10-24.md`（pin/CAFILE/错 pin 拒绝/mTLS 四场景）。
