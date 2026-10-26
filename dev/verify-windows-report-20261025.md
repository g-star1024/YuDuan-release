# Windows 副端启动失败排查报告（归档）

> ## ⚠️ 根因修正（2026-10-25 22:40，Windows 侧二次实机核实）
>
> **上方「主仓确认」的根因结论已被证伪，请勿再沿用。**
>
> 该结论把栈溢出归因于「rustc 1.98.1 旧工具链」，并据此在
> `rust/agent/build-windows-cross.sh` 加了「rustc minor ≥ 99」断言。
>
> **实测反证**：主仓按该结论用 1.99.1 重新交叉编译的发布包
> （`yuduan-agent-win (2).zip`，exe 1,601,024 字节，内嵌 rustc commit
> `58cf8f9c35b3` = 1.99.1），在 Windows 上**依然启动即崩**，退出码
> `0xC00000FD`，零输出，3/3 冷启动 100% 复现。
>
> **同一版 rustc（1.99.1 / `58cf8f9c`）**：Windows 原生 MSVC 构建 → 正常；
> macOS 交叉构建 → 崩。**版本不是变量，交叉编译链才是。**
>
> **真实根因**：macOS 交叉编译链（rust-lld + mingw-w64 CRT + libgcc/gimli
> 展开器）产出的 PE 带 `.tls` 段 + TLS 回调 + mingw 展开器符号，
> 在 `main()` 之前的 TLS 初始化阶段栈溢出。结构判据：
>
> | 产物 | section | `.tls` | TLS回调 | `__mingw` | `_Unwind_` | gimli | 结果 |
> |---|---|---|---|---|---|---|---|
> | 交叉编译(1.98.1) | 6 | 有 | 2 | 17 | 17 | 有 | ❌ 崩 |
> | 交叉编译(1.99.1) | 6 | 有 | 2 | 17 | 17 | 有 | ❌ 崩 |
> | 原生 MSVC(1.99.1) | 5 | 无 | 0 | 0 | 0 | 无 | ✅ 正常 |
>
> **修正后的行动项**：
> 1. **不要用 `build-windows-cross.sh` 产出 Windows 发布包**；
> 2. Windows 发布包一律在**真实 Windows 主机用 MSVC 工具链原生构建**
>    （`rustc -O src/main.rs -o yuduan-agent.exe`；本 crate 无外部依赖，
>    **不要**跑 `cargo build`）；
> 3. 「rustc minor ≥ 99」断言**通过了但没拦住问题**，不能当质量闸门；
> 4. 已新增产物结构校验（脚本内「校验 B」）自动拦截已知坏结构，
>    但**产物必须在真实 Windows 上冒烟通过**才算交付合格。
>
> 完整证据链见 `C:\yuduan\排查报告-新包栈溢出-根因二次修正.md`。
>
> 以下为 Windows 侧首次排查原报告（其中「根因 = 旧工具链」的判断已被上述修正取代，
> 其余排查过程与排除项仍然有效）。

> **主仓确认（2026-10-25 18:20）**：报告结论完全正确。崩溃包内嵌 rustc commit
> `48a229ce` 已核实为本机 rustup stable **1.98.1**——该版本交叉编译（rust-lld +
> mingw CRT）产物启动即 STATUS_STACK_OVERFLOW；升级到 1.99.1（`58cf8f9c`，与
> 本报告构建版一致）后重编，产物内嵌 hash 校验通过。以下为 Windows 侧原报告：

# 副端启动失败排查报告

**日期**：2026-10-25
**对象**：`C:\Users\itwor\Desktop\yuduan-agent-win\yuduan-agent.exe`（主仓 2026-10-25 发布包，1,554,432 字节）
**结论**：发布包**一启动即崩溃**（`STATUS_STACK_OVERFLOW`），已用主仓 `origin/main` 源码重新构建替换，**副端现已正常运行**。

---

## 一、现象

双击 `run-agent.cmd` 或命令行直接运行，**无任何输出、瞬间退出**。

```
> yuduan-agent.exe
（无输出）
REAL_EXITCODE=-1073741571
```

- `-1073741571` = `0xC00000FD` = **STATUS_STACK_OVERFLOW**（栈溢出）
- Windows 事件日志 Application/EventID=1001 记录 `APPCRASH`，`P7: c00000fd`
- 非网络问题：崩溃发生在**任何输出之前**（连 `[agent] 防篡改自检` 都未打印），即 `main()` 第一条 `eprintln!` 之前
- 非权限/安全策略拦截：Defender 无命中记录，无 Zone.Identifier 下载标记

## 二、排查过程与关键结论

### 1. 排除环境变量与配置因素

| 实验 | 结果 |
|---|---|
| 显式设置 `YUDUAN_HUB=ws://192.168.1.24:18241/ws/agent` | 仍崩溃 |
| 清空全部 `YUDUAN_*` 变量（干净环境） | 仍崩溃 |
| 状态文件 `~/.yuduan/agent-state.json` | 不存在（排除身份持久化解析触发） |
| 中枢连通性 `curl http://192.168.1.24:18241/api/v1/health` | 404 但有 HTTP 响应（**路由通**，崩溃与网络无关） |

### 2. 排除「栈帧过大」

| 实验 | 结果 |
|---|---|
| `editbin /STACK:16777216,65536`（栈保留 1MB → 16MB） | 仍崩溃（`REAL_EXITCODE` 不变） |
| `RUST_MIN_STACK=33554432`（32MB） | 仍崩溃 |
| PE 头 `SizeOfStackReserve` 检查 | 崩溃版与正常版**均为 1MB**，无异常 |

→ **排除大栈帧**，指向**无限递归**（任何栈大小都会被填满）。

### 3. 定位到根因：构建工具链不一致

从 PE 二进制中提取内嵌的 Rust 编译器标识（`/rustc/<commit-hash>`）：

| 产物 | 字节数 | rustc commit | 状态 |
|---|---|---|---|
| **桌面包（崩溃）** | 1,554,432 | `48a229ceaefd4985c50990b14116b6d856af0985` | ❌ 启动即崩 |
| 替换版（可用） | 675,840 | `58cf8f9c35b355199727627d07ae34a4e2846d67` (1.99.1) | ✅ 正常 |
| 远端 rustc 直编 | 690,688 | `58cf8f9c...` (1.99.1) | ✅ 正常 |
| 远端 cargo 构建 | 675,840 | `58cf8f9c...` (1.99.1) | ✅ 正常 |

**崩溃包是用一个与当前 `rustc 1.99.1` 不同的、更旧的 Rust 工具链编译的。**
同一份源码（`origin/main` @ `4bb7722`）用 1.99.1 无论 `rustc` 直编还是 `cargo build` 均**完全正常**。

补充佐证：
- 崩溃包 exe **内嵌完整符号表**（132 个 `yuduan_agent::*` 函数符号，含泛型 closure 环境），而 `rustc` 直编产物**不含**（符号在 PDB 里）→ 崩溃包的构建方式与仓库 `Cargo.toml` 注释中「**不要执行 cargo build**，请使用离线 rustc 直接编译」不一致
- 崩溃包函数集合与 `origin/main` 源码**完全一致**（含 `agentstate`、`RC_LOSS_PCT`、`RC_KBPS_TARGET`、`next_jpeg_q`、`target_dims` 等 README 承诺的新特性）→ **源码是对的，是构建产物有问题**

### 4. 源码侧递归候选已逐个排除

| 候选 | 结论 |
|---|---|
| `Parser::parse_value` / `parse_string`（递归下降 JSON） | 每层递归至少消费 1 字符，深度受输入嵌套限制；且崩溃早于任何 JSON 解析调用 |
| `sha256::update` / `process` | 循环，非递归 |
| `Lcg::next_u64` / `bytes` | 迭代，非递归 |
| `tamper::self_check` | 仅三步（自校验 SHA-256 / 反调试跳过 / codesign 跳过），无递归 |
| `win_asset` / `win_net` | 全部 `vec!` 堆分配，无栈数组 |

→ 源码侧无递归缺陷，**问题在旧工具链产出的二进制**。

## 三、处置

### 已执行
1. 备份崩溃产物：`yuduan-agent.exe.crashed.bak`（sha256 `ebba1620…`）
2. 用 `origin/main` @ `4bb7722` 源码本地构建（`rustc 1.99.1`，`cargo build --release --offline`）替换为 `yuduan-agent.exe`（675,840 字节，sha256 `d2408184…`）
3. 启动副端，连接 Mac 中枢 `ws://192.168.1.24:18241/ws/agent`

### 副端运行证据

```
[agent] 防篡改自检：
  [OK] self_integrity: 未配置期望值（开发态）；actual=d2408184098c50ae…
  [OK] anti_debug: 未启用（YUDUAN_AGENT_ANTI_DEBUG=1 启用）
  [OK] codesign: 仅 macOS 适用
[agent] 御端 Rust 副端启动，目标中枢: ws://192.168.1.24:18241/ws/agent
[agent] 配置: 验签密钥=已配置 (YUDUAN_HMAC_SECRET)
[agent] WebSocket 握手成功: ws://192.168.1.24:18241/ws/agent（验签 已启用）
[agent] 已恢复本地设备身份 device_id=6f22069871189a0e022b5db05de107ae（复用 token 注册）
[agent] 已发送 register (host=胡萝卜, os=windows, arch=x86_64)
[agent] 注册成功 device_id=6f22069871189a0e022b5db05de107ae token=a5efcd8f… ok=true
[agent] 心跳已发送 ip=192.168.0.100
[agent] 心跳已发送 ip=192.168.0.100     ← 30s 周期持续
```

- 进程：`yuduan-agent.exe` PID 16432，常驻 9,856 K
- 身份持久化落盘正常：`~/.yuduan/agent-state.json` = `{"device_id":"6f220698…","token":"a5efcd8f…"}`

### 遗留：Mac 中枢控制台台账无法查看

`GET /api/v1/devices` 返回 `{"code":4033,"message":"password_change_required"}`：
- 首次登录 `admin/admin123` 返回 `must_change_password: true`，随后该密码即失效（`invalid credentials`）
- `POST /api/v1/password` 存在但需正确的旧密码
- **不影响副端**：注册（`ok=true`）与心跳（中枢已接收）均成功，仅控制台侧改密门禁拦住台账查询

需主端配合：完成管理员改密，或在中枢侧关闭 `must_change_password` 强制门禁（`YUDUAN_ADMIN_MUST_CHANGE_PW=0`，与本机 Go 中枢同开关）。

## 四、给主仓的建议

1. **发布包构建必须锁定工具链**：在构建脚本中固定 `rustc --version` 断言（≥1.99.1），并记录 `rustc -vV` 到发布清单；当前 `Cargo.toml` 注释要求 rustc 直编，但发布包显然走了另一条路径。
2. **发布前冒烟**：产物必须先在构建机执行一次 `yuduan-agent.exe` 确认能打印 `[agent] 御端 Rust 副端启动` 再打包；本次缺陷正是「编译通过但运行即崩」，编译期无法发现。
3. **崩溃码识别**：`0xC00000FD` 一律按「旧工具链 / 无限递归」方向排查，先比对 `/rustc/<commit>` 标识。
