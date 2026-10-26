# Windows 实机验证清单

> 目标：在真实 Windows 机器上完成三件事——① MF 编码器 DLL 运行时验证（当前唯一
> 「待实机」项）；② 副端 Windows 冒烟（注册/心跳/指令）；③ 远控 h264 全链路。
> 按阶段推进，每阶段给出「执行命令 + 预期输出 + 需回传证据」。卡住时把完整报错
> 截图回传即可，不用自行排查。

## 阶段 0：文件准备

从仓库拷贝以下内容到 Windows 机器（如 `C:\yuduan\`，路径可含空格但不建议）：

| 内容 | 来源 | 用途 |
|---|---|---|
| `dev/encoder-mf/` 整个目录 | 仓库 | MF 编码器源码 + 构建脚本 + harness |
| `dev/bin/windows/hub.exe` | 已交叉编译好 | 中枢（零安装） |
| `dev/bin/windows/agent.exe` | 已交叉编译好 | Go 参考副端（零安装） |
| `dev/bin/windows/p2pviewer.exe` | 已交叉编译好 | 远控查看器 |
| `dev/console/` 整个目录 | 仓库 | Web 控制台静态页 |
| `rust/agent/src/` + `rust/agent/Cargo.toml` | 仓库 | Rust 生产副端源码（阶段 3 用） |

## 阶段 1：MF 编码器 DLL 直测（核心，约 10 分钟）

**只依赖 VS Build Tools，无需 Go/Rust。**

1. 安装 Visual Studio 2022 Build Tools（微软官网免费），勾选 **"使用 C++ 的桌面开发"**
   工作负载（含 Windows SDK）。已装过可跳过。
2. 开始菜单打开 **"x64 Native Tools Command Prompt for VS 2022"**（必须是 x64 版）。
3. 执行：

```cmd
cd C:\yuduan\encoder-mf
build-windows.cmd
build-harness.cmd

:: 直测：1280x720，编码 60 帧，输出裸流
enc_harness.exe %TEMP%\yuduan_enc_mf.dll h264 1280 720 60 out.h264
```

**预期输出**：`create OK codec=h264 1280x720`，随后 60 行 `frame N: xxx bytes`
（首帧应显著大于后续帧=含 SPS/PPS/IDR；后续帧大小波动=有真实帧间预测），
最后 `OK frames=60 total=... bytes -> out.h264`。

4. 码流交叉验证（二选一）：
   - 若装有 ffmpeg：`ffprobe -v error -show_streams out.h264` 应报 h264 流、
     分辨率 1280x720、无 error；`ffplay out.h264` 应能看到渐变画面+移动白块。
   - 无 ffmpeg：直接把 `out.h264` 拷回给开发侧验证（码流本身即证据）。

5. 失败排查：先 `set YUDUAN_ENC_DEBUG=1` 重跑 harness，把各阶段 HRESULT 截图回传。
   常见失败：N 版 Windows 缺媒体特性包（无 H.264 编码 MFT，属环境问题非代码问题）。

**回传证据**：build 两条命令的完整输出 + harness 运行输出截图 + out.h264 文件。

## 阶段 2：中枢 + 控制台 + Go 参考副端冒烟（零安装，约 5 分钟）

```cmd
:: 窗口 1：启动中枢（8080 被占会自动回退 8081/8082/8083/18080，以启动日志打印为准）
set YUDUAN_ADMIN_MUST_CHANGE_PW=0
hub.exe

:: 窗口 2：启动 Go 参考副端（地址按窗口 1 实际端口改）
set YUDUAN_HUB=ws://127.0.0.1:8080/ws/agent
agent.exe
```

**预期**：窗口 1 打印中枢监听地址与「内置 admin」提示；窗口 2 打印
`注册成功`-类日志；浏览器打开 `http://127.0.0.1:8080/`（端口按实际）→
账号 `admin` / `admin123`（本次已关强制改密）→ 「设备」页应出现这台
Windows 主机（资产采集：hostname/os/cpu/mem/disk 等齐备）。

**回传证据**：两个窗口的日志截图 + 控制台设备页截图。

## 阶段 3：Rust 生产副端（注册/心跳/HMAC 指令）

1. 安装 Rust：`winget install Rustlang.Rustup`（或 rustup.rs 下载 rustup-init.exe），
   装完重开命令行确认 `rustc --version` 可用。
2. 编译（不要用 cargo，离线直编）：

```cmd
xcopy C:\yuduan\rust\agent\src C:\yuduan\rustbuild\src\
copy C:\yuduan\rust\agent\Cargo.toml C:\yuduan\rustbuild\
cd C:\yuduan\rustbuild
rustc -O src/main.rs -o agent.exe
```

3. 运行（ws 明文模式；Windows 默认无 openssl，wss 管道模式不支持，属已知限制）：

```cmd
set YUDUAN_HUB=ws://127.0.0.1:8080/ws/agent
set YUDUAN_HMAC_SECRET=test-secret
agent.exe

:: 中枢侧同步（重启窗口 1 前设置）：
::   set YUDUAN_HMAC_SECRET=test-secret  再启动 hub.exe
```

**预期**：注册成功、30s 心跳；控制台下发给该设备的 `shell` 指令（如
`whoami`）能收到回执（HMAC 验签通过）；故意改错副端密钥应回执 failed 而非执行。

**回传证据**：注册/心跳日志截图 + 一条 shell 指令回执截图。

## 阶段 4：远控 h264 全链路（MF 编码器接入副端）

```cmd
:: 副端窗口：
set YUDUAN_HUB=ws://127.0.0.1:8080/ws/agent
set YUDUAN_ENCODER_LIB=%TEMP%\yuduan_enc_mf.dll
agent.exe
```

浏览器控制台 → 该设备 → 发起远控（codec 选 h264）。

**预期**：副端日志打印「原生编码器 h264」加载成功（而非回退 RAW_RGBA/JPEG）；
控制台画面流畅且带宽显著低于 JPEG 模式；中断后可正常 stop。

**回传证据**：副端启动日志（编码器加载行）+ 控制台远控画面截图 + 一段观感描述
（延迟/清晰度）。

## 阶段 5（可选）：服务化

管理员 PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File C:\yuduan\rust\agent\deploy\windows\install-agent.ps1
Get-Service yuduan*
```

（需先按脚本顶部变量改中枢地址与密钥；卸载加 `-Uninstall`。）

## 已知限制（Windows 侧，测试时不必惊讶）

- Rust 副端 wss 需 `openssl s_client`（Windows 默认没有）→ 测试用 `ws://`；
  TLS 收口在私有 CA / mTLS 里程碑（已另有方案）。
- 副端 TLS 证书固定模式同理仅在明文不可用的现场才需要，局域网测试可跳过。
- Go 参考副端不加载 MF DLL（C-ABI 加载在 Rust 副端实现）→ 阶段 4 必须用 Rust 副端。
- 无 GPU 远程会话时 MS 软编码 MFT 仍可用（系统组件）；N 版缺媒体特性包除外。
