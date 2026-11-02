# YuDuan-release

御端（YuDuan）官方发布仓库。源代码在私有仓 [g-star1024/YuDuan](https://github.com/g-star1024/YuDuan)。

> 当前版本：**v0.4.10** —— v0.4.8 实测报告四项修复：① 副端版本串构建期注入（YUDUAN_AGENT_VERSION=发布号）+ 发布断言，杜绝 v0.4.8 式「包 0.4.8 自报 0.4.7」回归；② 部署自检就绪轮询按 hub.log 字节偏移只扫本轮新增行（旧实例残留行不再 0 秒放行），hub 就绪日志移到 Serve 前打印（信号即登录真正可用）；③ 副端安装器回车等待加 15s 倒计时超时（提权脚本链场景不再挂起）；④ 设备 ID 硬件指纹稳定派生（sha256 前 16 hex，Go/Rust/python 三方同构）——内存模式重启/重装/换中枢不再换设备 ID。⑤ macOS 主端/副端 ad-hoc 自签名（消除「已损坏」误报）。含 v0.4.9 全部内容（官方清理脚本 cleanup.ps1，[SKIP] 灰显）。

## 下载

见右侧 [Releases](https://github.com/g-star1024/YuDuan-release/releases)：

| 产物 | 说明 |
|---|---|
| `YuDuan-main_*_macos.dmg` | macOS 主端（未签名，首次打开右键 → 打开） |
| `YuDuan-main_*_windows.exe` | Windows 主端（免安装，直接运行） |
| `YuDuan-agent_*_windows.exe` | Windows 副端（UDP 自动发现中枢，零配置注册） |
| `YuDuan-hub_*_linux_*.tar.gz` | Linux 中枢（systemd，`sudo ./install.sh`） |
| `YuDuan-hub_*_windows_amd64.zip` | Windows 中枢（前台运行或计划任务自启） |
| `YuDuan-hub_*_macos_*.tar.gz` | macOS 中枢（launchd，`sudo ./install-macos.sh`） |

## 发布流程

推送 `v*` 标签到本仓库 → CI 自动从私有仓拉取同名标签源码，构建三平台产物并发布 Release。
