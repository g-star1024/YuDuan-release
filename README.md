# YuDuan-release

御端（YuDuan）官方发布仓库。源代码在私有仓 [g-star1024/YuDuan](https://github.com/g-star1024/YuDuan)。

> 当前版本：**v0.4.9** —— 部署/清理体验修复：① 新增官方重装清理脚本 **cleanup.ps1**（随 Windows 中枢包分发，中枢+副端一体清：计划任务/防火墙规则/残留进程/副端服务/YUDUAN_* 环境变量），**先探测再执行**——目标不存在时打灰色 `[SKIP]` 而非红色报错，消除现场「清理报错=部署失败」误判；② register-task.ps1 的 -Remove 卸载与升级停旧同样改为探测式输出。配置与数据（hub.env、data\）一律不动。

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
