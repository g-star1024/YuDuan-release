# YuDuan-release

御端（YuDuan）官方发布仓库。源代码在私有仓 [g-star1024/YuDuan](https://github.com/g-star1024/YuDuan)。

> 当前版本：**v0.4.3** —— Windows 中枢控制台已内嵌进 `yuduan-hub.exe`，修复生产环境访问 `:8080` 返回 404 的问题；部署脚本含重部署孤儿进程清理。

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
