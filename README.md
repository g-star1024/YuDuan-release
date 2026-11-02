# YuDuan-release

御端（YuDuan）官方发布仓库。源代码在私有仓 [g-star1024/YuDuan](https://github.com/g-star1024/YuDuan)。

> 当前版本：**v0.4.6** —— 主端体验升级：① 软件上传接入原生「选择文件」弹窗（tauri-plugin-dialog，选中后自动预填软件名/版本，手动粘贴路径保留为兜底）；② RBAC 角色显性适配——非 admin 隐藏「用户管理」导航，用户管理/备份/上传区对无权限角色给出明确说明（不再弹 401 报错；用 admin 账号登录主端即可管理用户与备份，功能不受限，与网页控制台权限口径一致）。含 v0.4.5 全部修复（真实 HTTP 401 / 部署自检防误报 / 指引勘误 / PG 投产阻断提示）。

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
