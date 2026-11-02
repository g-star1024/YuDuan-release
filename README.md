# YuDuan-release

御端（YuDuan）官方发布仓库。源代码在私有仓 [g-star1024/YuDuan](https://github.com/g-star1024/YuDuan)。

> 当前版本：**v0.4.7** —— v0.4.5 实测报告问题 1/3/6/7 修复：① 部署自检③登录重试仅 code=0 跳出（401/000 重试约 21s，消除启动竞态 WARN）；② 计划任务放开电池启动策略（笔记本电池开机也会自启）；③ 副端安装器升级路径——旧服务停不掉时按 PID 强杀兜底、仍失败显式报错（不再长时间无输出挂起），无权限时不再假报「已常驻」；④ 副端版本标识对齐发布号（agent_version=0.4.7）+ 测试指引 5-4 片段勘误。含 v0.4.6 全部主端升级（软件上传文件弹窗 / RBAC 角色显性适配）。

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
