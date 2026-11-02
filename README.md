# YuDuan-release

御端（YuDuan）官方发布仓库。源代码在私有仓 [g-star1024/YuDuan](https://github.com/g-star1024/YuDuan)。

> 当前版本：**v0.4.8** —— v0.4.7 实测报告四项修复：① 部署自检改为轮询 hub.log 「内置 admin 账号就绪」行（≤60s）再测登录，根治 ~40s 启动竞态误报；② 计划任务电池策略属性名修正（DisallowStartIfOnBatteries=false）+ 回读断言；③ 副端一键安装器非交互场景（--quiet / stdin 非控制台）自动跳过回车等待，自动化部署不再挂起；④ 设备注册幂等化——token 轮换后按硬件身份（serial → hostname+mac）复用既有设备 ID，台账不再重复建档，分组/生命周期属性保留；副端支持 YUDUAN_HOSTNAME/MAC/SERIAL 身份覆盖（多设备模拟/容器场景）。

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
