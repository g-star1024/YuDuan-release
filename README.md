# YuDuan-release

御端（YuDuan）官方发布仓库。源代码在私有仓 [g-star1024/YuDuan](https://github.com/g-star1024/YuDuan)（私有维护，本仓库仅提供发布产物）。

> 当前版本：**v0.4.56** —— 主端 + 中枢 + 副端三端齐备：资产台账与变更时间线、局域网/中继远程控制、软件静默分发、策略合规与告警外送（Webhook / 企业微信 / SMTP）、报表订阅导出；可选公网模式（TLS + ACME 证书自动续期），默认局域网部署。

## 官网

<https://g-star1024.github.io/YuDuan-release/>（即将由本仓库 gh-pages 分支发布）

## 下载

见右侧 [Releases](https://github.com/g-star1024/YuDuan-release/releases)，每个 Release 共 16 个产物：

| 分组 | 产物 | 说明 |
|---|---|---|
| 副端（5 个） | `YuDuan-agent_*` | Windows / macOS / Linux 系统服务，UDP 自动发现中枢，零配置注册 |
| 中枢（5 个） | `YuDuan-hub_*_linux_*.tar.gz` | Linux 中枢（systemd，`sudo ./install.sh`） |
|  | `YuDuan-hub_*_windows_amd64.zip` | Windows 中枢（前台运行或计划任务自启） |
|  | `YuDuan-hub_*_macos_*.tar.gz` | macOS 中枢（launchd，`sudo ./install-macos.sh`） |
| 主端（6 个） | `YuDuan-main_*_macos.dmg` | macOS 主端（未签名，首次打开右键 → 打开） |
|  | `YuDuan-main_*_windows_*` | Windows 主端（免安装 exe / setup.exe 安装包） |
| 数据库 | `YuDuan-hub-server-db_*` | PostgreSQL 离线包（内存模式仅供评估，生产建议配 PostgreSQL DSN） |

## 快速上手

1. 装中枢：下载 hub 包并运行 `deploy.bat`（Windows）/ `install.sh`（Linux / macOS）。
2. 装副端：下载 agent 包安装，自动发现中枢并注册。
3. 装主端：安装 macOS dmg / Windows 安装包，登录即可管理。

部署详见私仓 `dev/deploy/hub/README-deploy.md`。提示：memory 模式仅供评估，生产环境请配置 PostgreSQL DSN。

## 发布流程

推送 `v*` 标签到本仓库 → CI 自动从私有仓拉取同名标签源码，构建三平台产物并发布 Release。
