# 中枢（Hub）企业部署指南

单个静态二进制即可部署，无外部运行时依赖。**三平台产物**：Linux 服务器（systemd）、Windows 管理机、Mac 管理机（launchd）。

## 产物总览

| Release 产物 | 平台 | 常驻方式 |
|---|---|---|
| `YuDuan-hub_<版本>_linux_amd64/arm64.tar.gz` | Linux 服务器 | systemd |
| `YuDuan-hub_<版本>_windows_amd64.zip` | Windows | 控制台 / 计划任务开机自启 |
| `YuDuan-hub_<版本>_macos_<arch>.tar.gz` | macOS（arm64=Apple Silicon / amd64=Intel） | launchd |

通用内容：`env.example`（全量配置模板，三平台同格式）、`README-deploy.md`。

## 一、Linux 服务器（生产推荐）

```bash
tar -xzf YuDuan-hub_v0.1.x_linux_amd64.tar.gz && cd yuduan-hub_*/
sudo ./install.sh
sudo vi /etc/yuduan-hub/env     # 生产至少配 YUDUAN_DB_DSN
sudo systemctl enable --now yuduan-hub
journalctl -u yuduan-hub -f     # 看启动日志
```

## 二、Windows 管理机

```powershell
# 解压 zip 后进入目录：
# 方式 A：前台运行（首次部署观察日志）
.\run-hub.cmd

# 方式 B：服务化（开机自启，SYSTEM 身份，右键「使用 PowerShell 运行」）
.\register-task.ps1
.\register-task.ps1 -Remove    # 卸载
```

- 配置文件：方式 B 自动生成 `C:\ProgramData\yuduan-hub\hub.env`（自动生成 HMAC 密钥与 pepper）；方式 A 用同目录 `hub.env`
- 防火墙放行（管理员 PowerShell）：

```powershell
netsh advfirewall firewall add rule name="yuduan-hub" dir=in action=allow protocol=TCP localport=18241
netsh advfirewall firewall add rule name="yuduan-disc" dir=in action=allow protocol=UDP localport=18242
```

- 更稳的服务方案（可选）：用 [NSSM](https://nssm.cc) 把 `yuduan-hub.exe` 包装成真正的 Windows 服务

## 三、macOS 管理机

```bash
tar -xzf YuDuan-hub_v0.1.x_macos_arm64.tar.gz && cd yuduan-hub_*/
sudo ./install-macos.sh
sudo vi /usr/local/etc/yuduan-hub/env   # 生产至少配 YUDUAN_DB_DSN，改完重跑安装脚本刷新 plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.yuduan.hub.plist
tail -f /usr/local/var/yuduan-hub/hub.log
```

## 防火墙端口（三平台通用）

| 端口 | 协议 | 用途 |
|---|---|---|
| 18241（或 `YUDUAN_HUB_ADDR` 所设） | TCP | 控制台/API/设备通道（明文） |
| 8443（`YUDUAN_TLS_ADDR`，可选） | TCP | TLS/mTLS 设备通道 |
| 18242 | UDP | 副端自动发现广播应答 |

## 副端接入

- **同网段**：零配置，启动即 UDP 广播自动发现并注册
- **跨网段**（广播被路由器隔离）：副端设 `YUDUAN_HUB=ws://<中枢IP>:18241/ws/agent`
- 生产建议：启用 TLS + `YUDUAN_CLIENT_CA`（mTLS），副端经 TLS 端口接入

## 生产检查清单

- [ ] `YUDUAN_DB_DSN` 已配 PostgreSQL（否则内存存储，重启丢数据）
- [ ] `YUDUAN_HMAC_SECRET` 已设置且 `YUDUAN_HMAC_ENFORCE=1`（铁律 4，安装脚本自动生成）
- [ ] `YUDUAN_ADMIN_MUST_CHANGE_PW` 保持默认（=1 强制改密）
- [ ] 副端侧已同步同一 `YUDUAN_HMAC_SECRET`
- [ ] TLS/mTLS 已启用（证书 + `YUDUAN_CLIENT_CA`）
- [ ] 首个管理员登录后立即改掉初始密码

## 升级

- **Linux**：`systemctl stop yuduan-hub` → 覆盖 `/usr/local/bin/yuduan-hub` → `systemctl start yuduan-hub`
- **Windows**：停旧进程/任务 → 覆盖 exe → 重新 `register-task.ps1`
- **macOS**：`launchctl bootout system/io.yuduan.hub` → 覆盖 `/usr/local/bin/yuduan-hub` → `bootstrap`（配置 `/usr/local/etc/yuduan-hub/env` 不会被覆盖）
