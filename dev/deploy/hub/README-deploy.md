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
sudo ./install.sh        # 装完即自动 systemctl enable --now（D-01 不再手动启动）
sudo vi /etc/yuduan-hub/env     # 生产至少配 YUDUAN_DB_DSN，改完 sudo systemctl restart yuduan-hub
tail -f /var/log/yuduan-hub/hub.log   # D-06 日志落盘（或 journalctl -u yuduan-hub -f）
```

## 二、Windows 管理机

```powershell
# 解压 zip 后进入目录：
# 方式 A：前台运行（首次部署观察日志）
.\run-hub.cmd

# 方式 B：服务化（开机自启，SYSTEM 身份，右键「使用 PowerShell 运行」）
.\register-task.ps1      # 注册后即自动 schtasks /Run（D-01 不再手动启动）
.\register-task.ps1 -Remove    # 卸载
```

- 配置文件：方式 B 自动生成 `hub.env` 到脚本所在安装目录（随机 HMAC/PEPPER/SIGN_SEED，ACL 收紧）；方式 A 用同目录 `hub.env`
- 日志：方式 B 自动重定向到 `data\hub.log`（D-06）；方式 A 输出到控制台
- 防火墙：方式 B 自动放行 TCP 8080 / TCP 8443 / UDP 18242；方式 A 手动放行（管理员 PowerShell）：

```powershell
netsh advfirewall firewall add rule name="yuduan-hub" dir=in action=allow protocol=TCP localport=8080
netsh advfirewall firewall add rule name="yuduan-hub-tls" dir=in action=allow protocol=TCP localport=8443
netsh advfirewall firewall add rule name="yuduan-disc" dir=in action=allow protocol=UDP localport=18242
```

- 更稳的服务方案（可选）：用 [NSSM](https://nssm.cc) 把 `yuduan-hub.exe` 包装成真正的 Windows 服务

## 三、macOS 管理机

```bash
tar -xzf YuDuan-hub_v0.1.x_macos_arm64.tar.gz && cd yuduan-hub_*/
sudo ./install-macos.sh   # 装完即自动 launchctl bootstrap（D-01 不再手动启动）
sudo vi /usr/local/etc/yuduan-hub/env   # 生产至少配 YUDUAN_DB_DSN，改完重跑安装脚本刷新 plist
tail -f /usr/local/var/log/yuduan-hub.log   # D-06 日志落盘
```

## 防火墙端口（三平台通用）

| 端口 | 协议 | 用途 |
|---|---|---|
| 8080（或 `YUDUAN_HUB_ADDR` 所设） | TCP | 控制台/API/设备通道（明文） |
| 8443（`YUDUAN_TLS_ADDR`，可选） | TCP | TLS/mTLS 设备通道 |
| 18242 | UDP | 副端自动发现广播应答 |

## 副端接入

- **同网段**：零配置，启动即 UDP 广播自动发现并注册
- **跨网段**（广播被路由器隔离）：副端设 `YUDUAN_HUB=ws://<中枢IP>:8080/ws/agent`
- 生产建议：启用 TLS + `YUDUAN_CLIENT_CA`（mTLS），副端经 TLS 端口接入

## PostgreSQL 持久化（生产必配）

默认后端为**内存**（重启即丢全部设备/任务/审计/告警）。生产必须配置 `YUDUAN_DB_DSN` 指向 PostgreSQL（中枢自动建表，幂等）。

**① 建库建用户**（任选其一）：

```bash
# 方式 A：本机 PostgreSQL（systemd 主机）
sudo -u postgres createuser yuduan -P          # 按提示输入密码
sudo -u postgres createdb -O yuduan yuduan

# 方式 B：Docker 容器
docker exec -it <pg容器> psql -U postgres -c \
  "CREATE USER yuduan PASSWORD 'CHANGE-ME'; CREATE DATABASE yuduan OWNER yuduan;"
```

**② 配置 DSN**（`/etc/yuduan-hub/env`，两种等价格式均可）：

```bash
# URL 格式（推荐，与 libpq 一致）
YUDUAN_DB_DSN=postgres://yuduan:CHANGE-ME@127.0.0.1:5432/yuduan?sslmode=disable
# 或 libpq 键值格式
# YUDUAN_DB_DSN=host=127.0.0.1 port=5432 user=yuduan dbname=yuduan password=CHANGE-ME
```

> 内置 pg 客户端为明文连接，`sslmode`/其余查询参数被忽略；生产建议内网 + 防火墙白名单。

**③ 验证持久化**（改完 `sudo systemctl restart yuduan-hub`）：

```bash
# 登录 → 创建一条用户 → 重启中枢 → 数据仍在即持久化生效
curl -s -X POST http://127.0.0.1:8080/api/v1/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"<初始密码>"}'
```

**④ 备份/恢复**（第 3 批「投产阻断」，PG 模式端到端可用）：
- 手动备份：`POST /api/v1/admin/backup`；列备份：`GET /api/v1/admin/backups`
- 恢复：`POST /api/v1/admin/backup/restore`（body `{"file":"<备份文件名>"}`；恢复前自动做一次安全网备份）
- 自动备份：中枢启动 10s 后产出首备份，此后按 `YUDUAN_BACKUP_INTERVAL`（默认 24h）循环，轮转保留 `YUDUAN_BACKUP_KEEP`（默认 7）份，目录 `YUDUAN_BACKUP_DIR`（默认 `data/backups`）

## 内网根 CA 与 mTLS（生产推荐）

默认中枢用**一次性自签证书**（无信任锚，仅防被动嗅探）。生产纳管建议建立**内网根 CA**，用它签发中枢服务器证书（TLS/mTLS）+ 副端 mTLS 客户端证书。

**① 一键初始化**（`yuduan-ca` 随包分发，`init-ca.sh` 自动构建或使用同目录二进制）：

```bash
# 建根 CA + 签服务器证书（SAN 含中枢主机名/IP）+ 写入中枢 env（TLS_ADDR/CERT/KEY/CLIENT_CA/PIN）
sudo ./init-ca.sh -dns hub.example.com,10.0.0.5 -ip 10.0.0.5
# 仅生成证书不写配置：加 -no-config；指定目录：-dir /etc/yuduan-hub/tls
```

**② 产物**（证书目录）：`ca.pem/ca.key`（根 CA）、`cert.pem/key.pem`（服务器证书）、`chain.pem`（完整链，`YUDUAN_TLS_CERT` 指向它）、`client-<id>.pem/.key`（副端客户端证书，`issue-client` 逐个签发）。

**③ 副端接入**（分发 `ca.pem` 到副端，任选其一）：
- 严格链校验：`YUDUAN_TLS_CAFILE=<ca.pem>`
- 公钥固定（推荐，防 CAfile 泄露面）：`YUDUAN_TLS_PIN=$(yuduan-ca pin -cert cert.pem)`

**④ 运维**：轮换服务器证书 `yuduan-ca issue-server -dir <目录> -dns ... -ip ...`；到期检查 `yuduan-ca check -dir <目录>`（<30 天退出码 1，可挂 cron 告警）；**根 CA 私钥 `ca.key` 生成后立即移出中枢生产机离线保管**。

## 生产检查清单

- [ ] `YUDUAN_DB_DSN` 已配 PostgreSQL（否则内存存储，重启丢数据）
- [ ] `YUDUAN_HMAC_SECRET` 已设置且 `YUDUAN_HMAC_ENFORCE=1`（铁律 4，安装脚本自动生成）
- [ ] `YUDUAN_ADMIN_MUST_CHANGE_PW` 保持默认（=1 强制改密）
- [ ] 副端侧已同步同一 `YUDUAN_HMAC_SECRET`
- [ ] TLS/mTLS 已启用（证书 + `YUDUAN_CLIENT_CA`）
- [ ] 首个管理员登录后立即改掉初始密码

## 升级

三平台安装脚本均自动「停旧 → 替换 → 起新」（D-02 修复，无需手动停旧）：

- **Linux**：直接 `sudo ./install.sh <新二进制>` —— 检测到运行中服务先 `systemctl stop`，替换后 `systemctl start`；`/etc/yuduan-hub/env` 不被覆盖
- **Windows**：覆盖 `yuduan-hub.exe` 后重新 `.\register-task.ps1` —— 先 `schtasks /End` 停旧循环，注册后自动 `/Run`；`hub.env` 保留（-ResetConfig 才重生成）
- **macOS**：直接 `sudo ./install-macos.sh <新二进制>` —— 先 `launchctl bootout` 停旧，替换后 `bootstrap` 起新；`/usr/local/etc/yuduan-hub/env` 不被覆盖

> 升级注意：`hub.env` / `env` 的 `YUDUAN_HMAC_SECRET` 若改变，副端需重新 claim（同机副端由安装脚本自动同步）。
