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
- 防火墙：方式 B 自动放行 TCP 8080 / TCP 8443 / UDP 18242（默认 18242，可由 `YUDUAN_DISCOVERY_PORT` 覆盖）；方式 A 手动放行（管理员 PowerShell）：

```powershell
$discoveryPort = 18242   # 默认 18242，可由 YUDUAN_DISCOVERY_PORT 覆盖（须与 hub.env 一致）
netsh advfirewall firewall add rule name="yuduan-hub" dir=in action=allow protocol=TCP localport=8080
netsh advfirewall firewall add rule name="yuduan-hub-tls" dir=in action=allow protocol=TCP localport=8443
netsh advfirewall firewall add rule name="yuduan-disc-udp" dir=in action=allow protocol=UDP localport=$discoveryPort
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
| 18242（默认，可由 `YUDUAN_DISCOVERY_PORT` 覆盖） | UDP | 副端自动发现广播应答 |

> UDP 发现端口默认 18242，可由 `YUDUAN_DISCOVERY_PORT` 覆盖；下文所有 `18242` / 发现端口均指该默认端口，
> 多实例并存 / 自定义端口见下方「多实例并存 / 自定义发现端口」小节。

## 副端接入

- **同网段**：零配置，启动即 UDP 广播自动发现并注册
- **跨网段**（广播被路由器隔离）：副端设 `YUDUAN_HUB=ws://<中枢IP>:8080/ws/agent`
- 生产建议：启用 TLS + `YUDUAN_CLIENT_CA`（mTLS），副端经 TLS 端口接入

## 多实例并存 / 自定义发现端口（v0.4.29 / F-07）

UDP 自动发现的「客户端广播目标端口 ↔ 中枢 UDP 监听端口」是**带外约定**，广播帧不携带发现端口，
**帧格式与 `Ver=1` 均不变**。默认端口 **18242**，可由 `YUDUAN_DISCOVERY_PORT` 覆盖（1..65535），
**三端必须一致**：

| 端 | 配置位置 |
|---|---|
| 中枢（hub） | `env` / `hub.env` 的 `YUDUAN_DISCOVERY_PORT`（部署脚本写文件，各托管方式加载整个 env 文件） |
| 副端 | 机器级环境变量 `setx /M YUDUAN_DISCOVERY_PORT <端口>`（服务由 SCM/SYSTEM 拉起，只读机器级；User 级读不到） |
| 主端 | GUI 设置项中的发现端口 |

- **env 注入链（两条独立路径，取值须一致）**：
  - 中枢：systemd `EnvironmentFile`、launchd plist `EnvironmentVariables`、`run-hub.cmd` 与 Windows 服务 bat
    **都加载整个 env 文件**，在 env 模板 / 生成处加键即注入，无需改 service / plist / bat 的加载逻辑。
  - 副端：服务由 SCM/SYSTEM 拉起，读**机器级**环境变量，用 `setx /M YUDUAN_DISCOVERY_PORT <端口>` 注入
    （User 级服务读不到）；**必须在副端服务启动之前**注入——服务启动时一次性读取，运行中改需重启服务。
  存量升级不覆盖已有 env（install.sh / install-macos.sh 保留），中枢**要用新端口需手工加键**；
  三端缺省 / 非法 / 0 / 超 u16 一律回落 18242，代码不硬编码端口，默认 LAN 零回归。
- **★ `YUDUAN_DISCOVERY_PORT` 不得加入任何「重装清理」清单**：一键安装 / `--setup` 的
  `clean_deployment_env()` 用 `reg delete` 清理历史残留且**不回写**——若把发现端口列入清理项，
  双击安装会把它抹掉、服务进程回落默认 18242，自定义端口在最主要的一键路径直接失效。
  中枢 `register-task.ps1` / `cleanup.ps1` 的「先清后写」foreach 与副端 `install-agent.ps1` /
  `rust/agent/src/setup.rs::DEPLOY_ENV_NAMES` 的清理清单**均不纳入该键**（清单项数以代码实际为准，
  不在文档固化，避免清单增减时文档过时）；要脚本写入只在「写入新配置」段按需 `setx`，清理段排除它。
- **帧内 ws 地址本就区分实例**：广播应答帧带 `http=` / `ws=` 具体地址，不同实例即便共用发现端口也能按帧内地址区分；
  多实例并存时让每个实例及其客户端使用**同一个非默认端口**即可彻底隔离广播域。
- **配错端口会拿到别的实例的 token 导致 claim 失败**：三端口径不一致时，客户端向错误端口广播收不到本实例应答，
  或收到别的实例的应答帧并拿其地址 / token 去 claim，因实例 / HMAC 不匹配而失败；排障先核对三端
  `YUDUAN_DISCOVERY_PORT` 是否一致。

## PostgreSQL 持久化（生产必配）

**v0.4.30 起默认失败即中止**：一键/脚本部署若未配置 `YUDUAN_DB_DSN` 且未能自动就绪，将**明确报错中止**部署（不再静默回退内存模式丢数据）。生产必须配置 `YUDUAN_DB_DSN` 指向 PostgreSQL（中枢自动建表，幂等）；仅测试可加 `--memory`（Linux/macOS）或 `-Memory`（Windows）显式允许内存模式（重启即丢全部设备/任务/审计/告警）。

> **Windows 一键部署（v0.4.22 起）本节可全自动**：`deploy.bat → register-task.ps1` 自动检测宿主机
> PostgreSQL；未检出时优先解压同目录捆绑包 `pgsql-windows-x64-binaries.zip`（离线），否则自动下载
> EDB 官方便携包（固定版本 16.9-1）装为 `yuduan-pg` 服务（仅监听 127.0.0.1:5432，开机自启），
> 并自动创建 yuduan 角色/库（随机 24 位 hex 口令）后把 DSN 写入 `hub.env`。
> 下面 ①② 手工步骤仅适用于 Linux/macOS 部署，或 Windows 需要连接远程 PG 服务器时。

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

---

## 客户自建公网部署（v0.4.29 修订版 · P1 公网形态）

> **定位声明**：服务器、域名、DNS、证书、防火墙全部由客户自备并自运维；官方**不运营、不托管、不依赖**
> 任何公网服务端、中继或代管域名（铁律 1 v1.2 / Gate G-2026-11-06-02）。但产品**内置公网远控能力包**：
> LAN/公网 开关、自绑域名、ACME 自动签发与自传证书双轨、一键部署向导，客户一键部署即可自选 LAN 或公网。
> v0.4.26 起提供**显式公网形态开关**（Windows `-Public` / Linux `--public` / macOS `--public`，对应
> `YUDUAN_NET_MODE=public`），默认 `lan` 不变；公网形态需显式 TLS 证书与域名，并强制显式
> `YUDUAN_TLS_CERT`/`YUDUAN_TLS_KEY`（详见 §G「公网形态约束」）。
>
> **默认 LAN 零影响**：未执行本章任何配置时，部署行为与 v0.4.24 局域网默认完全一致——
> `:8080` 明文 + `:8443` TLS + UDP `:18242`（默认 18242，可由 `YUDUAN_DISCOVERY_PORT` 覆盖）自动发现并存，协议字段与 `Ver=1` 不变。
> 本章全部为纯增量配置，不改端口、不改监听、不改代码。

### A. 适用边界与前置

| 客户自备项 | 说明 |
|---|---|
| 服务器 / 公网 IP | 客户自有，产品不提供 |
| 域名 + DNS A/AAAA 记录 | 客户自绑定，产品不代绑定 |
| TLS 证书 | 用中枢包内 `yuduan-ca` 私有 CA 签发（见 B），也可用客户自有 CA |
| 防火墙 / 反向代理 | 客户侧配置，产品不托管 |

- **公网形态不使用 UDP 自动发现**：`:18242`（默认 18242，可由 `YUDUAN_DISCOVERY_PORT` 覆盖）广播只回本机/同网段 IP，公网客户端收不到帧，
  主端 `discover` 列表为空即不显示中枢。**必须静态配置**
  `YUDUAN_HUB=wss://YOUR_DOMAIN:8443/ws/agent`，不能依赖自动发现。
  残留风险显式说明：`ServeDiscovery` 用明文监听串拼广播帧，若 `YUDUAN_HUB_ADDR` 被写成带
  主机名的形式会产出畸形 UDP 应答帧；本轮按裁决选 A **不改该变量**，靠客户防火墙阻断公网
  8080/18242（默认，可覆盖） + 静态 `YUDUAN_HUB` 让该帧不可达，因此可接受。中枢就绪探针已自行做
  `net.SplitHostPort` 归一且只打回环，不受影响，不会误判启动失败。
- **地址必须写全端口**：**必须**使用 `https://YOUR_DOMAIN:8443`，不是可选优化。
  **⚠️ v0.4.27 公网形态不支持反向代理**（见 §G(b)）：反代会让 `RemoteAddr` 塌缩为单一来源，
  登录防爆破形成跨来源账号锁定 DoS、登录审计 IP 失去溯源能力；可信代理白名单 + XFF 采信列为技术债、
  当前版本未实现。下列 443 对齐说明仅适用于客户自有边缘设备转发，不建议在公网形态使用。
  若走 443 转发，则中枢 TLS 端口、`YUDUAN_PUBLIC_ADDR`、主端登录页、副端 `YUDUAN_HUB` 四处**统一写 443**，
  并由客户反代把流量转到 `:8443`。
- **`YUDUAN_PUBLIC_ADDR` 是事实必配项（非可选）**：不设时中枢以明文监听串（如 `:8080`）兜底，
  W3 软件分发、集群节点地址、心跳地址都会取到这个回环/裸端口值（反例见 C 节 #3），
  公网副端 https 直连下载必然失败。
- 本章示例统一用 `YOUR_DOMAIN` / `YOUR_IP` 占位符，请替换为实际值；产品不预置任何域名、IP 或公网端点。

### B. 证书准备（私有 CA + SPKI 指纹双轨）

中枢包随附 `yuduan-ca`（`dev/cmd/ca`）与两个证书准备脚本：

| 平台 | 脚本 | 随包位置 |
|---|---|---|
| Linux / macOS | `prepare-public-cert.sh` | Linux / macOS 中枢包（另有局域网一键脚本 `init-ca.sh`） |
| Windows | `prepare-public-cert.ps1` | Windows 中枢包 / 服务器整包 |

```bash
# Linux / macOS（YOUR_DOMAIN、YOUR_IP 换成客户真实值）
sudo ./prepare-public-cert.sh -dns YOUR_DOMAIN -ip YOUR_IP
# 走 443 转发时（公网形态不支持反代，见 §G(b)）：sudo ./prepare-public-cert.sh -dns YOUR_DOMAIN -port 443
# 轮换叶证书：   sudo ./prepare-public-cert.sh -dns YOUR_DOMAIN -ip YOUR_IP -rotate
```

```powershell
# Windows（PowerShell）
.\prepare-public-cert.ps1 -DnsNames YOUR_DOMAIN -IpAddresses YOUR_IP
.\prepare-public-cert.ps1 -DnsNames YOUR_DOMAIN -Port 443
.\prepare-public-cert.ps1 -DnsNames YOUR_DOMAIN -Rotate
```

脚本复用 `yuduan-ca` 的 `init` / `issue-server -dns/-ip` / `pin` / `check`，不重写证书逻辑；
**不写任何 env**——局域网 `init-ca.sh` 会自动写 `YUDUAN_CLIENT_CA` / `YUDUAN_TLS_PIN`，
那会拉起独立的 `:8444` mTLS 端口，不适用于公网只开 `:8443` 的形态。产物：

| 产物 | 用途 |
|---|---|
| `ca.pem` | 根 CA 公钥，**带外分发**到主端/副端作链校验信任锚 |
| `ca.key` | 根 CA 私钥，**签发后立即移出中枢生产机离线保管**。`claim` 仍正常下发 `hmacSecret` + `ca.pem`，只是**不启用 claim 的客户端证书自动签发**（副端客户端证书改离线预签发 + 带外分发） |
| `cert.pem` / `key.pem` | 服务器证书 / 私钥，SAN 含客户 `-dns/-ip` |
| `chain.pem` | leaf+root 完整链，`YUDUAN_TLS_CERT` 指向它 |

- **私有 CA 签发路径的 SAN 已可配置**：客户自绑定域名/IP **必须手动跑一次**
  `issue-server -dns/-ip`（或直接用本节的 `prepare-public-cert.sh` / `.ps1`，脚本即调用它）：
  用域名连接就必须有对应 **DNS SAN**（`-dns YOUR_DOMAIN`），用 IP 直连就必须有 **IP SAN**
  （`-ip YOUR_IP`）。**公网禁用一次性自签证书**（其 SAN 固定 `localhost/127.0.0.1/::1`）；
  也不要依赖中枢的私有 CA 自动签发——那段逻辑只补本机主机名的 **DNS SAN、无 IP SAN**。
  **显式设 `YUDUAN_TLS_CERT` 会跳过中枢自动签发**，所以「证书脚本生成 SAN」与
  「#2 显式 `YUDUAN_TLS_CERT=chain.pem`」必须**绑在一起做**——这正是本轮 SAN 零 Go 代码
  改动的前提，缺一都会让客户域名/IP 的证书校验落空。
- **SPKI SHA-256 指纹**：`yuduan-ca pin -cert cert.pem` 输出 64 位小写 hex，
  主端 `native-tls`、副端 `openssl` 双侧口径一致。
- **Windows 平台可用性（v0.4.25 根修）**：v0.4.25 已将证书指纹计算改为系统临时目录
  + 逐步 openssl 调用，不再依赖 `/tmp` 或 `sh`，CAFILE 与 PIN 双轨在
  Windows / Linux / macOS 均可用；Windows 实机证书轨验收仍列入上线后抽测项。
- **ca.pem / PIN 必须带外预置**：`claimResponse.caPem` 不能作为本次 claim 校验的信任锚
  （bootstrap 先有鸡还是先有蛋），只作后续 wss / mTLS 信任锚。
- **`:8443` 不是 mTLS 端口**：`YUDUAN_CLIENT_CA` 会额外监听独立的 `:8444`；
  公网只开 `:8443` 时**不要设** `YUDUAN_CLIENT_CA`，两者不要混淆。
- **SNI 无需额外变量**：显式 `YUDUAN_HUB=wss://<域名>:<端口>/ws/agent` 时，副端
  `-servername` 自动从 URL 取域名，本轮不新增任何 SNI 变量。

### C. 公网部署必配清单

> v0.4.26 起公网形态新增且已生效的变量：`YUDUAN_NET_MODE`（默认 `lan`，显式 `public` 才进入公网形态）、
> `YUDUAN_PUBLIC_DOMAIN`（公网域名，用于推导 `https://<域名>:8443`）、`YUDUAN_LOGIN_GUARD`（登录防爆破），
> 及其可调项 `YUDUAN_LOGIN_MAX_FAILS` / `YUDUAN_LOGIN_WINDOW_SEC` / `YUDUAN_LOGIN_LOCK_SEC`。
> 这些变量由 `-Public` / `--public` 一键部署脚本自动写入（见 §G），无需手工填写；
> 「双 pin 过渡」「SNI 覆盖」等仍未实现，不要照抄（写了也不会生效）。

| # | 必配项 | 值 / 动作 | 原因 |
|---|---|---|---|
| 1 | `YUDUAN_TLS_ADDR` | `:8443` | 显式固定 TLS 监听 |
| 2 | `YUDUAN_TLS_CERT` / `YUDUAN_TLS_KEY` | `<绝对路径>/chain.pem` / `<绝对路径>/key.pem` | **显式**指向私有 CA 完整链。注意：显式设 `YUDUAN_TLS_CERT` 会跳过中枢的证书到期告警，必须按 #10 用 `ca check` cron 补偿 |
| 3 | `YUDUAN_PUBLIC_ADDR`（**事实必配，非可选**） | `https://YOUR_DOMAIN:8443`（**含 scheme 的完整地址** + 端口） | 中枢 `PublicAddr` 不设时兜底为明文监听串 `plainBound`（如 `:8080`）；`w3RepoURL()` 仅在值里不含 `://` 时补 **`http://`**（不是 `https://`，与公网 TLS 形态不符），会拼出 **`http://:8080/api/v1/repo/<id>`**（或回环 `http://127.0.0.1:8080/...`），集群节点地址与心跳地址同源取该值 → 副端 https 直连下载必然失败。必须显式写含 scheme 的完整 `https://<客户域名>:<TLS端口>`，并与 #2 的 `YUDUAN_TLS_CERT/KEY` 及 B 节证书 SAN 一并配置 |
| 4 | `YUDUAN_HUB`（副端） | `wss://YOUR_DOMAIN:8443/ws/agent` | UDP 广播不跨公网，必须静态指定 |
| 5 | 主端登录页 | `https://YOUR_DOMAIN:8443` | **必须带端口**：主端对 https 省略端口时默认连 **443**，而中枢 TLS 默认 **8443**，省略会静默连错且报错难懂 |
| 6 | 信任锚（主端/副端） | `YUDUAN_TLS_CAFILE=<绝对路径>/ca.pem` **或** `YUDUAN_TLS_PIN=<64位hex>` | 至少配其一；**同时配置时为 AND 叠加**——链校验与指纹固定都需通过。必须带外预置、启动前配置；主端无证书/指纹配置界面 |
| 7 | `YUDUAN_LOGIN_GUARD` | `1` | LAN 形态默认关闭；`-Public`/public 形态默认开启（部署脚本自动写 `YUDUAN_LOGIN_GUARD=1`）。**v0.4.27 起回环来源不再豁免**（F-04）：`127.0.0.1` / `::1` 同样进入计数/锁定；就绪探针只发一次登录请求、首次成功即停止轮询，最多记 1 次失败，远低于默认 5 次阈值，不会误判中枢启动失败。可调 `YUDUAN_LOGIN_MAX_FAILS=5` / `YUDUAN_LOGIN_WINDOW_SEC=300` / `YUDUAN_LOGIN_LOCK_SEC=300` |
| 8 | 防火墙 | **只放行 TCP 8443**；阻断公网 TCP 8080、UDP 18242（默认，可覆盖）、TCP 5432 | 明文口与发现口不暴露；PG 不对外 |
| 9 | `YUDUAN_HUB_ADDR` | **不改**，保持 `:8080` | 裁决选 A：靠客户防火墙阻断公网 8080/18242（默认，可覆盖），不把明文口绑回环——绑回环会让 `ServeDiscovery` 拼出畸形 UDP 应答帧，破坏同机 LAN 自动发现 |
| 10 | `ca check` cron / 计划任务 | `yuduan-ca check -dir <证书目录>`（<30 天退出码 1） | 补偿 #2 跳过的到期告警，轮换提醒不能丢 |
| 11 | PostgreSQL | `listen_addresses = '127.0.0.1'`；`YUDUAN_DB_DSN` 指向回环 | 数据库仅本机可达 |
| 12 | 账号与密钥 | 首个管理员登录后立即改密；`YUDUAN_HMAC_SECRET` 已设且 `YUDUAN_HMAC_ENFORCE=1`；`YUDUAN_ADMIN_MUST_CHANGE_PW` 保持 1 | 沿用上文「生产检查清单」 |

**SNI 只设 servername，不等于主机名校验**：显式 `YUDUAN_HUB=wss://<域名>:<端口>/ws/agent`
时，副端从 URL 自动推导并发送 `-servername`（仅设 SNI 扩展）；SNI 本身**不做** SAN / 主机名校验。
本轮严格校验只来自显式信任锚：副端配置了 `YUDUAN_TLS_CAFILE` 或 `YUDUAN_TLS_PIN` 时，
才会在 `-servername` 之外追加 `-CAfile` + `-verify_return_error`（证书链校验 / SPKI 指纹固定）；
两者均未配置时保持原有行为（默认 LAN 零影响）。因此证书 SAN 必须覆盖客户域名/IP（见 B），
且 #6 的信任锚必须带外预置——「能连上」不等于「已逐项比对主机名」。

> **遗留与观察（本轮不实现）**：主机名 / IP 与证书 SAN 的逐项比对、以及双 pin 过渡窗口，
> 本轮均未提供，不要依赖它们做安全判定或无缝轮换。后续若启用逐项比对，须同时满足四条前置约束：
> ① 先完成三平台客户端 openssl 版本矩阵实机验证（macOS 自带 LibreSSL，支持性未实测）；
> ② 仅在显式信任锚（`YUDUAN_TLS_CAFILE` / `YUDUAN_TLS_PIN`）路径启用，绝不无条件追加；
> ③ 四条存量连接路径参数一字不动（含仅 PIN 的自签兼容路径）——自签 LAN 证书的 SAN 仅
> `localhost/127.0.0.1/::1`，而 LAN 副端普遍以局域网 IP 直连，半无条件启用会打断全部
> 存量自签部署，违反「默认 LAN 零影响」；
> ④ 中枢私有 CA 自动签发路径只补本机主机名的 **DNS SAN、无 IP SAN**，存量「私有 CA + IP 直连」
> 客户若后续启用逐项比对会一次性握手失败，须先按 `ca issue-server -dns/-ip` 重签服务器证书
> （这也正是 B 节要求客户自绑定域名/IP 时手动跑一次 `issue-server` 的原因）。

### D. 证书轮换与 CA / 指纹同步分发

| 轨道 | 是否平滑 | 说明 |
|---|---|---|
| `YUDUAN_TLS_CAFILE`（链校验） | **平滑** | 根 CA 10 年有效、同根换叶，`ca.pem` 不变，无需逐端重分发 |
| `YUDUAN_TLS_PIN`（指纹固定） | **不平滑** | 叶证书换了 SPKI 指纹就变，必须**逐端更新 + 变更窗口，会有短暂中断**；不做虚假平滑承诺。仅建议高安全终端启用，别全量铺开 |

轮换步骤：① 用 `prepare-public-cert.sh` / `.ps1 ... -rotate` 签发新叶（需临时取回 `ca.key`）→
② **带外分发**新 `ca.pem` / 新 PIN 到全部主端与副端 → ③ 切中枢 `YUDUAN_TLS_CERT`
（`chain.pem` 原地覆盖，重启中枢生效）→ ④ 验证全端在线 → ⑤ 撤销旧 PIN / 旧信任锚 →
⑥ `ca check` 确认新证书有效期，并把 `ca.key` 重新移出中枢机离线保管。

> 双 pin 过渡窗口本轮**不实现**，列入「遗留与观察」，不要依赖它做无缝切换。
> **任何一次轮换都必须同步分发 CA / 指纹**：只换中枢证书而不换客户端信任锚会全端掉线。

### E. 验证与失败回滚

**上线后验证清单**

- [ ] `openssl s_client -connect YOUR_DOMAIN:8443 -servername YOUR_DOMAIN -CAfile ca.pem -verify_return_error < /dev/null` 返回 `Verify return code: 0 (ok)`，且 `stderr` 无报错
- [ ] 换用**未预置**的信任锚（换一份 CA 或改 PIN）连接必须**失败**，不得静默连上
- [ ] 主端用 `https://YOUR_DOMAIN:8443` 能登录；副端用 `YUDUAN_HUB=wss://YOUR_DOMAIN:8443/ws/agent` 能注册上线
- [ ] 公网侧端口扫描：8443 通；8080 / 18242（默认，可覆盖） / 5432 不通
- [ ] `yuduan-ca check -dir <证书目录>` 退出码 0，cron / 计划任务已挂
- [ ] 软件分发下载 URL 前缀为 `https://YOUR_DOMAIN:8443/api/v1/repo/...`；若出现 `http://` 或 `:8080` / 回环地址，即说明 `YUDUAN_PUBLIC_ADDR` 未配置（见 #3 反例）

**回滚（两条路径，没有回滚不上线）**

- **仅公网增量异常**：恢复原 `env` / 原证书 / 原防火墙规则，或删除本章新增的显式配置项，
  即回到纯 LAN 默认（`:8080` + `:8443` + UDP 自动发现），**无需整版回滚**，预计 < 5 分钟。
- **P0 整版故障**：回退 v0.4.24 的 tag / Release 产物，按上文「升级」章节的停旧→替换→起新流程恢复；
  `hub.env` / `env` 不会被覆盖，回滚后按上一节重新核验端口与证书。

### F. LAN 默认 vs 客户自建公网差异对照

| 项 | 默认 LAN（v0.4.24 等价，零改动） | 客户自建公网（本章增量） |
|---|---|---|
| 监听端口 | `:8080` 明文 + `:8443` TLS + UDP `:18242`（默认，可覆盖） | 端口不变；仅客户防火墙**只放行 8443** |
| 自动发现 | UDP 广播，零配置 | 不依赖广播，显式 `YUDUAN_HUB` |
| 服务器证书 | 一次性自签（SAN 仅 localhost/127.0.0.1/::1） | 私有 CA 签发，SAN 含客户域名/IP，显式 `chain.pem` |
| 客户端信任 | 可无 | `YUDUAN_TLS_CAFILE` 或 `YUDUAN_TLS_PIN` 带外预置（AND 叠加亦可） |
| 登录防爆破 | LAN 形态默认关闭 | `-Public`/public 形态默认开启（部署脚本自动写 `YUDUAN_LOGIN_GUARD=1`） |
| `YUDUAN_PUBLIC_ADDR` | 不设（取明文监听地址） | 显式 `https://YOUR_DOMAIN:8443` |
| `YUDUAN_HUB_ADDR` | `:8080` | **不改**（靠防火墙阻断公网 8080/18242；18242 默认，可覆盖） |
| `YUDUAN_CLIENT_CA` / `:8444` | 可选 mTLS | **不设**（公网只开 8443） |
| 运维责任 | 客户内网 | 域名 / DNS / 证书 / 防火墙 / 反代全部客户自备自运维，产品不托管公网服务 |

---

### G. P1 公网一键部署（`-Public`，最小白闭环）

**铁律 1 v1.2 / Gate G-2026-11-06-02** 要求产品内置「公网远控能力包」：客户（个人/企业）一键部署后
即可实现公网端点暴露、内置中继（P2）、NAT 穿透（P3）、自绑域名、证书自动化、LAN/公网 开关。
P1 交付**公网可达最小闭环**：LAN/公网 开关 + 自绑域名 + 证书自动化（ACME / 自传双轨）+ 一键部署脚本。

**新增一键入口（三端脚本一致，默认 LAN、不加 `-Public` 即完全沿用原有局域网默认逻辑，v0.4.29 LAN 零回归）**：

- Windows：`deploy.bat` 交互选 LAN / Public；或 `register-task.ps1 -Public -Domain <域名> -Email <邮箱> [-CertMode acme|self]`。
- Linux：`install.sh --public --domain <域名> --email <邮箱> [--cert-mode acme|self]`。
- macOS：`install-macos.sh --public --domain <域名> --email <邮箱> [--cert-mode acme|self] [--staging]`。

> **macOS 特别说明**：launchd plist 是 env 的**静态快照**（安装时一次性展开为 `EnvironmentVariables`），
> 不是 systemd 的运行时 `EnvironmentFile`。因此 `install-macos.sh --public` 把「证书准备 + 7 项 env」
> 放在 plist 生成**之前**完成，一次 bootstrap 即起公网服务，无需二次 bootout/bootstrap；
> 改完 `/usr/local/etc/yuduan-hub/env` 后必须**重跑安装脚本刷新 plist**（同 §三 macOS 章节），
> 直接改 env 而不重跑安装脚本，旧 plist 仍按旧 env 启动、不会生效。

**`-Public` 流程自动完成**：

1. 跑证书准备——
   - `acme`：`yuduan-acme issue --domain <域名> --email <邮箱> [-staging]`（HTTP-01，需公网 IP + 开放 :80/:443；
     签发 `certs/acme.fullchain.pem` + `acme.key` + `acme.pin`，临时放开 :80 签发后回收）。
     **首次 / 预发请先加 `-staging`**（对应 Windows `-Staging`、Linux `--staging`、macOS `--staging`），
     避免误配置撞 Let's Encrypt 正式环境速率限制；验证通过后再去掉该参数正式签发；
   - `self`：复用 `prepare-public-cert.sh` / `.ps1` 生成 `chain.pem` + 私有 CA。
2. 写入 env（幂等 upsert，不动 `YUDUAN_HMAC_SECRET`/`PEPPER`/`SIGN_SEED`/`DB_DSN`）：
   `YUDUAN_NET_MODE=public`、`YUDUAN_TLS_CERT`、`YUDUAN_TLS_KEY`、`YUDUAN_PUBLIC_ADDR=https://<域名>:8443`、
   `YUDUAN_PUBLIC_DOMAIN=<域名>`、`YUDUAN_LOGIN_GUARD=1`。
3. 防火墙：放开 :8443（ACME 期间临时 :80）。**macOS 无 ufw / firewall-cmd**，脚本仅打印人工放行指引
   （TCP 8443 / ACME 临时 TCP 80），需客户自行在「系统设置 → 网络 → 防火墙」放行，不阻断部署。
4. 副端公网接入提示：运维须在副端设 `YUDUAN_HUB=wss://<域名>:8443/ws/agent`，
   以及信任锚（ACME 模式系统根已信任则无需；self 模式另需 `YUDUAN_TLS_CAFILE=<ca.pem>` 或 `YUDUAN_TLS_PIN=<pin>`）。

**中枢侧形态门**（`dev/cmd/hub/main.go`）：`YUDUAN_NET_MODE` 默认 `lan`（零配置、仅内网、不广播公网地址）；
仅显式 `public` 才进入公网形态——强制显式 TLS 证书（否则拒绝启动，禁止回退局域网自签）、
由 `YUDUAN_PUBLIC_DOMAIN` 推导广播地址、默认开启登录防爆破。

> **⚠️ 公网形态约束（v0.4.29 修订，必读）**
>
> **(a) 必须经一键入口进入公网形态**：公网形态必须经
> `register-task.ps1 -Public -Domain ... -Email ... -CertMode ...`（或
> `install.sh --public ...` / `install-macos.sh --public ...`）进入；**不要仅手工把 `YUDUAN_NET_MODE=public` 写入 hub.env**——
> LAN 一键部署目录默认存在 `certs/chain.pem`（SAN 仅本机地址），仅手改 NET_MODE 而不显式
> 配置 `YUDUAN_TLS_CERT`/`YUDUAN_TLS_KEY` 会被中枢**拒绝启动**（公网形态强制显式 TLS 证书；
> v0.4.27 已删除证书自动探测逻辑，不会回退到局域网自签链）。
>
> **(b) 公网形态不支持本机反向代理**：**不要在本机部署 nginx/Caddy 等反向代理再转发到 hub**：
> 公网形态按 hub 直接暴露 8443 + 客户防火墙收敛 8080/18242（默认，可覆盖）设计。反代下所有请求的
> RemoteAddr 均为 127.0.0.1，登录防爆破会按单一来源键计数（可能形成跨来源账号锁定 DoS），
> 且登录审计来源 IP 全部塌缩为 127.0.0.1 失去溯源能力。若确需反代，须先实现可信代理
> 白名单 + 仅对该白名单采信 XFF（列为技术债，当前版本不支持）。

**主端侧**（Tauri/React）：Settings 新增「部署形态」开关（LAN/公网）+ 自绑域名输入，
持久化到 `localStorage`（`yuduan.netmode` / `yuduan.pubdomain`）；公网形态由域名推导
`https://<域名>:8443` 作为连接地址，且不被局域网 UDP 发现覆盖。

> 最小白目标：**客户只需准备一个域名（DNS A 记录指向本机公网 IP）并开放 80/443 端口，
> 跑一次 `-Public` 即可获得公网远端**；中继（P2）/ 穿透（P3）为后续里程碑。
>
> **(c) v0.4.31 补注**：新增的「全局按源 IP」防爆破维度对 loopback 放行，故反代下
> 127.0.0.1 不再触发该维度的跨来源账号锁定；但**账号维度沿用 v0.4.27 F-04「回环不豁免」**，
> 上段关于审计来源 IP 失去溯源能力、以及「不支持反代」的总体结论**仍然成立**，请勿据此放宽反代。

---

## v0.4.31 增量能力（默认关闭 / 纯增量，LAN 部署无需任何改动）

全部新能力的环境变量见同目录 `env.example`。**缺省状态与 v0.4.30 逐字节一致**：
LAN 部署不设以下任何变量即可照常升级，无需改脚本、无需重启前后兼容处理。

### 1. 中枢配置 API + 主端面板
`GET/POST /api/v1/config`。`operator`/`admin` 可读、**仅 `admin` 可写**，`viewer` 无权限。
9 项非敏感配置可写：告警 webhook、远控时长/空闲上限、设备台账上限、备份份数/间隔、
HMAC 强制、录像开关/留存天数。其中 6 项即时热更新，3 项（备份间隔/录像开关/留存天数）
仅持久化、重启后生效（主端面板会提示「需重启」）。
写回值原子落盘 `data/hub-config-overrides.json`，重启后优先于 env 生效。
**敏感项（HMAC 密钥 / pepper / 签名种子 / CA 密钥 / TLS 私钥 / 录像密钥 / PG DSN /
CLIENT_* / TLS_CAFILE）一律不开放 API 读写**，只能改 env 或 keystore 后重启；
GET 只回显「排除清单」名称，不回显任何值。

### 2. TLS 证书自动续期（ACME）
默认关闭，须同时 `YUDUAN_NET_MODE=public` 且 `YUDUAN_ACME_AUTORENEW=1`。
支持 standalone（临时监听 `:80`）与 webroot 两种 HTTP-01 模式；续期前校验
`tls.X509KeyPair`、成功后原子替换 cert/key 并经 `GetCertificate` 热重载，**无需重启**；
失败按指数退避重试，绝不 `log.Fatal`、绝不降级为明文。副端 SPKI PIN 口径不变。

### 3. 登录防爆破增强（全局按源 IP 维度）
与既有「账号维度」并存、独立累计：同 IP 跨多个账号的失败会累加，达阈值封该 IP。
默认阈值 20 次 / 300 秒窗口 / 锁定 300 秒（账号维度仍为 5 次）。
仅 `YUDUAN_TRUST_PROXY=1` 时采信 XFF 首段（默认只信 `RemoteAddr`）；
IP 维度对 loopback 放行以规避反代 `RemoteAddr` 塌缩导致的跨来源锁定 DoS 并保护就绪探针。
锁定仍返 `code=4029` + HTTP 200，文案含秒数，**契约未变**。

### 4. 会话安全（服务端会话表 / 吊销 / 空闲超时）
默认关闭，`YUDUAN_SESSION_ENFORCE=1` 启用；公网自建形态建议显式开启。
令牌格式不变（会话键由令牌整体 SHA-256 派生），副端与旧客户端无感。
启用后补齐：主动登出吊销、角色变更/强制改密后旧令牌即时失效、账号级会话吊销、
绝对过期与 30 分钟空闲超时。`YUDUAN_SESSION_LEGACY_ALLOW=1` 可平滑迁移旧令牌。
`last_active` 只在低频 REST 管理 API 刷新，**绝不挂到 `/ws/agent` 心跳或 viewer 媒体帧**（铁律 10）。
会话表已从全库备份导出中排除，且恢复重放时跳过会话 INSERT ⇒ 恢复备份不会让旧令牌复活，
代价是恢复后所有客户端需重新登录。回环就绪探针（只看 HTTP 200/401）不受影响。

### 5. 审计链尾外锚
默认关闭，`YUDUAN_AUDIT_ANCHOR=1` 启用。每次「校验审计链」通过后，把链尾 `(id, hash)`
的 HMAC 签名以 **append-only** 方式追加到库外独立文件 `data/audit-anchor.jsonl`。
签名密钥优先 `YUDUAN_AUDIT_ANCHOR_KEY`（独立可轮换），未配则回退 `YUDUAN_HMAC_SECRET`
（**与令牌签名同密钥，能读 secret 者可自伪造、强度打折**，锚行会标 `key_source`）；两者皆空
则不锚定、不写文件，**绝不误报链损坏**。

> **为何必须库外**：全库备份 `BackupSQL` 动态遍历全部 public 表导出，`RestoreSQL` 用
> `TRUNCATE ... RESTART IDENTITY CASCADE` 全量重放（TRUNCATE 不触发行级 WORM 触发器）。
> 任何存进 PG 的锚表都会被导出、清空、重放伪造。只把签名塞进 `ChainReport` 返回前端
> 同样无效：整库回滚后签名器会用同一 secret 对伪造链重新盖合法章。
>
> **诚实边界**：库外文件只能靠人工/带外比对发现整库回滚，**本版不提供自动告警**；
> 若攻击者同时删除锚文件，仍需异地备份或只读介质。生产建议把
> `YUDUAN_AUDIT_ANCHOR_FILE` 指到中枢进程不可写的目录，并定期同步到另一台机器。
> 可用离线核验函数（见 `internal/audit/audit_anchor.go`）复算每行 sig、检查 `tail_id` 单调不减。

### 6. 副端设备证明（attestation）— 本期仅为契约基座
`dev/proto/protocol.md` §9.2 + Gate `G-2026-11-08-01`。副端新增每设备 Ed25519 keypair
（独立文件 `agent-devicekey.json`，Windows DPAPI / mac+Linux `/dev/urandom`，零新增 crate）、
二进制度量签名、跨语言黄金向量；协议新增 `require_attest`/`pubkey`/`attest_sig`/
`measurement`/`agent_pubkey`，全部 `omitempty`，`Ver` 保持 1、顶层 `Envelope` 零改动。

> ⚠️ **本期中枢 handler 未接线、默认关闭**：`require_attest` 缺省 false，副端只发旧三字段
> `nonce/mac/token`，逐字节兼容旧中枢与 Go 参考副端。本期**不构成已启用的设备证明能力**，
> 请勿在安全检查清单里把它当作已生效的门禁。中枢侧验签叠加、pubkey 台账白名单、
> 二进制度量比对、灰度开关与审计联动属后续接线，须单独评审后启用。
> 沿用既有裁决：**不采用 mTLS 客户端证书做唯一门禁**。

