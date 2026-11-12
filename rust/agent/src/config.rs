// 副端引导配置（档位 A：广播一次性令牌 → claim 换取 → 本机加密落盘）。
//
// 流程：副端 YUDUAN_HMAC_SECRET 未配置时，用 UDP 广播拿到的注册令牌向中枢
// /api/agent/claim 换取 HMAC 验签密钥（与可选的 mTLS 客户端证书），随后在
// **本机**加密落盘 agent-config.json，重启后自动复用——部署零手动填密钥。
//
// 传输安全：中枢广播 ws= 为 wss:// 时 claim 走 https（openssl s_client 子进程，
// 复用 wss 通道同一套 openssl 方案）；仅明文 ws:// 可达时走 http 并醒目告警
// （内网信任模型；生产建议中枢启用 TLS 使密钥经加密通道下发）。
// 落盘安全：Windows 用 DPAPI LocalMachine 作用域加密（dpapi.rs）；其它平台
// 明文 + 0600 权限（ACL）。

use std::path::PathBuf;

use crate::httpget;

/// 引导配置结果（claim 换取）。
#[derive(Debug)]
pub struct Claimed {
    pub hmac_secret: String,
    pub hub_id: String,
    pub tls_addr: String,
    pub via_tls: bool,
}

/// 配置文件路径：YUDUAN_CONFIG_FILE 优先；Windows 默认 %PROGRAMDATA%\YuDuan\，
/// 其它平台 $HOME/.yuduan/。返回 None 时调用方跳过持久化（仅本次会话生效）。
pub fn config_file() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("YUDUAN_CONFIG_FILE") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    #[cfg(windows)]
    {
        if let Ok(pd) = std::env::var("PROGRAMDATA") {
            if !pd.trim().is_empty() {
                let mut p = PathBuf::from(pd);
                p.push("YuDuan");
                p.push("agent-config.json");
                return Some(p);
            }
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    if home.trim().is_empty() {
        return None;
    }
    let mut p = PathBuf::from(home);
    p.push(".yuduan");
    p.push("agent-config.json");
    Some(p)
}

/// 配置目录（agent-config.json 所在目录）。v0.4.40：中枢端点文件 agent-hub.json、
/// 运行状态文件 agent-status.json 均落在此目录，与密钥配置同生命周期、同权限域。
/// 复用 config_file() 的目录逻辑（含 YUDUAN_CONFIG_FILE 覆盖），避免三处各写一份
/// %PROGRAMDATA%/$HOME 解析而漂移。
pub fn config_dir() -> Option<PathBuf> {
    config_file()?.parent().map(|p| p.to_path_buf())
}

/// 持久化中枢端点文件（v0.4.40 --set-hub 写入）。URL 非机密，明文 JSON，无需 DPAPI。
/// 刻意与 agent-config.json（仅存 DPAPI 加密的 HMAC 密钥）分开：--setup 清理密钥
/// 时绝不碰此文件，运维设置的中枢端点不会因重装 / 密钥轮换自愈而丢失。
pub fn hub_file() -> Option<PathBuf> {
    Some(config_dir()?.join("agent-hub.json"))
}

/// 服务运行状态快照（v0.4.40 --status 观测）。服务写、CLI 读，非机密明文 JSON。
pub fn status_file() -> Option<PathBuf> {
    Some(config_dir()?.join("agent-status.json"))
}

/// 生效的 HMAC 密钥：config 落盘值优先（部署自动下发），环境变量兜底（显式覆盖）。
/// 都缺失返回空串（= 开发态放行，与现状一致）。
pub fn effective_hmac_secret() -> String {
    if let Some(s) = load_hmac_secret() {
        return s;
    }
    std::env::var("YUDUAN_HMAC_SECRET").unwrap_or_default()
}

/// 读取落盘的 HMAC 密钥（Windows DPAPI 解密；缺失/损坏返回 None）。
pub fn load_hmac_secret() -> Option<String> {
    let path = config_file()?;
    let data = std::fs::read_to_string(&path).ok()?;
    let v = crate::parse_json(data.as_bytes()).ok()?;
    let enc = v
        .get("enc")
        .and_then(|x| x.as_str())
        .unwrap_or("plain")
        .to_string();
    let val = v
        .get("hmacSecret")
        .and_then(|x| x.as_str())?
        .to_string();
    if val.is_empty() {
        return None;
    }
    match enc.as_str() {
        "dpapi" => {
            #[cfg(windows)]
            {
                let blob = hex_decode(&val)?;
                crate::dpapi::unprotect(&blob)
            }
            #[cfg(not(windows))]
            {
                None // 非 Windows 无 DPAPI（跨平台 blob 也不可解），视为无配置
            }
        }
        _ => Some(val),
    }
}

/// 删除落盘引导配置（v0.4.20 密钥轮换自愈：注册连续被拒时清掉旧密钥，
/// 下次引导自动重新 claim 当前中枢密钥）。显式 env YUDUAN_HMAC_SECRET 不受影响
/// （effective_hmac_secret 仍会取到 env 值而跳过重新 claim——显式配置视为运维意图）。
pub fn delete_config_file() {
    let Some(path) = config_file() else { return };
    match std::fs::remove_file(&path) {
        Ok(()) => eprintln!("[agent] 已删除落盘密钥配置 {:?}", path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("[agent] 删除落盘密钥配置失败（忽略）: {}", e),
    }
}

/// 保存 HMAC 密钥（Windows 先 DPAPI 加密再落盘；其它平台明文 + 0600）。
/// 原子写（临时文件改名）；失败仅记日志，不阻塞主流程。
pub fn save_hmac_secret(secret: &str) {
    let Some(path) = config_file() else { return };
    let (field, enc) = {
        #[cfg(windows)]
        {
            match crate::dpapi::protect(secret.as_bytes()) {
                Some(blob) => (hex_encode(&blob), "dpapi"),
                None => {
                    eprintln!("[agent] ⚠️ DPAPI 加密失败，退回明文落盘（0600 权限防护）");
                    (secret.to_string(), "plain")
                }
            }
        }
        #[cfg(not(windows))]
        {
            (secret.to_string(), "plain")
        }
    };
    let body = format!(
        "{{\"hmacSecret\":{},\"enc\":{}}}",
        crate::json_string(&field),
        crate::json_string(enc)
    );
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    let ok = std::fs::write(&tmp, body.as_bytes())
        .and_then(|_| std::fs::rename(&tmp, &path));
    if ok.is_ok() {
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        }
        eprintln!(
            "[agent] 已持久化引导配置（{}加密）：{}",
            if enc == "dpapi" { "DPAPI " } else { "" },
            path.display()
        );
    } else {
        eprintln!("[agent] ⚠️ 引导配置落盘失败（本次会话仍生效）：{}", path.display());
    }
}

// ===================== v0.4.40：持久化中枢端点（--set-hub） =====================
//
// 背景（已核实根因）：agent-config.json 只存 DPAPI 加密的 HMAC 密钥，**不存中枢端点**；
// YUDUAN_HUB 环境变量由部署脚本注入，服务进程继承的是创建时的 env 快照，运行时改 env
// 且服务从未真正重启（sc stop 报 1052、PID 不变）时根本不生效。--set-hub 把运维的最新
// 意图单独落到 agent-hub.json，服务每轮重连都重新读它，彻底绕开 env 快照与 1052 停止失败。

/// 读取持久化中枢端点；缺失 / 损坏 / 空值返回 None（调用方回退到 env / 自动发现）。
/// 容错解析：trim、拒绝空串、JSON 损坏当作未配置。
pub fn load_hub_url() -> Option<String> {
    let path = hub_file()?;
    let data = std::fs::read_to_string(&path).ok()?;
    let v = crate::parse_json(data.as_bytes()).ok()?;
    let url = v
        .get("hubUrl")
        .and_then(|x| x.as_str())?
        .trim()
        .to_string();
    if url.is_empty() {
        return None;
    }
    Some(url)
}

/// 原子写入中枢端点（tmp + rename，复用 save_hmac_secret 的落盘手法）。
/// URL 非机密，不加密；失败返回 Err，供 --set-hub 明确报错（绝不静默失败）。
pub fn save_hub_url(url: &str) -> std::io::Result<()> {
    let url = url.trim();
    if url.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "中枢端点为空",
        ));
    }
    let path = hub_file().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "无法确定配置文件目录")
    })?;
    let body = format!("{{\"hubUrl\":{}}}", crate::json_string(url));
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, &path)?;
    eprintln!("[agent] 已持久化中枢端点 {}: {}", url, path.display());
    Ok(())
}

// ===================== v0.4.40：运行状态快照（--status 可观测性） =====================
//
// 副端原本无任何文件日志、--status 又是独立短命进程且无 IPC：把「当前端点 / 来源、
// 最近连接时间、最近错误、是否连接、进程启动时间」原子写到 agent-status.json，
// CLI 先读文件（普通用户也可读，无需管理员），再叠加 SCM 状态，SCM 失败也能降级展示。

#[derive(Debug, Clone, Default)]
pub struct AgentStatus {
    pub hub_url: String,
    pub hub_source: String,   // "persisted" | "env" | "discovery"
    pub last_connect_at: i64, // unix 秒
    pub last_error: String,
    pub connected: bool,
    pub started_at: i64,      // 进程启动 unix 秒（用于 uptime）
}

/// 读取状态快照；缺失 / 损坏返回 None（--status 降级为「暂无状态文件」）。
pub fn load_agent_status() -> Option<AgentStatus> {
    let path = status_file()?;
    let data = std::fs::read_to_string(&path).ok()?;
    let v = crate::parse_json(data.as_bytes()).ok()?;
    Some(AgentStatus {
        hub_url: v.get("hubUrl").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        hub_source: v.get("hubSource").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        last_connect_at: v.get("lastConnectAt").and_then(|x| x.as_i64()).unwrap_or(0),
        last_error: v.get("lastError").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        connected: v.get("connected").and_then(|x| x.as_bool()).unwrap_or(false),
        started_at: v.get("startedAt").and_then(|x| x.as_i64()).unwrap_or(0),
    })
}

/// 原子写状态快照。started_at 首次写入时固化为进程启动时间，后续更新保持不变。
fn persist_status(s: &AgentStatus) {
    let Some(path) = status_file() else { return };
    let started_at = if s.started_at > 0 { s.started_at } else { crate::now_secs() };
    let body = format!(
        "{{\"hubUrl\":{},\"hubSource\":{},\"lastConnectAt\":{},\"lastError\":{},\"connected\":{},\"startedAt\":{}}}",
        crate::json_string(&s.hub_url),
        crate::json_string(&s.hub_source),
        s.last_connect_at,
        crate::json_string(&s.last_error),
        if s.connected { "true" } else { "false" },
        started_at,
    );
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    let ok = std::fs::write(&tmp, body.as_bytes())
        .and_then(|_| std::fs::rename(&tmp, &path));
    if let Err(e) = ok {
        eprintln!("[agent] ⚠️ 状态快照落盘失败（不影响连接）: {}", e);
    }
}

fn read_or_default_status() -> AgentStatus {
    load_agent_status().unwrap_or_default()
}

/// 会话开始（每轮重连）：记录当前端点 + 来源 + 最近连接时间，标记未连接。
pub fn status_note_connect(url: &str, source: &str) {
    let mut s = read_or_default_status();
    s.hub_url = url.to_string();
    s.hub_source = source.to_string();
    s.last_connect_at = crate::now_secs();
    s.connected = false;
    persist_status(&s);
}

/// 握手成功：标记已连接并清空最近错误。
pub fn status_note_connected() {
    let mut s = read_or_default_status();
    s.connected = true;
    s.last_error.clear();
    persist_status(&s);
}

/// 会话结束 / 异常：标记未连接并记录最近错误。
pub fn status_note_error(err: &str) {
    let mut s = read_or_default_status();
    s.connected = false;
    s.last_error = err.to_string();
    persist_status(&s);
}

/// 人类可读的状态文件内容（供 --status 先于 SCM 展示；win_service 再叠加 SCM 行）。
pub fn format_agent_status() -> String {
    let Some(s) = load_agent_status() else {
        return "状态文件 agent-status.json: 暂无（服务尚未写入，或副端未以服务方式运行）"
            .to_string();
    };
    let source_cn = match s.hub_source.as_str() {
        "persisted" => "持久化 agent-hub.json（--set-hub）",
        "env" => "环境变量 YUDUAN_HUB",
        "discovery" => "UDP 自动发现",
        "" => "未知",
        other => other,
    };
    let now = crate::now_secs();
    let uptime = if s.started_at > 0 {
        format_duration(now.saturating_sub(s.started_at))
    } else {
        "未知".to_string()
    };
    let last_conn = if s.last_connect_at > 0 {
        format!(
            "unix {}（距今 {}）",
            s.last_connect_at,
            format_duration(now.saturating_sub(s.last_connect_at))
        )
    } else {
        "尚无".to_string()
    };
    let err = if s.last_error.is_empty() {
        "(无)".to_string()
    } else {
        s.last_error.clone()
    };
    [
        "状态文件 agent-status.json:".to_string(),
        format!("  当前中枢端点: {}", if s.hub_url.is_empty() { "(未记录)" } else { &s.hub_url }),
        format!("  端点来源: {}", source_cn),
        format!("  连接状态: {}", if s.connected { "已连接" } else { "未连接" }),
        format!("  最近连接: {}", last_conn),
        format!("  最近错误: {}", err),
        format!("  进程已运行: {}", uptime),
    ]
    .join("\n")
}

/// 秒 → 人类可读时长（std-only，避免引入 chrono）。
fn format_duration(secs: i64) -> String {
    let s = secs.max(0);
    let d = s / 86400;
    let h = (s % 86400) / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if d > 0 {
        format!("{}天{}小时{}分", d, h, m)
    } else if h > 0 {
        format!("{}小时{}分{}秒", h, m, sec)
    } else if m > 0 {
        format!("{}分{}秒", m, sec)
    } else {
        format!("{}秒", sec)
    }
}

/// 用广播令牌向中枢 claim 引导配置。
/// ws_url 取自广播 ws= 字段（ws:// 或 wss://）；wss 走 https（openssl 子进程），
/// ws 走明文 http（告警）。device 为本机标识（日志/证书 CN 用）。
pub fn claim_from_ws(ws_url: &str, token: &str, device: &str) -> Result<Claimed, String> {
    let (scheme, rest) = if let Some(r) = ws_url.strip_prefix("wss://") {
        ("https", r)
    } else if let Some(r) = ws_url.strip_prefix("ws://") {
        ("http", r)
    } else {
        return Err(format!("非 ws/wss 地址: {}", ws_url));
    };
    // 取 authority（ip:port），丢弃路径（/ws/agent）
    let authority = match rest.find('/') {
        Some(i) => &rest[..i],
        None => rest,
    };
    let path = format!(
        "/api/agent/claim?token={}&device={}",
        urlencode(token),
        urlencode(device)
    );
    let body = if scheme == "https" {
        https_get_via_openssl(authority, &path)?
    } else {
        eprintln!(
            "[agent] ⚠️ claim 经明文 HTTP 下发密钥（内网信任模型）。生产建议：中枢启用 TLS 并让广播携带 wss 地址"
        );
        let url = format!("http://{}{}", authority, path);
        let resp = httpget::http_get(&url, 10)?;
        if resp.status != 200 {
            return Err(format!("claim http status {}", resp.status));
        }
        String::from_utf8_lossy(&resp.body).to_string()
    };
    parse_claim_response(&body, scheme == "https")
}

/// 解析 claim 响应 JSON → Claimed。
fn parse_claim_response(body: &str, via_tls: bool) -> Result<Claimed, String> {
    let v = crate::parse_json(body.as_bytes())?;
    // 御端错误风格：HTTP 200 + {code:非零,message}
    if let Some(code) = v.get("code").and_then(|x| x.as_i64()) {
        if code != 0 {
            let msg = v
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown");
            return Err(format!("claim 被拒 code={} msg={}", code, msg));
        }
    }
    let hmac_secret = v
        .get("hmacSecret")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if hmac_secret.is_empty() {
        return Err("claim 响应缺少 hmacSecret".into());
    }
    Ok(Claimed {
        hmac_secret,
        hub_id: v
            .get("hubId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        tls_addr: v
            .get("tlsAddr")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        via_tls,
    })
}

/// 经 openssl s_client 子进程做 HTTPS GET（std 无 TLS；复用 wss 同一套方案）。
///
/// v0.4.25：claim 通道下发的正是 HMAC 根密钥，此前只有 `-connect <authority> -quiet`，
/// 无 SNI、无任何证书校验。现在与 wss 数据隧道共用 `tls::plan_verify`：
/// 无条件补 `-servername`（取 URL authority 的 hostname，去端口，不新增变量），
/// 仅当显式 `YUDUAN_TLS_CAFILE` / `YUDUAN_TLS_PIN` 存在时才追加
/// `-CAfile` + `-verify_return_error`。三变量皆不配时，除 `-servername` 外
/// 命令行参数与旧版逐字节一致（缺省等价，局域网自签部署不受影响）。
fn https_get_via_openssl(authority: &str, path: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let bin = crate::tls::openssl_bin();
    let sni = crate::tls::sni_host_from_authority(authority);
    let plan = crate::tls::plan_verify(authority, &sni)
        .map_err(|e| format!("claim https {}", e))?;

    let mut cmd = Command::new(&bin);
    cmd.args([
        "s_client",
        "-connect",
        authority,
        "-servername",
        sni.as_str(),
        "-quiet",
    ]);
    crate::tls::apply_verify_args(&mut cmd, plan.as_ref());
    crate::tls::apply_client_cert_args(&mut cmd);
    // 严格校验开启时捕获 stderr，便于把证书校验失败翻成可诊断的中文提示；
    // 缺省路径仍丢弃 stderr，与旧版等价。
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if plan.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .spawn()
        .map_err(|e| format!("spawn {} failed: {}", bin, e))?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: yuduan-rust-agent\r\nConnection: close\r\n\r\n",
        path, authority
    );
    {
        let mut sin = child
            .stdin
            .take()
            .ok_or_else(|| "openssl stdin 不可用".to_string())?;
        sin.write_all(req.as_bytes())
            .map_err(|e| format!("claim 请求写入失败: {}", e))?;
    }
    // wait_with_output 并发排空 stdout/stderr，避免 stderr 管道写满造成死锁。
    let output = child
        .wait_with_output()
        .map_err(|e| format!("claim https openssl 等待失败: {}", e))?;
    crate::tls::cleanup_temp_ca(plan.as_ref());
    let text = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // 分离响应头与体（openssl -quiet 会透传 HTTP 响应）
    let body = match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => {
            return Err(format!(
                "claim https 响应格式异常：{}",
                claim_tls_hint(&stderr)
            ))
        }
    };
    let status_ok = text.starts_with("HTTP/") && text.contains(" 200 ");
    if !status_ok {
        return Err(format!(
            "claim https 状态异常: {}",
            text.lines().next().unwrap_or("")
        ));
    }
    Ok(body)
}

/// 证书严格校验失败时给出可诊断的中文提示（副端日志用，不把英文原文抛给主端 UI）。
fn claim_tls_hint(stderr: &str) -> String {
    let low = stderr.to_ascii_lowercase();
    if low.contains("certificate verify failed")
        || low.contains("verify error")
        || low.contains("verify return")
    {
        return "证书校验未通过：请检查副端 YUDUAN_TLS_CAFILE / YUDUAN_TLS_PIN 与中枢证书是否匹配"
            .to_string();
    }
    if stderr.trim().is_empty() {
        return "未收到 TLS 响应（连接被拒绝、超时或证书校验提前终止）".to_string();
    }
    format!(
        "openssl: {}",
        stderr.lines().take(2).collect::<Vec<_>>().join(" ")
    )
}

// ---- 小工具：hex 编解码 + URL 编码（副端零依赖，够用即可） ----

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// 极简 URL 编码：仅编码 claim 参数需要的保留字符（字母数字与 -_.~ 保留）。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = vec![0u8, 1, 0xAB, 0xFF];
        let enc = hex_encode(&data);
        assert_eq!(enc, "0001abff");
        assert_eq!(hex_decode(&enc), Some(data));
        assert_eq!(hex_decode("xyz"), None);
        assert_eq!(hex_decode("abc"), None);
    }

    #[test]
    fn urlencode_encodes_reserved() {
        assert_eq!(urlencode("abc-123"), "abc-123");
        assert_eq!(urlencode("a b&c"), "a%20b%26c");
    }

    #[test]
    fn parse_claim_response_ok() {
        let body = r#"{"hmacSecret":"sec-xyz","hubId":"hub-1","tlsAddr":":8443"}"#;
        let c = parse_claim_response(body, true).expect("应解析成功");
        assert_eq!(c.hmac_secret, "sec-xyz");
        assert_eq!(c.hub_id, "hub-1");
        assert!(c.via_tls);
    }

    #[test]
    fn parse_claim_response_rejects_error_code() {
        let body = r#"{"code":4003,"message":"invalid_or_expired_token"}"#;
        let err = parse_claim_response(body, false).unwrap_err();
        assert!(err.contains("4003"), "应包含错误码: {}", err);
    }

    #[test]
    fn parse_claim_response_rejects_missing_secret() {
        let body = r#"{"code":0}"#;
        assert!(parse_claim_response(body, false).is_err());
    }

    #[test]
    fn claim_from_ws_rejects_non_ws_scheme() {
        assert!(claim_from_ws("http://1.2.3.4:1/x", "t", "d").is_err());
    }

    #[test]
    fn config_roundtrip_with_env_file() {
        let _g = crate::test_lock();
        let path = std::env::temp_dir().join(format!("yd-cfg-test-{}.json", std::process::id()));
        std::env::set_var("YUDUAN_CONFIG_FILE", &path);
        std::fs::remove_file(&path).ok();

        // 未落盘 → None
        assert!(load_hmac_secret().is_none());

        // 保存 → 读回一致（Windows 走 DPAPI 往返；其它平台明文）
        save_hmac_secret("secret-roundtrip");
        assert_eq!(load_hmac_secret(), Some("secret-roundtrip".to_string()));

        // 损坏文件 → None（不 panic）
        std::fs::write(&path, "{broken").unwrap();
        assert!(load_hmac_secret().is_none());

        std::fs::remove_file(&path).ok();
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    #[test]
    fn delete_config_file_roundtrip() {
        // v0.4.20 密钥轮换自愈回归：删除后 load 回 None，可重新 claim
        let _g = crate::test_lock();
        let path = std::env::temp_dir().join(format!("yd-cfg-del-{}.json", std::process::id()));
        std::env::set_var("YUDUAN_CONFIG_FILE", &path);
        std::fs::remove_file(&path).ok();

        save_hmac_secret("to-be-deleted");
        assert_eq!(load_hmac_secret(), Some("to-be-deleted".to_string()));

        delete_config_file();
        assert!(load_hmac_secret().is_none());
        // 幂等：再删一次不 panic
        delete_config_file();

        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    /// v0.4.40：端点持久化（独立文件 / 原子写 / trim / 容错 / 重装不清端点）。
    #[test]
    fn hub_url_roundtrip_and_survives_key_cleanup() {
        let _g = crate::test_lock();
        // 用独立子目录，避免 hub/status 文件落进 /tmp 根目录与并行用例撞名。
        let dir = std::env::temp_dir().join(format!("yd-hub-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("YUDUAN_CONFIG_FILE", dir.join("agent-config.json"));

        assert!(load_hub_url().is_none());
        save_hub_url("  wss://remote.example:8443/ws/agent  ").unwrap();
        assert_eq!(
            load_hub_url(),
            Some("wss://remote.example:8443/ws/agent".to_string())
        );
        // 空值拒绝
        assert!(save_hub_url("").is_err());
        assert!(save_hub_url("   ").is_err());
        // 损坏文件 → None（不 panic）
        std::fs::write(hub_file().unwrap(), "{broken").unwrap();
        assert!(load_hub_url().is_none());

        // 重装 / 密钥轮换自愈只删 agent-config.json，绝不碰 agent-hub.json
        save_hmac_secret("k");
        save_hub_url("wss://keep").unwrap();
        delete_config_file();
        assert_eq!(
            load_hub_url(),
            Some("wss://keep".to_string()),
            "重装清密钥不得清掉运维设置的远端端点"
        );

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    /// v0.4.40：状态快照读写 + started_at 跨更新保持不变。
    #[test]
    fn agent_status_roundtrip() {
        let _g = crate::test_lock();
        let dir = std::env::temp_dir().join(format!("yd-status-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("YUDUAN_CONFIG_FILE", dir.join("agent-config.json"));

        assert!(load_agent_status().is_none());
        status_note_connect("wss://a", "persisted");
        status_note_connected();
        let s = load_agent_status().unwrap();
        assert_eq!(s.hub_url, "wss://a");
        assert_eq!(s.hub_source, "persisted");
        assert!(s.connected);
        assert!(s.started_at > 0);
        let started = s.started_at;

        status_note_error("连接被拒绝");
        let s2 = load_agent_status().unwrap();
        assert!(!s2.connected);
        assert_eq!(s2.last_error, "连接被拒绝");
        assert_eq!(s2.started_at, started, "started_at 应跨更新保持不变");
        assert!(format_agent_status().contains("wss://a"));

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }
}
