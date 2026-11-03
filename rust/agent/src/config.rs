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
fn https_get_via_openssl(authority: &str, path: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let bin = crate::tls::openssl_bin();
    let mut child = Command::new(&bin)
        .args(["s_client", "-connect", authority, "-quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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
    let mut out = Vec::new();
    if let Some(mut sout) = child.stdout.take() {
        let _ = sout.read_to_end(&mut out);
    }
    let _ = child.wait();
    let text = String::from_utf8_lossy(&out);
    // 分离响应头与体（openssl -quiet 会透传 HTTP 响应）
    let body = match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => return Err("claim https 响应格式异常".into()),
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
}
