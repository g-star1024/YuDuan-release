// 御端 Rust 副端 —— TLS 加固（证书固定 / mTLS 客户端证书，std-only，复用系统 openssl）。
//
// 局域网信任模型下 wss 缺省接受自签名；生产应配置 CA 或固定证书指纹。
// 本模块提供：
//  - 抓取服务端叶子证书并计算 SPKI SHA-256（RFC 7469 公钥固定）；
//  - 供 WsClient 在连接前校验固定指纹，并把该证书作为临时 CAfile 供数据隧道严格信任
//    （pin 即「仅信任此证书」，避免 TOCTOU）。
//  - mTLS 客户端证书由 connect 通过 openssl -cert/-key 透传。

use std::process::Command;

/// openssl 可执行文件路径解析（结果进程内缓存）：
/// 1. `YUDUAN_OPENSSL` 显式指定（最高优先，如运维自定义安装位置）；
/// 2. 常见安装位置探测（Windows：Git for Windows / OpenSSL-Win64 / Shining Light；
///    Unix：Homebrew / /usr/local）——开箱即用，免手动设环境变量；
/// 3. 回退 PATH 上的 `openssl`（找不到时 spawn 报错信息已足够定位）。
/// 供 wss 数据隧道（main.rs）与证书固定（本模块）共用。
pub fn openssl_bin() -> String {
    static RESOLVED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    RESOLVED
        .get_or_init(resolve_openssl)
        .clone()
}

fn resolve_openssl() -> String {
    // 1) 显式覆盖
    if let Ok(v) = std::env::var("YUDUAN_OPENSSL") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return v;
        }
    }
    // 2) 常见安装位置探测（首个存在者胜出）
    for cand in openssl_candidates() {
        let p = std::path::Path::new(&cand);
        if p.is_file() {
            eprintln!("[agent] openssl 自动探测: {}", cand);
            return cand;
        }
    }
    // 3) PATH 回退
    "openssl".to_string()
}

/// 按平台枚举常见 openssl 安装路径（借助系统环境变量，避免硬编码盘符）。
fn openssl_candidates() -> Vec<String> {
    let mut v = Vec::new();
    let push = |v: &mut Vec<String>, parts: &[&str]| {
        v.push(parts.iter().fold(String::new(), |a, s| {
            if a.is_empty() {
                s.to_string()
            } else {
                format!("{a}\\{s}")
            }
        }));
    };
    if cfg!(windows) {
        // %ProgramFiles%\Git\usr\bin\openssl.exe 等（ProgramW6432 兜底 32 位进程视角）
        for root in [
            std::env::var("ProgramW6432").ok(),
            std::env::var("ProgramFiles").ok(),
            std::env::var("ProgramFiles(x86)").ok(),
            Some("C:\\Program Files".to_string()),
        ]
        .into_iter()
        .flatten()
        {
            let root = root.trim_end_matches('\\').to_string();
            push(&mut v, &[&root, "Git", "usr", "bin", "openssl.exe"]);
            push(&mut v, &[&root, "OpenSSL-Win64", "bin", "openssl.exe"]);
            push(&mut v, &[&root, "OpenSSL-Win32", "bin", "openssl.exe"]);
            push(&mut v, &[&root, "OpenSSL", "bin", "openssl.exe"]);
        }
        if let Ok(lad) = std::env::var("LOCALAPPDATA") {
            let lad = lad.trim_end_matches('\\').to_string();
            push(&mut v, &[&lad, "Programs", "Git", "usr", "bin", "openssl.exe"]);
        }
    } else {
        for p in ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"] {
            v.push(p.to_string());
        }
    }
    v
}

/// 抓取服务端下发的**完整证书链** PEM（s_client -showcerts 全部 CERTIFICATE 块按序拼接，
/// 首张为叶证书）。openssl 不可用时返回 None（调用方据此拒绝连接，安全失败）。
/// 私有 CA 模式下中枢应下发 leaf+root 全链：完整链才能同时满足
/// 「叶证书当 pin 锚」与「链式校验需要根锚」两种临时 CAfile 用法。
pub fn fetch_chain_pem(addr: &str, sni: &str) -> Option<String> {
    let out = Command::new(openssl_bin())
        .args(["s_client", "-connect", addr, "-servername", sni, "-showcerts"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    extract_chain(&text)
}

/// 抓取服务端叶子证书 PEM（兼容保留：取链首张）。
pub fn fetch_leaf_cert_pem(addr: &str, sni: &str) -> Option<String> {
    fetch_chain_pem(addr, sni)
}

/// 从 openssl 输出中提取第一个 BEGIN/END CERTIFICATE 块。
fn extract_first_cert(text: &str) -> Option<String> {
    let begin = text.find("-----BEGIN CERTIFICATE-----")?;
    let end_marker = "-----END CERTIFICATE-----";
    let end = text[begin..].find(end_marker)? + begin + end_marker.len();
    Some(text[begin..end].to_string())
}

/// 从 openssl 输出中提取全部 CERTIFICATE 块（保持服务端下发顺序，叶在前）。
fn extract_chain(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(begin) = rest.find("-----BEGIN CERTIFICATE-----") {
        let end_marker = "-----END CERTIFICATE-----";
        let end = match rest[begin..].find(end_marker) {
            Some(e) => begin + e + end_marker.len(),
            None => break,
        };
        out.push_str(&rest[begin..end]);
        out.push('\n');
        rest = &rest[end..];
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// 计算证书 PEM 的 SPKI SHA-256（hex）。用于公钥固定。
///
/// v0.4.25 根修：原实现写死 `/tmp/...` 且用 `sh -c` 串三级管道 —— Windows 上
/// 既无 `/tmp`（会解析成 `C:\tmp`，通常不存在）也无 `sh.exe`（除非 PATH 恰好带
/// Git for Windows），导致 **PIN 轨在 Windows 副端直接失败**。现改为
/// `std::env::temp_dir()` + 逐步 openssl 调用（`-out` 直接落盘，无需 shell 管道）
/// + 复用副端自带 `sha256`，三平台等价且零新增依赖。
pub fn spki_sha256_hex(cert_pem: &str) -> Option<String> {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let cert = dir.join(format!("yuduan-spki-{}.pem", pid));
    let pub_pem = dir.join(format!("yuduan-pub-{}.pem", pid));
    let pub_der = dir.join(format!("yuduan-pub-{}.der", pid));
    let cleanup = || {
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&pub_pem);
        let _ = std::fs::remove_file(&pub_der);
    };
    std::fs::write(&cert, cert_pem.as_bytes()).ok()?;
    let ossl = openssl_bin();

    // 1) 提取公钥 PEM（stdout 直接落文件，避开 shell 管道）
    let r1 = Command::new(&ossl)
        .arg("x509")
        .arg("-in")
        .arg(&cert)
        .arg("-noout")
        .arg("-pubkey")
        .output();
    let r1 = match r1 {
        Ok(r) if r.status.success() => r,
        _ => {
            cleanup();
            return None;
        }
    };
    if std::fs::write(&pub_pem, &r1.stdout).is_err() {
        cleanup();
        return None;
    }
    // 2) 公钥 PEM → SPKI DER
    let r2 = Command::new(&ossl)
        .arg("pkey")
        .arg("-pubin")
        .arg("-in")
        .arg(&pub_pem)
        .arg("-outform")
        .arg("DER")
        .arg("-out")
        .arg(&pub_der)
        .output();
    if !matches!(r2, Ok(ref r) if r.status.success()) {
        cleanup();
        return None;
    }
    // 3) 副端自带 SHA-256（FIPS 180-4），输出小写 hex，与 openssl dgst 口径一致
    let der = std::fs::read(&pub_der).ok();
    cleanup();
    let der = der?;
    Some(crate::sha256::hex_encode(&crate::sha256::sha256(&der)))
}

/// 解析 openssl dgst 输出：`(stdin)= <hex>` 或 `<hex>`。
/// 兼容保留（历史管道实现与单测使用）；当前主路径已改用副端自带 SHA-256。
#[allow(dead_code)]
fn parse_openssl_sha256(text: &str) -> Option<String> {
    // 取最后一个空白分隔 token，且为 64 位 hex
    for tok in text.split_whitespace().rev() {
        let t = tok.trim_start_matches("(stdin)=").trim_start_matches("=").trim();
        if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(t.to_ascii_lowercase());
        }
    }
    None
}

/// 校验服务端证书固定：抓取完整链，比对**叶证书**（链首）SPKI；匹配则返回
/// 完整链 PEM（供调用方作临时 CAfile——链含根锚，CA 签发与自签两种形态都可通过）。
/// 任一环节失败或不匹配均返回 None（调用方应拒绝连接）。
pub fn verify_server_pin(addr: &str, sni: &str, pin: &str) -> Option<String> {
    let pin = pin.trim().to_ascii_lowercase();
    if pin.is_empty() {
        return None;
    }
    let chain = fetch_chain_pem(addr, sni)?;
    let leaf = extract_first_cert(&chain)?;
    let spki = spki_sha256_hex(&leaf)?;
    if spki == pin {
        Some(chain)
    } else {
        eprintln!(
            "[agent] TLS 证书固定失败：SPKI 不匹配（期望 {} 实际 {}）",
            pin, spki
        );
        None
    }
}

/// 把证书 PEM 写入临时 CAfile，返回路径；调用方在 openssl 子进程 spawn 后应删除。
/// v0.4.25：改用 `std::env::temp_dir()`（原写死 `/tmp` 在 Windows 不存在，
/// 会让仅 PIN 单轨的自签兼容路径直接失败）。
pub fn write_temp_ca(pem: &str) -> Option<String> {
    let path = std::env::temp_dir()
        .join(format!("yuduan-pin-ca-{}.pem", std::process::id()));
    std::fs::write(&path, pem.as_bytes()).ok()?;
    Some(path.to_string_lossy().to_string())
}

// ---- v0.4.25：两条 TLS 通道（wss 数据隧道 / claim https 引导）共用的严格校验规划 ----
//
// 设计约束（Gate 铁律：默认 LAN 行为逐字节不变）：
//  * 未显式配置 CAFILE / PIN 时，plan_verify 返回 Ok(None)，一个参数都不追加；
//  * `-servername` 只设 SNI、不开启主机名校验（本轮不实现 -verify_hostname/-verify_ip）；
//  * CAFILE 与 PIN 为 AND 叠加，不是 fallback；
//  * 本模块不新增任何 YUDUAN_ 变量，SNI 一律从连接 URL 的 authority 推导。

/// 从 URL authority（`host:port` / `host` / `[v6]:port`）提取 SNI 主机名（去端口）。
/// 与 wss 通道 main.rs 的 authority 解析同源；本轮不新增 `YUDUAN_TLS_SNI` 变量。
pub fn sni_host_from_authority(authority: &str) -> String {
    let a = authority.trim();
    if let Some(rest) = a.strip_prefix('[') {
        // IPv6 字面量：[::1]:8443 / [::1]
        if let Some(i) = rest.find(']') {
            return rest[..i].to_string();
        }
    }
    match a.rsplit_once(':') {
        // 仅当冒号后全为数字（端口）才剥离，避免把裸 IPv6 误切
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => a.to_string(),
    }
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// 严格校验计划：`-CAfile <path> -verify_return_error` 的参数来源与临时文件归属。
#[derive(Debug)]
pub struct TlsVerifyPlan {
    pub ca_path: String,
    /// 仅 PIN 单轨时落盘的临时 CAfile；调用方须在 openssl 子进程退出后删除。
    pub temp_ca: Option<String>,
}

/// CAFILE 与 PIN 为 **AND 叠加**：都配置时 PIN 仍由 `verify_server_pin` 带外比对，
/// 且信任锚改用客户显式 CAFILE；仅 PIN 时沿用历史「抓到的证书链作临时 CAfile」
/// 自签兼容路径；仅 CAFILE 时直接链式校验；两者皆无返回 `Ok(None)`（缺省等价）。
pub fn plan_verify(addr: &str, sni: &str) -> Result<Option<TlsVerifyPlan>, String> {
    plan_verify_with(
        addr,
        sni,
        env_opt("YUDUAN_TLS_CAFILE"),
        env_opt("YUDUAN_TLS_PIN"),
    )
}

fn plan_verify_with(
    addr: &str,
    sni: &str,
    cafile: Option<String>,
    pin: Option<String>,
) -> Result<Option<TlsVerifyPlan>, String> {
    if cafile.is_none() && pin.is_none() {
        return Ok(None);
    }
    // PIN 存在即必须带外比对（与 CAFILE 并存也不例外 = AND，而非「CAFILE 优先就跳过 PIN」）。
    let pinned_chain = match &pin {
        Some(p) => Some(
            verify_server_pin(addr, sni, p).ok_or_else(|| {
                "TLS 证书固定校验失败：SPKI 不匹配或服务端证书不可达".to_string()
            })?,
        ),
        None => None,
    };
    if let Some(ca) = cafile {
        return Ok(Some(TlsVerifyPlan {
            ca_path: ca,
            temp_ca: None,
        }));
    }
    let pem = pinned_chain.unwrap_or_default();
    let path = write_temp_ca(&pem)
        .ok_or_else(|| "TLS 证书固定：无法写入临时 CA 文件".to_string())?;
    Ok(Some(TlsVerifyPlan {
        ca_path: path.clone(),
        temp_ca: Some(path),
    }))
}

/// 把严格校验参数追加到 openssl `s_client` 命令。`None` 时一个参数都不追加。
pub fn apply_verify_args(cmd: &mut std::process::Command, plan: Option<&TlsVerifyPlan>) {
    if let Some(p) = plan {
        cmd.arg("-CAfile").arg(&p.ca_path).arg("-verify_return_error");
    }
}

/// mTLS 客户端证书（两条通道共用；显式配置才追加）。
pub fn apply_client_cert_args(cmd: &mut std::process::Command) {
    if let Some(cert) = env_opt("YUDUAN_CLIENT_CERT") {
        cmd.arg("-cert").arg(cert);
    }
    if let Some(key) = env_opt("YUDUAN_CLIENT_KEY") {
        cmd.arg("-key").arg(key);
    }
}

/// 仅 PIN 单轨的临时 CAfile 清理（openssl 子进程退出后调用）。
pub fn cleanup_temp_ca(plan: Option<&TlsVerifyPlan>) {
    if let Some(p) = plan {
        if let Some(path) = &p.temp_ca {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openssl_sha256_variants() {
        assert_eq!(
            parse_openssl_sha256("(stdin)= abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into())
        );
        assert_eq!(
            parse_openssl_sha256("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into())
        );
        assert_eq!(parse_openssl_sha256("no hash here"), None);
    }

    #[test]
    fn extract_first_cert_handles_multiple() {
        let input = "junk\n-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\nmore junk\n-----BEGIN CERTIFICATE-----\nMII2\n-----END CERTIFICATE-----\n";
        let cert = extract_first_cert(input).unwrap();
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.contains("MII\n")); // 第一条
        assert!(!cert.contains("MII2")); // 不含第二条
    }

    #[test]
    fn fetch_and_pin_graceful_without_server() {
        // 无监听端口时不应 panic，应返回 None
        let r = verify_server_pin("127.0.0.1:1", "localhost", "deadbeef");
        assert!(r.is_none());
    }

    #[test]
    fn openssl_candidates_platform_paths() {
        let cands = openssl_candidates();
        assert!(!cands.is_empty());
        if cfg!(windows) {
            // 至少包含 Git for Windows 主流路径形态（含 ProgramW6432/硬编码兜底之一）
            assert!(cands.iter().any(|c| c.ends_with("Git\\usr\\bin\\openssl.exe")));
            assert!(cands.iter().all(|c| c.ends_with(".exe")));
        } else {
            assert_eq!(cands[0], "/opt/homebrew/bin/openssl");
            assert!(cands.contains(&"/usr/bin/openssl".to_string()));
        }
    }

    #[test]
    fn openssl_bin_always_nonempty() {
        // 显式 env / 探测 / PATH 回退三路必有一路，永不返回空串
        assert!(!openssl_bin().is_empty());
    }

    // ---- v0.4.25 证书校验规划的回归断言 ----

    #[test]
    fn sni_host_from_authority_variants() {
        assert_eq!(sni_host_from_authority("hub.example.com:8443"), "hub.example.com");
        assert_eq!(sni_host_from_authority("hub.example.com"), "hub.example.com");
        assert_eq!(sni_host_from_authority("192.168.1.10:8443"), "192.168.1.10");
        assert_eq!(sni_host_from_authority("localhost"), "localhost");
        assert_eq!(sni_host_from_authority("[::1]:8443"), "::1");
        assert_eq!(sni_host_from_authority("[::1]"), "::1");
    }

    #[test]
    fn plan_verify_default_adds_nothing() {
        // 三变量（CAFILE/PIN/SNI）皆未配置 → 一个参数都不追加，缺省等价
        let p = plan_verify_with("127.0.0.1:1", "localhost", None, None).unwrap();
        assert!(p.is_none());
    }

    #[test]
    fn plan_verify_cafile_only_uses_explicit_ca() {
        let p = plan_verify_with(
            "127.0.0.1:1",
            "localhost",
            Some("/tmp/customer-ca.pem".into()),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(p.ca_path, "/tmp/customer-ca.pem");
        assert!(p.temp_ca.is_none()); // 客户 CA 不是临时文件，调用方不得删除
    }

    #[test]
    fn plan_verify_cafile_and_pin_is_and_not_fallback() {
        // CAFILE 存在时 PIN 仍须带外比对：无服务端 → PIN 校验失败必须冒泡，
        // 证明「CAFILE 优先即跳过 PIN」的 fallback 语义已被消除。
        let e = plan_verify_with(
            "127.0.0.1:1",
            "localhost",
            Some("/tmp/customer-ca.pem".into()),
            Some("deadbeef".into()),
        )
        .unwrap_err();
        assert!(e.contains("证书固定"), "实际错误: {}", e);
    }

    #[test]
    fn plan_verify_pin_only_also_checks_pin() {
        let e = plan_verify_with("127.0.0.1:1", "localhost", None, Some("deadbeef".into()))
            .unwrap_err();
        assert!(e.contains("证书固定"), "实际错误: {}", e);
    }

    #[test]
    fn temp_ca_uses_platform_temp_dir() {
        // Windows 根修：不再写死 /tmp（C:\tmp 通常不存在）
        let p = write_temp_ca("dummy").unwrap();
        let path = std::path::Path::new(&p);
        assert_eq!(path.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "dummy");
        assert!(!p.starts_with("/tmp/"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn spki_hash_is_64_hex_and_stable() {
        // 真实自签证书走一遍新实现（不依赖 sh -c；无 openssl 的环境跳过）
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let key = dir.join(format!("yd-tls-test-key-{}.pem", pid));
        let crt = dir.join(format!("yd-tls-test-crt-{}.pem", pid));
        let st = std::process::Command::new(openssl_bin())
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&crt)
            .args(["-days", "1", "-subj", "/CN=localhost"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if !matches!(st, Ok(ref s) if s.success()) {
            let _ = std::fs::remove_file(&key);
            let _ = std::fs::remove_file(&crt);
            return;
        }
        let pem = std::fs::read_to_string(&crt).unwrap();
        let a = spki_sha256_hex(&pem).unwrap();
        let b = spki_sha256_hex(&pem).unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, b);
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&crt);
    }

    #[test]
    fn apply_verify_args_none_is_noop() {
        let mut cmd = std::process::Command::new("openssl");
        cmd.arg("s_client").arg("-connect").arg("127.0.0.1:1");
        apply_verify_args(&mut cmd, None);
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, vec!["s_client", "-connect", "127.0.0.1:1"]);
    }
}
