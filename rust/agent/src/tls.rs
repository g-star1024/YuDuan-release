// 御端 Rust 副端 —— TLS 加固（证书固定 / mTLS 客户端证书，std-only，复用系统 openssl）。
//
// 局域网信任模型下 wss 缺省接受自签名；生产应配置 CA 或固定证书指纹。
// 本模块提供：
//  - 抓取服务端叶子证书并计算 SPKI SHA-256（RFC 7469 公钥固定）；
//  - 供 WsClient 在连接前校验固定指纹，并把该证书作为临时 CAfile 供数据隧道严格信任
//    （pin 即「仅信任此证书」，避免 TOCTOU）。
//  - mTLS 客户端证书由 connect 通过 openssl -cert/-key 透传。

use std::process::Command;

/// 抓取服务端下发的**完整证书链** PEM（s_client -showcerts 全部 CERTIFICATE 块按序拼接，
/// 首张为叶证书）。openssl 不可用时返回 None（调用方据此拒绝连接，安全失败）。
/// 私有 CA 模式下中枢应下发 leaf+root 全链：完整链才能同时满足
/// 「叶证书当 pin 锚」与「链式校验需要根锚」两种临时 CAfile 用法。
pub fn fetch_chain_pem(addr: &str, sni: &str) -> Option<String> {
    let out = Command::new("openssl")
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
pub fn spki_sha256_hex(cert_pem: &str) -> Option<String> {
    // 落临时文件，避免 shell 转义问题
    let tmp = format!("/tmp/yuduan-spki-{}.pem", std::process::id());
    {
        let mut f = std::fs::File::create(&tmp).ok()?;
        use std::io::Write;
        f.write_all(cert_pem.as_bytes()).ok()?;
    }
    let script = format!(
        "openssl x509 -in '{}' -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256",
        tmp
    );
    let out = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .ok();
    let _ = std::fs::remove_file(&tmp);
    let out = out?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_openssl_sha256(&text)
}

/// 解析 openssl dgst 输出：`(stdin)= <hex>` 或 `<hex>`。
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
pub fn write_temp_ca(pem: &str) -> Option<String> {
    let path = format!("/tmp/yuduan-pin-ca-{}.pem", std::process::id());
    let mut f = std::fs::File::create(&path).ok()?;
    use std::io::Write;
    f.write_all(pem.as_bytes()).ok()?;
    Some(path)
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
}
