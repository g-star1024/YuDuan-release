// 御端 Rust 副端 —— 极简 HTTP/1.1 GET 客户端（软件分发下载用）。
// 纯 std：TcpStream + 手写请求/响应解析（支持 Content-Length 与 chunked）。
// 仅覆盖 http://（软件仓库走中枢明文端口；wss 通道见 ws 层的 openssl 管道方案）。

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// 服务端 Content-Disposition 建议的文件名（软件仓库下载时携带原始包名）。
    pub suggested_name: Option<String>,
}

/// GET 一个 URL（仅支持 http://host[:port]/path），返回状态码与响应体。
pub fn http_get(url: &str, timeout_secs: u64) -> Result<HttpResponse, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("仅支持 http:// URL: {}", url))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.find(':') {
        Some(i) => (&authority[..i], authority[i + 1..].parse::<u16>().map_err(|e| e.to_string())?),
        None => (authority, 80u16),
    };
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("bad addr {}: {}", addr, e))?,
        Duration::from_secs(timeout_secs),
    )
    .map_err(|e| format!("connect {} failed: {}", addr, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(timeout_secs))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(timeout_secs))).ok();

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: yuduan-rust-agent\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, authority
    );
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    writer
        .write_all(req.as_bytes())
        .map_err(|e| format!("write failed: {}", e))?;
    writer.flush().ok();

    let mut reader = BufReader::new(stream);
    parse_response(&mut reader)
}

/// 解析 HTTP/1.1 响应（http:// 与 https:// 两条通道共用同一份逻辑，避免解析漂移）。
/// 泛型 Read：明文路径传 `BufReader<TcpStream>`，TLS 路径传 `Cursor<Vec<u8>>`。
fn parse_response<R: Read>(reader: &mut R) -> Result<HttpResponse, String> {
    // 读响应头
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => header.push(byte[0]),
            Err(e) => return Err(format!("read header failed: {}", e)),
        }
        if header.len() >= 4 && &header[header.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if header.len() > 64 * 1024 {
            return Err("response header too large".into());
        }
    }
    let header_str = String::from_utf8_lossy(&header).to_string();
    let status = header_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {}", header_str.lines().next().unwrap_or("")))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut suggested_name: Option<String> = None;
    for line in header_str.lines().skip(1) {
        let l = line.to_ascii_lowercase();
        if let Some(v) = l.strip_prefix("content-length:") {
            content_length = v.trim().parse::<usize>().ok();
        } else if l.starts_with("transfer-encoding:") && l.contains("chunked") {
            chunked = true;
        } else if l.starts_with("content-disposition:") {
            // attachment; filename="xxx.zip"（用原始大小写行解析，避免小写化文件名）
            if let Some(idx) = l.find("filename=") {
                let f = line[idx + "filename=".len()..].trim().trim_matches('"');
                let base = f.rsplit(['/', '\\']).next().unwrap_or(f);
                if !base.is_empty() {
                    suggested_name = Some(base.to_string());
                }
            }
        }
    }

    let body = if chunked {
        read_chunked(&mut *reader)?
    } else if let Some(n) = content_length {
        let mut buf = vec![0u8; n];
        reader
            .read_exact(&mut buf)
            .map_err(|e| format!("read body failed: {}", e))?;
        buf
    } else {
        // Connection: close：读到 EOF
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| format!("read body failed: {}", e))?;
        buf
    };
    Ok(HttpResponse { status, body, suggested_name })
}

fn read_chunked<R: Read>(reader: &mut R) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line = read_line(reader)?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|e| format!("bad chunk size: {}", e))?;
        if size == 0 {
            // 读取尾部 CRLF（或 trailer）
            let _ = read_line(reader);
            break;
        }
        let mut buf = vec![0u8; size];
        reader
            .read_exact(&mut buf)
            .map_err(|e| format!("read chunk failed: {}", e))?;
        out.extend_from_slice(&buf);
        let _ = read_line(reader)?; // chunk 后 CRLF
    }
    Ok(out)
}

fn read_line<R: Read>(reader: &mut R) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                line.push(byte[0]);
                if line.len() >= 2 && &line[line.len() - 2..] == b"\r\n" {
                    line.truncate(line.len() - 2);
                    break;
                }
            }
            Err(e) => return Err(format!("read line failed: {}", e)),
        }
        if line.len() > 8 * 1024 {
            return Err("line too long".into());
        }
    }
    Ok(String::from_utf8_lossy(&line).to_string())
}

/// GET 一个 `https://` URL（v0.4.25：补齐副端 https 直连下载占位）。
///
/// 与 wss 数据隧道 / claim https 引导共用 `tls::plan_verify` 的严格校验规划：
/// `-servername` 从 URL authority 推导；`-CAfile -verify_return_error` 仅在显式
/// `YUDUAN_TLS_CAFILE` / `YUDUAN_TLS_PIN` 存在时追加；两者皆不配时保持局域网
/// 自签信任模型，行为与 http 路径对称。openssl 子进程 stdout 由独立线程排空，
/// 主线程按 timeout 守护并 kill 超时进程，避免大包撑满管道或半开连接挂死。
pub fn https_get(url: &str, timeout_secs: u64) -> Result<HttpResponse, String> {
    use std::io::Cursor;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("仅支持 https:// URL: {}", url))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let sni = crate::tls::sni_host_from_authority(authority);
    let plan = crate::tls::plan_verify(authority, &sni)?;

    let mut cmd = Command::new(crate::tls::openssl_bin());
    cmd.args([
        "s_client",
        "-connect",
        authority,
        "-servername",
        sni.as_str(),
        "-quiet",
        "-ign_eof",
    ]);
    crate::tls::apply_verify_args(&mut cmd, plan.as_ref());
    crate::tls::apply_client_cert_args(&mut cmd);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn openssl failed: {}（https 下载需要系统 openssl）", e))?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: yuduan-rust-agent\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, authority
    );
    {
        let mut sin = child
            .stdin
            .take()
            .ok_or_else(|| "openssl stdin 不可用".to_string())?;
        sin.write_all(req.as_bytes())
            .map_err(|e| format!("write failed: {}", e))?;
        sin.flush().ok();
    }
    // 独立线程排空 stdout：安装包可达数百 MB，同步等待会把管道写满导致死锁。
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "openssl stdout 不可用".to_string())?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let err = stdout.read_to_end(&mut buf).err().map(|e| e.to_string());
        let _ = tx.send((buf, err));
    });
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    crate::tls::cleanup_temp_ca(plan.as_ref());
                    return Err(format!("https 下载超时（{}s）", timeout_secs));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("openssl wait failed: {}", e)),
        }
    }
    let _ = child.wait();
    crate::tls::cleanup_temp_ca(plan.as_ref());
    let (buf, read_err) = rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "https 下载读取超时".to_string())?;
    if let Some(e) = read_err {
        return Err(format!("read body failed: {}", e));
    }
    if buf.is_empty() {
        return Err(
            "https 下载无响应：请检查 TLS 证书配置（YUDUAN_TLS_CAFILE / YUDUAN_TLS_PIN）与目标服务"
                .to_string(),
        );
    }
    let mut cursor = Cursor::new(buf);
    parse_response(&mut cursor)
}

/// 下载到临时文件，返回 (路径, 服务端建议文件名)。
pub fn download_to_temp(url: &str, prefix: &str) -> Result<(String, Option<String>), String> {
    let resp = http_get(url, 120)?;
    if resp.status != 200 {
        return Err(format!("http status {}", resp.status));
    }
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = dir.join(format!("{}-{}-{}.bin", prefix, pid, nanos % 1_000_000));
    std::fs::write(&path, &resp.body).map_err(|e| format!("write temp failed: {}", e))?;
    Ok((path.to_string_lossy().to_string(), resp.suggested_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_forms() {
        // 仅验证 URL 解析不抛异常
        assert!(http_get("ftp://x", 1).is_err());
        assert!(http_get("http://127.0.0.1:1/x", 1).is_err());
    }

    // ---- v0.4.25：http / https 共用的响应解析回归 ----

    #[test]
    fn parse_response_content_length_and_filename() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Disposition: attachment; filename=\"pkg/root/a.zip\"\r\n\r\nhello";
        let mut c = std::io::Cursor::new(raw.to_vec());
        let r = parse_response(&mut c).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
        assert_eq!(r.suggested_name.as_deref(), Some("a.zip"));
    }

    #[test]
    fn parse_response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let mut c = std::io::Cursor::new(raw.to_vec());
        let r = parse_response(&mut c).unwrap();
        assert_eq!(r.body, b"abcde");
    }

    #[test]
    fn parse_response_read_to_eof() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\nmissing";
        let mut c = std::io::Cursor::new(raw.to_vec());
        let r = parse_response(&mut c).unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"missing");
    }

    #[test]
    fn https_get_rejects_non_https_url() {
        // 不触发 openssl：协议守卫必须先于任何子进程
        let e = https_get("http://127.0.0.1:1/x", 1).unwrap_err();
        assert!(e.contains("仅支持 https://"), "实际错误: {}", e);
    }
}
