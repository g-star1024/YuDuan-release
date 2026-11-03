// 御端 Rust 副端 —— 极简 HTTP/1.1 GET 客户端（软件分发下载用）。
// 纯 std：TcpStream + 手写请求/响应解析（支持 Content-Length 与 chunked）。
// 仅覆盖 http://（软件仓库走中枢明文端口；wss 通道见 ws 层的 openssl 管道方案）。

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

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
        read_chunked(&mut reader)?
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
}
