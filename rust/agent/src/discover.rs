//! UDP 广播自动发现中枢（§8.4）。
//!
//! YUDUAN_HUB 未设置时的兜底：向 255.255.255.255:18242 广播 "YUDUAN_DISCOVER"，
//! 收中枢单行回复 `proto=yuduan-disc http=http://<ip>:<port> ws=ws://<ip>:<port>/ws/agent hostname=<h>`，
//! 取 ws= 字段作为连接地址。纯 std（UdpSocket + broadcast），无第三方依赖。

use std::net::UdpSocket;
use std::time::{Duration, Instant};

pub const PROBE: &[u8] = b"YUDUAN_DISCOVER";
pub const DISCOVERY_PORT: u16 = 18242;

/// 广播探测并返回首个发现的 ws:// 中枢地址；超时无响应返回 None。
pub fn discover_ws(timeout: Duration) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_broadcast(true).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(300))).ok()?;
    sock.send_to(PROBE, ("255.255.255.255", DISCOVERY_PORT)).ok()?;
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(ws) = parse_ws(&buf[..n]) {
                    return Some(ws);
                }
            }
            Err(_) => continue, // 读超时，继续等剩余窗口
        }
    }
    None
}

/// 解析单行回复，取 ws= 字段（严格前缀匹配，不信任多余内容）。
pub fn parse_ws(line: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(line).ok()?;
    s.split_whitespace()
        .find_map(|tok| tok.strip_prefix("ws="))
        .filter(|v| v.starts_with("ws://") || v.starts_with("wss://"))
        .map(|v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ws_extracts_field() {
        let line = b"proto=yuduan-disc http=http://192.168.1.24:18241 ws=ws://192.168.1.24:18241/ws/agent hostname=hub";
        assert_eq!(
            parse_ws(line).as_deref(),
            Some("ws://192.168.1.24:18241/ws/agent")
        );
    }

    #[test]
    fn parse_ws_rejects_garbage_and_non_ws_scheme() {
        assert!(parse_ws(b"hello world").is_none());
        assert!(parse_ws(b"ws=not-a-scheme").is_none());
        assert!(parse_ws(b"proto=yuduan-disc").is_none());
    }
}
