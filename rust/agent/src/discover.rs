//! UDP 广播自动发现中枢（§8.4）。
//!
//! YUDUAN_HUB 未设置时的兜底：向 255.255.255.255:18242 广播 "YUDUAN_DISCOVER"，
//! 收中枢单行回复 `proto=yuduan-disc http=http://<ip>:<port> ws=ws://<ip>:<port>/ws/agent hostname=<h>`，
//! 取 ws= 字段作为连接地址。纯 std（UdpSocket + broadcast），无第三方依赖。

use std::net::UdpSocket;
use std::time::{Duration, Instant};

pub const PROBE: &[u8] = b"YUDUAN_DISCOVER";
pub const DISCOVERY_PORT: u16 = 18242;

/// 从环境变量原始值解析 UDP 发现端口（F-07）。纯函数、不触碰进程级 env，
/// 便于单测而不落入 Rust 单测并行读写全局 env 互相干扰的竞态。
/// 语义与主端 `resolve_discovery_port` / 中枢 `envIntOr` 一致：trim → parse<u16> → >0；
/// 缺省 / 非法 / 0 一律回退默认端口（LAN 零回归）。
fn parse_discovery_port(raw: Option<&str>) -> u16 {
    raw.and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(DISCOVERY_PORT)
}

/// 运行时 UDP 发现端口：可由 `YUDUAN_DISCOVERY_PORT` 覆盖，否则用默认值 18242。
pub fn discovery_port() -> u16 {
    let raw = std::env::var("YUDUAN_DISCOVERY_PORT").ok();
    parse_discovery_port(raw.as_deref())
}

/// 一次广播发现的完整结果：中枢 ws 地址 + 一次性注册令牌（档位 A 设备引导）。
/// token 仅在副端 claim 引导配置时用一次，不落日志、不长期持有。
pub struct Discovery {
    pub ws: String,
    pub token: String,
}

/// 广播探测并返回首个发现结果（ws 地址 + 注册令牌）；超时无响应返回 None。
pub fn discover_hub(timeout: Duration) -> Option<Discovery> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_broadcast(true).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(300))).ok()?;
    sock.send_to(PROBE, ("255.255.255.255", discovery_port())).ok()?;
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(ws) = parse_ws(&buf[..n]) {
                    return Some(Discovery {
                        ws,
                        token: parse_token(&buf[..n]).unwrap_or_default(),
                    });
                }
            }
            Err(_) => continue, // 读超时，继续等剩余窗口
        }
    }
    None
}

/// 广播探测并返回首个发现的 ws:// 中枢地址；超时无响应返回 None。
pub fn discover_ws(timeout: Duration) -> Option<String> {
    discover_hub(timeout).map(|d| d.ws)
}

/// 解析单行回复，取连接地址字段（严格前缀匹配，不信任多余内容）。
/// 复盘 S-2：TLS 启用时中枢广播 wss= 与 ws= 双字段，副端**优先 wss**（claim 仅 TLS 可
/// 下发密钥）；无 wss 时回退 ws=（兼容纯明文部署）。
pub fn parse_ws(line: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(line).ok()?;
    let toks: Vec<&str> = s.split_whitespace().collect();
    toks.iter()
        .find_map(|t| t.strip_prefix("wss="))
        .filter(|v| v.starts_with("wss://"))
        .map(|v| v.to_string())
        .or_else(|| {
            toks.iter()
                .find_map(|t| t.strip_prefix("ws="))
                .filter(|v| v.starts_with("ws://"))
                .map(|v| v.to_string())
        })
}

/// 解析单行回复，取 token= 字段（一次性注册令牌；缺失返回 None）。
pub fn parse_token(line: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(line).ok()?;
    s.split_whitespace()
        .find_map(|tok| tok.strip_prefix("token="))
        .filter(|v| !v.is_empty())
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
    fn parse_ws_prefers_wss_when_tls_advertised() {
        // 复盘 S-2：TLS 启用时中枢同时广播 ws= 与 wss=，副端必须优先 wss（claim 仅 TLS 可下发密钥）。
        let line = b"proto=yuduan-disc http=http://192.168.1.24:8080 ws=ws://192.168.1.24:8080/ws/agent wss=wss://192.168.1.24:8443/ws/agent https=https://192.168.1.24:8443 hostname=hub token=ab";
        assert_eq!(
            parse_ws(line).as_deref(),
            Some("wss://192.168.1.24:8443/ws/agent")
        );
    }

    #[test]
    fn parse_ws_falls_back_to_plaintext_without_wss() {
        // 纯明文部署（中枢未启 TLS）：只广播 ws=，回退明文。
        let line = b"proto=yuduan-disc ws=ws://10.0.0.5:8080/ws/agent hostname=h token=cd";
        assert_eq!(parse_ws(line).as_deref(), Some("ws://10.0.0.5:8080/ws/agent"));
    }

    #[test]
    fn parse_ws_rejects_garbage_and_non_ws_scheme() {
        assert!(parse_ws(b"hello world").is_none());
        assert!(parse_ws(b"ws=not-a-scheme").is_none());
        assert!(parse_ws(b"proto=yuduan-disc").is_none());
    }

    #[test]
    fn parse_token_extracts_field() {
        let line = b"proto=yuduan-disc ws=ws://192.168.1.24:18241/ws/agent hostname=hub token=abcd1234";
        assert_eq!(parse_token(line).as_deref(), Some("abcd1234"));
    }

    #[test]
    fn parse_token_absent_or_empty() {
        assert!(parse_token(b"proto=yuduan-disc ws=ws://x").is_none());
        assert!(parse_token(b"token= ws=ws://x").is_none());
    }

    #[test]
    fn discover_hub_returns_ws_and_token() {
        // 直接验证 Discovery 结构组装（网络栈在 CI 不稳定，协议解析单独测）
        let line = b"proto=yuduan-disc ws=ws://10.0.0.5:18241/ws/agent hostname=h token=deadbeef";
        let d = Discovery {
            ws: parse_ws(line).unwrap(),
            token: parse_token(line).unwrap(),
        };
        assert_eq!(d.ws, "ws://10.0.0.5:18241/ws/agent");
        assert_eq!(d.token, "deadbeef");
    }

    // —— F-07：端口解析纯函数（不改进程级 env，避免并行单测竞态） ——

    #[test]
    fn parse_discovery_port_defaults_when_absent() {
        assert_eq!(parse_discovery_port(None), DISCOVERY_PORT);
        assert_eq!(parse_discovery_port(Some("")), DISCOVERY_PORT);
        assert_eq!(parse_discovery_port(Some("   ")), DISCOVERY_PORT);
    }

    #[test]
    fn parse_discovery_port_valid_value() {
        assert_eq!(parse_discovery_port(Some("19000")), 19000);
        // 前后空白按 trim 处理，与主端 resolve_discovery_port 一致
        assert_eq!(parse_discovery_port(Some(" 20000 ")), 20000);
    }

    #[test]
    fn parse_discovery_port_invalid_falls_back() {
        assert_eq!(parse_discovery_port(Some("abc")), DISCOVERY_PORT);
        assert_eq!(parse_discovery_port(Some("70000")), DISCOVERY_PORT); // 超 u16
        assert_eq!(parse_discovery_port(Some("-1")), DISCOVERY_PORT);
    }

    #[test]
    fn parse_discovery_port_zero_falls_back() {
        assert_eq!(parse_discovery_port(Some("0")), DISCOVERY_PORT);
    }

    #[test]
    fn parse_discovery_port_max_u16() {
        assert_eq!(parse_discovery_port(Some("65535")), 65535);
    }
}
