// 御端 Rust 副端 —— 指令验签（铁律 4：关键指令服务端签名、副端验签）。
// 规范串与 Go 中枢一致：msg_id|ts|seq|payload_json|nonce，HMAC-SHA256 十六进制。
// 防重放：nonce 去重（有界环）+ 时间窗 ±300s（与 Go VerifyCommand maxSkew 一致）。

use crate::sha256::{ct_eq, hex_encode, hmac_sha256};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_SKEW_SECS: i64 = 300;

/// 判定消息类型是否属于「远控控制指令」（铁律 4：remote_control 为关键指令，
/// 必须 HMAC-SHA256 签名 + seq/nonce 防重放）。
///
/// 纳入门禁的是**主端→副端、会驱动被控端执行动作**的消息：
/// rc_request（发起会话）/ rc_input（键鼠注入）/ rc_stop（结束会话）/
/// rc_select（媒体协商触发 P2P 直连）/ rc_offer / rc_candidate（P2P 候选拨号）/
/// rc_qos（帧率重参数化）/ rc_ping（RTT 探测触发回包）。
/// 反向消息（rc_ready / rc_frame / rc_capabilities / rc_answer / rc_event / rc_pong）
/// 由副端发出，属上报而非指令，不在此列。
///
/// 与 Go 中枢 `proto.IsRCControl` 同口径（协议 §8.6），两端须同步修改。
pub fn is_rc_control(t: &str) -> bool {
    matches!(
        t,
        "rc_request"
            | "rc_input"
            | "rc_stop"
            | "rc_select"
            | "rc_offer"
            | "rc_candidate"
            | "rc_qos"
            | "rc_ping"
    )
}

/// nonce 防重放器（有界环，容量满时淘汰最旧）。
pub struct NonceGuard {
    seen: Mutex<VecDeque<String>>,
    cap: usize,
}

impl NonceGuard {
    pub fn new(cap: usize) -> Self {
        NonceGuard {
            seen: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
        }
    }
    /// 返回 true 表示首次见到（放行）；false 表示重放。
    pub fn check_and_insert(&self, nonce: &str) -> bool {
        if nonce.is_empty() {
            return false; // 无 nonce 一律拒绝（服务端必带）
        }
        let mut seen = self.seen.lock().unwrap();
        if seen.iter().any(|n| n == nonce) {
            return false;
        }
        if seen.len() >= self.cap {
            seen.pop_front();
        }
        seen.push_back(nonce.to_string());
        true
    }
}

/// 从信封原文中提取 payload 的原始 JSON 文本（签名按原文计算，不能重新序列化）。
pub fn extract_raw_payload(frame: &str) -> Option<&str> {
    let key = "\"payload\":";
    let idx = frame.find(key)?;
    let mut i = idx + key.len();
    let bytes = frame.as_bytes();
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'{' {
        return None;
    }
    let start = i;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&frame[start..=i]);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

fn json_str_field(env: &crate::Json, key: &str) -> String {
    env.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn json_int_field(env: &crate::Json, key: &str) -> Option<i64> {
    env.get(key).and_then(|v| v.as_i64())
}

/// 验签结果。
pub enum VerifyOutcome {
    Ok,
    NoSecret,          // 未配置 secret：放行（开发态）
    BadSignature,      // 签名不匹配
    Replayed,          // nonce 重放
    TimeSkew,          // 时间窗超限
    Malformed,         // 字段缺失/无法解析
}

/// 校验一条指令信封。secret 为空时返回 NoSecret（不强制）。
pub fn verify_command(
    secret: &str,
    frame: &str,
    env: &crate::Json,
    nonce_guard: &NonceGuard,
) -> VerifyOutcome {
    if secret.is_empty() {
        return VerifyOutcome::NoSecret;
    }
    let msg_id = json_str_field(env, "msg_id");
    let nonce = json_str_field(env, "nonce");
    let sig = json_str_field(env, "sig");
    let ts = match json_int_field(env, "ts") {
        Some(t) => t,
        None => return VerifyOutcome::Malformed,
    };
    let seq = match json_int_field(env, "seq") {
        Some(s) => s,
        None => return VerifyOutcome::Malformed,
    };
    let payload_raw = match extract_raw_payload(frame) {
        Some(p) => p,
        None => return VerifyOutcome::Malformed,
    };
    if msg_id.is_empty() || nonce.is_empty() || sig.is_empty() {
        return VerifyOutcome::Malformed;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - ts).abs() > MAX_SKEW_SECS {
        return VerifyOutcome::TimeSkew;
    }
    let canonical = format!("{}|{}|{}|{}|{}", msg_id, ts, seq, payload_raw, nonce);
    let expected = hex_encode(&hmac_sha256(secret.as_bytes(), canonical.as_bytes()));
    if !ct_eq(expected.as_bytes(), sig.as_bytes()) {
        return VerifyOutcome::BadSignature;
    }
    if !nonce_guard.check_and_insert(&nonce) {
        return VerifyOutcome::Replayed;
    }
    VerifyOutcome::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::{hex_encode, hmac_sha256};

    fn sign(secret: &str, msg_id: &str, ts: i64, seq: i64, payload: &str, nonce: &str) -> String {
        let canonical = format!("{}|{}|{}|{}|{}", msg_id, ts, seq, payload, nonce);
        hex_encode(&hmac_sha256(secret.as_bytes(), canonical.as_bytes()))
    }

    /// 远控指令门禁的类型集合须与 Go 中枢 `proto.IsRCControl` 完全一致（协议 §8.6）。
    #[test]
    fn is_rc_control_covers_driving_messages_only() {
        for t in [
            "rc_request",
            "rc_input",
            "rc_stop",
            "rc_select",
            "rc_offer",
            "rc_candidate",
            "rc_qos",
            "rc_ping",
        ] {
            assert!(is_rc_control(t), "{} 应纳入签名门禁", t);
        }
        for t in [
            "rc_ready",
            "rc_frame",
            "rc_capabilities",
            "rc_answer",
            "rc_event",
            "rc_pong",
            "command",
            "heartbeat",
        ] {
            assert!(!is_rc_control(t), "{} 属上报/普通指令，不应纳入远控门禁", t);
        }
    }

    /// 远控信封走同一验签函数：无签名被拒、正确签名放行（与 command 同口径）。
    #[test]
    fn verify_command_applies_to_rc_envelope() {
        let secret = "rc-gate-secret";
        let guard = NonceGuard::new(8);
        let payload = r#"{"session_id":"s1","device_id":"d1"}"#;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let good = sign(secret, "m1", ts, 3, payload, "n-rc-1");
        let frame = format!(
            r#"{{"ver":1,"msg_id":"m1","ts":{},"type":"rc_request","seq":3,"payload":{},"nonce":"n-rc-1","sig":"{}"}}"#,
            ts, payload, good
        );
        let env = crate::parse_json(frame.as_bytes()).unwrap();
        assert!(is_rc_control("rc_request"));
        assert!(matches!(
            verify_command(secret, &frame, &env, &guard),
            VerifyOutcome::Ok
        ));
        // 重放：同一 nonce 二次到达必须拒绝
        assert!(matches!(
            verify_command(secret, &frame, &env, &guard),
            VerifyOutcome::Replayed
        ));
        // 无签名的伪造远控指令（中间人/假中枢）必须被拒
        let forged = format!(
            r#"{{"ver":1,"msg_id":"m1","ts":{},"type":"rc_request","seq":3,"payload":{},"nonce":"n-rc-2","sig":"deadbeef"}}"#,
            ts, payload
        );
        let env2 = crate::parse_json(forged.as_bytes()).unwrap();
        assert!(matches!(
            verify_command(secret, &forged, &env2, &guard),
            VerifyOutcome::BadSignature
        ));
    }

    #[test]
    fn extract_raw_payload_balances_braces() {
        let frame = r#"{"ver":1,"msg_id":"m1","ts":1,"type":"command","seq":1,"payload":{"action":"shell","command":"echo }{"},"nonce":"n","sig":"s"}"#;
        let raw = extract_raw_payload(frame).unwrap();
        assert_eq!(raw, r#"{"action":"shell","command":"echo }{"}"#);
    }

    #[test]
    fn verify_ok_and_replay() {
        let secret = "diagsecret";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let payload = r#"{"action":"shell","task_id":"t1","command":"echo hi"}"#;
        let sig = sign(secret, "m1", ts, 1, payload, "nonce-1");
        let frame = format!(
            r#"{{"ver":1,"msg_id":"m1","ts":{},"type":"command","seq":1,"payload":{},"nonce":"nonce-1","sig":"{}"}}"#,
            ts, payload, sig
        );
        let env = crate::parse_json(frame.as_bytes()).unwrap();
        let guard = NonceGuard::new(16);
        assert!(matches!(verify_command(secret, &frame, &env, &guard), VerifyOutcome::Ok));
        // 同一帧重放 → 拒绝
        assert!(matches!(
            verify_command(secret, &frame, &env, &guard),
            VerifyOutcome::Replayed
        ));
    }

    #[test]
    fn verify_bad_signature_and_skew() {
        let secret = "diagsecret";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let payload = r#"{"action":"shell"}"#;
        // 错误签名
        let frame = format!(
            r#"{{"msg_id":"m1","ts":{},"type":"command","seq":1,"payload":{},"nonce":"n2","sig":"deadbeef"}}"#,
            ts, payload
        );
        let env = crate::parse_json(frame.as_bytes()).unwrap();
        let guard = NonceGuard::new(16);
        assert!(matches!(
            verify_command(secret, &frame, &env, &guard),
            VerifyOutcome::BadSignature
        ));
        // 时间偏移过大
        let sig = sign(secret, "m2", ts - 100000, 1, payload, "n3");
        let frame = format!(
            r#"{{"msg_id":"m2","ts":{},"type":"command","seq":1,"payload":{},"nonce":"n3","sig":"{}"}}"#,
            ts - 100000, payload, sig
        );
        let env = crate::parse_json(frame.as_bytes()).unwrap();
        assert!(matches!(
            verify_command(secret, &frame, &env, &guard),
            VerifyOutcome::TimeSkew
        ));
        // 未配置 secret → 放行
        let frame = format!(
            r#"{{"msg_id":"m3","ts":{},"type":"command","seq":1,"payload":{},"nonce":"n4","sig":"x"}}"#,
            ts, payload
        );
        let env = crate::parse_json(frame.as_bytes()).unwrap();
        assert!(matches!(verify_command("", &frame, &env, &guard), VerifyOutcome::NoSecret));
    }
}
