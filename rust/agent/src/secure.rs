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
/// 波次 2 追加（与 Go 中枢 `proto.IsRCControl` 同口径，两端须同步修改）：
/// rc_chat（以管理员身份向远端员工投递内容，须防冒名）/ rc_display（改变被控端画面输出）/
/// rc_file_offer / rc_file_accept / rc_file_chunk / rc_file_done（在被控端读写文件）。
///
/// 与 Go 中枢 `proto.IsRCControl` 同口径（协议 §8.5/§8.6），两端须同步修改。
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
            | "rc_chat"
            | "rc_display"
            | "rc_file_offer"
            | "rc_file_accept"
            | "rc_file_chunk"
            | "rc_file_done"
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
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
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

/// 计算 §9.1 注册凭据握手的应答 MAC（小程十六进制）。
///
/// 规范串必须与 Go 中枢 `crypto.SignRegisterAuth` 逐字节一致：
/// `"yuduan-register|" + nonce + "|" + token`。该约束由本模块的黄金向量用例
/// 与 Go 侧 `internal/crypto/regauth_test.go` 互锁——任一处漂移都会在
/// 「两端各自全绿」的表象下造成整网设备无法注册，故不可凭单欢呼测试通过。
pub fn register_auth_mac(secret: &str, nonce: &str, token: &str) -> String {
    let canonical = format!("yuduan-register|{}|{}", nonce, token);
    hex_encode(&hmac_sha256(secret.as_bytes(), canonical.as_bytes()))
}

// ===================== §9.2 副端设备证明（v0.4.31 安全 P2 基础） =====================
//
// 与 Go 中枢 `internal/crypto/attest.go::AttestationCanonical` **同名同串**互锁：
// 规范串、ts 单位（秒）、「签名消息 = 规范串的 32 字节 SHA-256 摘要」三者任一漂移
// 都会让整网验签互锁失败，而两端各自单测仍可能全绿——故以固定黄金向量两侧对齐
// （Go internal/crypto/attest_test.go ↔ 本文件 attestation_golden_vector）。

/// §9.2 规范串：`"yuduan-attest|" + nonce + "|" + token + "|" + measurement + "|" + ts`。
/// 绑定挑战 nonce、声明身份 token、二进制度量 measurement、挑战下发的 unix 秒 ts，
/// 防重放与换身份。ts 用**原始值**（秒；绝不用毫秒）。
pub fn attestation_canonical(nonce: &str, token: &str, measurement: &str, ts: i64) -> String {
    format!("yuduan-attest|{}|{}|{}|{}", nonce, token, measurement, ts)
}

/// 规范串的 SHA-256 摘要（32 字节）——即 ed25519::sign(seed, digest) 的 message。
/// 与 Go `ed25519.Sign(priv, digest)` / M5 软件分发 `ed25519::verify(&pk, &digest, &sig)`
/// 同语义：签名消息是摘要本身，不是规范串原文。
pub fn attestation_digest(nonce: &str, token: &str, measurement: &str, ts: i64) -> [u8; 32] {
    crate::sha256::sha256(attestation_canonical(nonce, token, measurement, ts).as_bytes())
}

/// 签名助手：seed(32B) 对摘要签名，返回 (pubkeyHex, sigHex)。
/// 任一步失败（seed 长度非法）返回 None，由调用方退回旧三字段、不阻断注册。
pub fn sign_attestation(
    seed: &[u8],
    nonce: &str,
    token: &str,
    measurement: &str,
    ts: i64,
) -> Option<(String, String)> {
    let digest = attestation_digest(nonce, token, measurement, ts);
    let sig = crate::ed25519::sign(seed, &digest)?;
    let public = crate::ed25519::public_key(seed)?;
    Some((hex_encode(&public), hex_encode(&sig)))
}

// 注：±300s 时间窗判定**不在副端做**。规范串 ts 恒为 challenge.TS 原值（不归一、
// 不改写、不用本地时间），时间窗由中枢接线时对 challenge.TS 旁路判定（见
// dev/internal/crypto/attest.go 注释与 protocol.md §9.2）。副端只负责用原始 ts 签名。

/// 构造 auth_response 的 payload JSON。
/// `attest=None`（= 中枢未要求 require_attest / 密钥或度量未就绪）时输出与旧副端
/// **逐字节一致**的原三字段 `{nonce,mac,token}`；Some 时追加 §9.2 三字段。
/// 纯函数便于单测锁定「缺 require_attest 时三字段不变」。
pub fn build_auth_response(
    nonce: &str,
    mac: &str,
    token: &str,
    attest: Option<(&str, &str, &str)>, // (pubkey, attest_sig, measurement)
) -> String {
    let j = crate::json_string;
    match attest {
        None => format!(
            r#"{{"nonce":{},"mac":{},"token":{}}}"#,
            j(nonce),
            j(mac),
            j(token)
        ),
        Some((pubkey, sig, measurement)) => format!(
            r#"{{"nonce":{},"mac":{},"token":{},"pubkey":{},"attest_sig":{},"measurement":{}}}"#,
            j(nonce),
            j(mac),
            j(token),
            j(pubkey),
            j(sig),
            j(measurement)
        ),
    }
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
    // v0.4.18：ts 单位兼容。历史主端曾以毫秒发 envelope ts，中枢原样转发
    // （NormalizeForSigning 仅补 0 值），秒级窗口判定必然 TimeSkew——生产网
    // 启用 HMAC 后主端所有远控指令被拒（用户侧表现为无限转圈）。按量级归一
    // 到秒再做窗口判定；签名规范串仍用原始 ts（与中枢 SignCommand 口径一致）。
    let ts_secs = if ts > 1_000_000_000_000 { ts / 1000 } else { ts };
    if (now - ts_secs).abs() > MAX_SKEW_SECS {
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

/// §9.1 注册挑战应答黄金向量——与 Go 中枢 `internal/crypto/regauth_test.go`
/// 使用同一组输入与期望值，防止两端规范串漂移。
#[test]
fn register_auth_mac_golden_vectors() {
    let cases = [
        (
            "yuduan-golden-secret",
            "000102030405060708090a0b0c0d0e0f",
            "dev-token-1",
            "29ad76ae575ea8e5f224b8668f8b94fba27cd3f59339919ab731e2ac8c9a1b45",
        ),
        (
            "yuduan-golden-secret",
            "000102030405060708090a0b0c0d0e0f",
            "",
            "f1decc1d2b2969404323ac050c79f332dfcba6800182a0bb77d8deefd06c502b",
        ),
        (
            "s3-cret",
            "nonce-empty-token",
            "",
            "9896f83576ea8f969c12de9282dc1828e201f66be92f4a763de626ae74fd76f4",
        ),
    ];
    for (secret, nonce, token, want) in cases {
        let got = register_auth_mac(secret, nonce, token);
        assert_eq!(got, want, "MAC 与黄金向量不一致（规范串可能已漂移）");
    }
    // 身份绑定：同一 nonce 换 token 必须得到不同 MAC，否则「换身份重放」仍成立
    assert_ne!(
        register_auth_mac("k", "n", "tok-a"),
        register_auth_mac("k", "n", "tok-b")
    );
}

// ---- §9.2 设备证明：跨语言黄金向量（与 Go internal/crypto/attest_test.go 逐字对齐）----
// 固定 nonce/token/measurement/ts/seed/期望 digest/pubkey/sig。任一侧改串、改 ts
// 单位、或改用规范串原文（而非 32 字节摘要）签名，另一侧必须同步，否则整网互锁失败。
const A_NONCE: &str = "000102030405060708090a0b0c0d0e0f";
const A_TOKEN: &str = "dev-token-1";
const A_MEASUREMENT: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const A_TS: i64 = 1700000000;
const A_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const A_CANONICAL: &str =
    "yuduan-attest|000102030405060708090a0b0c0d0e0f|dev-token-1|0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|1700000000";
const A_DIGEST: &str = "f94aec7edd47b1c06891895a1a39bea630b880b079aa0018e09907dc063eee7a";
const A_PUBKEY: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const A_SIG: &str = "47aa279435e1ffa0a0689fc37f90c8475f862463849fdc01303ebcc82303d028027c7ab825407f7677eb348c32342037af0547c478793c1ea1adbdeced1dfb09";

#[test]
fn attestation_golden_vector() {
    let canonical = attestation_canonical(A_NONCE, A_TOKEN, A_MEASUREMENT, A_TS);
    assert!(
        crate::sha256::ct_eq(canonical.as_bytes(), A_CANONICAL.as_bytes()),
        "规范串与 Go 侧不一致：{}",
        canonical
    );

    let digest = attestation_digest(A_NONCE, A_TOKEN, A_MEASUREMENT, A_TS);
    let digest_hex = crate::sha256::hex_encode(&digest);
    assert!(
        crate::sha256::ct_eq(digest_hex.as_bytes(), A_DIGEST.as_bytes()),
        "摘要与 Go 侧不一致"
    );

    let seed = crate::sha256::hex_decode(A_SEED).unwrap();
    let pubkey = crate::ed25519::public_key(&seed).unwrap();
    assert!(
        crate::sha256::ct_eq(crate::sha256::hex_encode(&pubkey).as_bytes(), A_PUBKEY.as_bytes()),
        "公钥与 Go 侧不一致"
    );

    let sig = crate::ed25519::sign(&seed, &digest).unwrap();
    let sig_hex = crate::sha256::hex_encode(&sig);
    assert!(
        crate::sha256::ct_eq(sig_hex.as_bytes(), A_SIG.as_bytes()),
        "签名与 Go 侧不一致（跨语言互锁失败）：{}",
        sig_hex
    );

    // ed25519::verify(pubkey, digest, sig) 闭环
    assert!(
        crate::ed25519::verify(&pubkey, &digest, &sig),
        "verify 闭环失败"
    );

    // 签名助手输出与向量一致
    let (p, s) = sign_attestation(&seed, A_NONCE, A_TOKEN, A_MEASUREMENT, A_TS).unwrap();
    assert_eq!(p, A_PUBKEY);
    assert_eq!(s, A_SIG);
}

#[test]
fn attestation_tampered_measurement_fails_verify() {
    let seed = crate::sha256::hex_decode(A_SEED).unwrap();
    let pubkey = crate::ed25519::public_key(&seed).unwrap();
    let sig = crate::sha256::hex_decode(A_SIG).unwrap();
    let good = attestation_digest(A_NONCE, A_TOKEN, A_MEASUREMENT, A_TS);
    assert!(crate::ed25519::verify(&pubkey, &good, &sig));

    // 篡改 measurement → 摘要变 → 原签名验签失败
    let tampered = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let bad = attestation_digest(A_NONCE, A_TOKEN, tampered, A_TS);
    assert!(
        !crate::ed25519::verify(&pubkey, &bad, &sig),
        "篡改 measurement 后验签竟通过"
    );
    // 换身份 / 换 nonce 重放 / 改 ts 同样必须失败（绑定维度）
    for (n, t, m, ts) in [
        (A_NONCE, "dev-token-2", A_MEASUREMENT, A_TS),
        ("ffffffffffffffffffffffffffffffff", A_TOKEN, A_MEASUREMENT, A_TS),
        (A_NONCE, A_TOKEN, A_MEASUREMENT, A_TS + 1),
    ] {
        let d = attestation_digest(n, t, m, ts);
        assert!(
            !crate::ed25519::verify(&pubkey, &d, &sig),
            "换身份/重放/改 ts 后验签竟通过"
        );
    }
}

#[test]
fn build_auth_response_keeps_three_fields_without_require_attest() {
    let base = r#"{"nonce":"n","mac":"m","token":"t"}"#;
    // 缺 require_attest：parse_json 宽松读取 → false，即使有 attestation 素材也
    // 必须回原三字段，逐字节与旧副端一致。
    let env = crate::parse_json(
        br#"{"type":"auth_challenge","payload":{"nonce":"n","ts":1700000000}}"#,
    )
    .unwrap();
    let require_attest = env
        .get("payload")
        .and_then(|p| p.get("require_attest"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(!require_attest, "缺失字段必须读作 false");
    let attest = if require_attest {
        Some(("pk", "sig", "meas"))
    } else {
        None
    };
    assert_eq!(build_auth_response("n", "m", "t", attest), base);

    // require_attest=true 时读得到 true，且六字段齐全、原三字段逐字保留在前
    let env2 =
        crate::parse_json(br#"{"payload":{"nonce":"n","require_attest":true}}"#).unwrap();
    let req2 = env2
        .get("payload")
        .and_then(|p| p.get("require_attest"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(req2);
    let six = build_auth_response("n", "m", "t", Some(("pk", "sig", "meas")));
    assert!(six.starts_with(r#"{"nonce":"n","mac":"m","token":"t""#));
    assert!(six.contains(r#""pubkey":"pk""#));
    assert!(six.contains(r#""attest_sig":"sig""#));
    assert!(six.contains(r#""measurement":"meas""#));
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
    fn verify_accepts_millisecond_ts() {
        // v0.4.18 回归：历史主端发毫秒级 envelope ts（单位错误），中枢原样转发；
        // 副端窗口判定按量级归一到秒后应放行。签名仍按原始毫秒 ts 计算
        // （与中枢 SignCommand 对原始 ts 签名口径一致）。
        let secret = "diagsecret";
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let payload = r#"{"device_id":"d1","session_id":"s1","operator":"admin"}"#;
        let sig = sign(secret, "m1", ts_ms, 1, payload, "nonce-ms");
        let frame = format!(
            r#"{{"ver":1,"msg_id":"m1","ts":{},"type":"rc_request","seq":1,"payload":{},"nonce":"nonce-ms","sig":"{}"}}"#,
            ts_ms, payload, sig
        );
        let env = crate::parse_json(frame.as_bytes()).unwrap();
        let guard = NonceGuard::new(16);
        assert!(matches!(verify_command(secret, &frame, &env, &guard), VerifyOutcome::Ok));
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
