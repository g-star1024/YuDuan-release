// 御端（YuDuan）终端统一管理平台 —— 生产副端（Rust 版，std-only）。
//
// 硬约束：本机无法访问网络，只能使用 Rust 标准库（std），无任何第三方依赖。
// 离线编译：rustc -O src/main.rs -o target/agent
// 单元测试：rustc --test src/main.rs -o /tmp/agent_test && /tmp/agent_test
//
// 模块划分（安全基座与 M4/M5 能力均为纯 std 实现）：
//   sha256.rs  SHA-256 / HMAC-SHA256 / base64 / 恒定时间比较（FIPS 180-4、RFC 4231 向量验证）
//   secure.rs  指令 HMAC 验签 + nonce 防重放 + 时间窗（铁律 4，与 Go 中枢规范串逐字节一致）
//   httpget.rs 极简 HTTP/1.1 GET（软件分发下载，Content-Length/chunked）
//   swdist.rs  M5 软件分发安装（macOS pkg/zip/dmg、Linux deb/rpm/sh、Windows msi/exe）
//   rc.rs      M4 远程控制（screencapture 采集 + CoreGraphics FFI 输入注入 + 合规远端提示）
//
// 传输：
//   ws://  直连 TCP（明文，仅限受信局域网/开发调试）
//   wss:// 经 openssl s_client 子进程管道代理做 TLS（std 无 TLS；见 WsClient::connect）
// 环境变量：
//   YUDUAN_HUB              中枢地址，默认 ws://127.0.0.1:8080/ws/agent（支持 wss://）
//   YUDUAN_HMAC_SECRET      指令验签密钥；为空 = 开发态放行（与 Go 中枢 YUDUAN_HMAC_SECRET 一致才启用）
//   YUDUAN_TLS_CAFILE       可选：wss 证书校验 CA（设置后启用严格校验；缺省接受自签名，限局域网）
//   YUDUAN_TLS_PIN          可选：wss 服务端证书 SPKI SHA-256 公钥固定（RFC 7469）；
//                             设置后仅信任该证书，不匹配则拒绝连接（生产推荐）
//   YUDUAN_CLIENT_CERT/KEY  可选：wss mTLS 客户端证书/私钥（PEM），用于中枢开启 mTLS 时鉴身
//   YUDUAN_SW_PUBKEY       可选：软件包验签受信公钥（hex）；缺省回退指令 payload 中的 signer
//   YUDUAN_AGENT_EXPECTED_SHA256  可选：副端自校验期望值；配合 YUDUAN_AGENT_ENFORCE_TAMPER=1 阻断篡改
//   YUDUAN_AGENT_ENFORCE_TAMPER   可选：1=防篡改关键失败阻断启动
//   YUDUAN_AGENT_ANTI_DEBUG       可选：1=启用反调试检测
//
// 控制面协议：JSON 信封（payload 为内嵌对象）——见 dev/proto/protocol.md 与 dev/internal/proto/proto.go。

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 单测用的**进程级互斥锁**。
///
/// 凡读写进程全局状态的单测（环境变量 `YUDUAN_RC_FPS` / `YUDUAN_ENCODER_LIB` /
/// `YUDUAN_STATE_FILE`，以及 rc.rs 的 `RC_FPS_QOS` / `RC_RTT_MS` 等 static 原子量）
/// **必须先取本锁**，否则 cargo test 并行执行时会互相踩踏，表现为偶发失败。
/// 历史事故：`rc_rtt_cap_applies_over_target_fps` 在满量并行下被相邻用例的
/// `handle_rc_qos` 改写 `RC_RTT_MS`，单独跑必过、全量跑偶发失败。
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

/// 取测试锁（锁中毒时直接接管，避免一个失败用例拖垮其余用例）。
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

mod agentstate;
mod discover;
mod ed25519;
mod httpget;
mod jpegenc;
mod rc;
mod rc_media;
mod secure;
mod sha256;
mod swdist;
mod tamper;
mod tls;
// Windows 原生资产采集（实机版见 src/win_asset.rs / src/win_net.rs）。
// 非 Windows 平台提供同名桩，保证三平台均可编译；调用点都在 cfg!(windows)
// 运行时分支内，桩永远不会被真实执行（仅编译期占位）。
#[cfg(windows)]
mod win_asset;
#[cfg(not(windows))]
mod win_asset {
    pub fn win_os_version() -> String { String::new() }
    pub fn win_cpu() -> String { String::new() }
    pub fn win_serial_no() -> String { String::new() }
    pub fn win_memory_gb_() -> i64 { 0 }
    pub fn win_disk_gb_() -> i64 { 0 }
}
#[cfg(windows)]
mod win_net;
#[cfg(not(windows))]
mod win_net {
    pub fn decode_console_bytes(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }
    pub fn win_ip_mac_pair() -> (String, String) { (String::new(), String::new()) }
    pub fn win_mac_addr() -> String { String::new() }
    pub fn win_outbound_ip() -> String { String::new() }
}

// ===================== 极简 JSON 解析（无 serde，纯 std） =====================

#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    // 对象用 Vec 保存以保持顺序并支持重复键（protocol 无重复键需求，仅取用）
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        if let Json::Obj(m) = self {
            for (k, v) in m {
                if k == key {
                    return Some(v);
                }
            }
        }
        None
    }
    fn as_str(&self) -> Option<&str> {
        if let Json::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Num(n) => Some(*n as i64),
            Json::Bool(b) => Some(if *b { 1 } else { 0 }),
            _ => None,
        }
    }
    fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(b: &'a [u8]) -> Self {
        Parser { b, i: 0 }
    }
    fn skip_ws(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }
    fn parse(&mut self) -> Result<Json, String> {
        self.skip_ws();
        self.parse_value()
    }
    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        if self.i >= self.b.len() {
            return Err("unexpected EOF".into());
        }
        match self.b[self.i] {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => Ok(Json::Str(self.parse_string()?)),
            b't' | b'f' => self.parse_bool(),
            b'n' => self.parse_null(),
            _ => self.parse_number(),
        }
    }
    fn parse_object(&mut self) -> Result<Json, String> {
        self.i += 1; // {
        let mut out = Vec::new();
        self.skip_ws();
        if self.i < self.b.len() && self.b[self.i] == b'}' {
            self.i += 1;
            return Ok(Json::Obj(out));
        }
        loop {
            self.skip_ws();
            if self.i >= self.b.len() || self.b[self.i] != b'"' {
                return Err("expected object key".into());
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.i >= self.b.len() || self.b[self.i] != b':' {
                return Err("expected ':'".into());
            }
            self.i += 1;
            let val = self.parse_value()?;
            out.push((key, val));
            self.skip_ws();
            if self.i >= self.b.len() {
                return Err("unterminated object".into());
            }
            match self.b[self.i] {
                b',' => {
                    self.i += 1;
                    continue;
                }
                b'}' => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected ',' or '}'".into()),
            }
        }
        Ok(Json::Obj(out))
    }
    fn parse_array(&mut self) -> Result<Json, String> {
        self.i += 1; // [
        let mut out = Vec::new();
        self.skip_ws();
        if self.i < self.b.len() && self.b[self.i] == b']' {
            self.i += 1;
            return Ok(Json::Arr(out));
        }
        loop {
            let val = self.parse_value()?;
            out.push(val);
            self.skip_ws();
            if self.i >= self.b.len() {
                return Err("unterminated array".into());
            }
            match self.b[self.i] {
                b',' => {
                    self.i += 1;
                    continue;
                }
                b']' => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected ',' or ']'".into()),
            }
        }
        Ok(Json::Arr(out))
    }
    fn parse_string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut s = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    if self.i >= self.b.len() {
                        return Err("bad escape".into());
                    }
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0c}'),
                        b'u' => {
                            if self.i + 4 > self.b.len() {
                                return Err("bad unicode escape".into());
                            }
                            let hex = &self.b[self.i..self.i + 4];
                            self.i += 4;
                            let mut v = 0u32;
                            for &d in hex {
                                let d = match d {
                                    b'0'..=b'9' => (d - b'0') as u32,
                                    b'a'..=b'f' => (d - b'a' + 10) as u32,
                                    b'A'..=b'F' => (d - b'A' + 10) as u32,
                                    _ => return Err("bad unicode hex".into()),
                                };
                                v = v * 16 + d;
                            }
                            if let Some(ch) = char::from_u32(v) {
                                s.push(ch);
                            }
                        }
                        _ => return Err("unknown escape".into()),
                    }
                }
                _ => {
                    // 直接把 UTF-8 字节序列按字符处理（简单做法：逐字节拼，遇到多字节自行合并）
                    if c < 0x80 {
                        s.push(c as char);
                    } else {
                        // 可能是多字节 UTF-8 首字节，回溯收集完整字符
                        let start = self.i - 1;
                        let extra = utf8_len(c) - 1;
                        if start + extra <= self.b.len() {
                            if let Ok(t) = std::str::from_utf8(&self.b[start..start + extra + 1]) {
                                s.push_str(t);
                                self.i = start + extra + 1;
                            }
                        }
                    }
                }
            }
        }
        Err("unterminated string".into())
    }
    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.i;
        let mut is_float = false;
        while self.i < self.b.len() {
            match self.b[self.i] {
                b'0'..=b'9' | b'-' | b'+' => self.i += 1,
                b'.' | b'e' | b'E' => {
                    is_float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let slice = &self.b[start..self.i];
        let st = String::from_utf8_lossy(slice).to_string();
        if let Ok(n) = st.parse::<f64>() {
            let _ = is_float;
            Ok(Json::Num(n))
        } else {
            Err("bad number".into())
        }
    }
    fn parse_bool(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Json::Bool(true))
        } else if self.b[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Json::Bool(false))
        } else {
            Err("bad bool".into())
        }
    }
    fn parse_null(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(b"null") {
            self.i += 4;
            Ok(Json::Null)
        } else {
            Err("bad null".into())
        }
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

pub fn parse_json(b: &[u8]) -> Result<Json, String> {
    let mut p = Parser::new(b);
    let v = p.parse()?;
    Ok(v)
}

// ===================== JSON 字符串转义（构建信封时用） =====================

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub fn json_string(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

// ===================== base64（握手 Key 用，标准表） =====================

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(B64[((n >> 6) & 63) as usize] as char);
        out.push(B64[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(B64[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

// ===================== 随机数（非密码学，仅用于掩码与 key / msg_id） =====================

pub struct Lcg {
    state: u64,
}

impl Lcg {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        Lcg {
            state: seed ^ 0x9E3779B97F4A7C15,
        }
    }
    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut buf = self.next_u64();
        let mut cnt = 0u64;
        for _ in 0..n {
            if cnt == 0 {
                buf = self.next_u64();
                cnt = 8;
            }
            out.push((buf & 0xff) as u8);
            buf >>= 8;
            cnt -= 1;
        }
        out
    }
}

// ===================== 资产采集（适配 macOS / Linux / Windows，纯 std） =====================

fn run_output(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| {
            let mut s = String::new();
            s.push_str(&String::from_utf8_lossy(&o.stdout));
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s
        })
        .unwrap_or_default()
}

/// run_output_gbk 读取以系统 ANSI 代码页编码输出的 Windows 命令（如中文版 ipconfig）。
/// 中文系统下 ipconfig 输出为 CP936(GBK)，用 UTF-8 解码会得到乱码，
/// 导致按值/标签解析全部失效。交由系统 MultiByteToWideChar 转换最稳妥。
fn run_output_gbk(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| {
            let mut s = String::new();
            #[cfg(windows)]
            {
                s.push_str(&crate::win_net::decode_console_bytes(&o.stdout));
                s.push_str(&crate::win_net::decode_console_bytes(&o.stderr));
            }
            #[cfg(not(windows))]
            {
                s.push_str(&String::from_utf8_lossy(&o.stdout));
                s.push_str(&String::from_utf8_lossy(&o.stderr));
            }
            s
        })
        .unwrap_or_default()
}

fn trim(s: &str) -> String {
    s.trim().to_string()
}

fn detect_os() -> String {
    if cfg!(target_os = "macos") {
        "macos".into()
    } else if cfg!(target_os = "windows") {
        "windows".into()
    } else if cfg!(target_os = "linux") {
        "linux".into()
    } else {
        std::env::consts::OS.to_string()
    }
}

fn hostname() -> String {
    if cfg!(windows) {
        // 中文 Windows 的 hostname 命令输出为系统 ANSI 代码页（CP936/GBK）字节，
        // 用 UTF-8 强解会得到乱码（如 "���ܲ�"），须走 CP_ACP 转换。
        trim(&run_output_gbk("hostname", &[]))
    } else {
        let h = trim(&run_output("hostname", &[]));
        if !h.is_empty() {
            h
        } else {
            trim(&run_output("uname", &["-n"]))
        }
    }
}

fn os_version() -> String {
    if cfg!(windows) {
        // Windows 无 uname；用注册表 Build 号判定（Win11 上 ProductName 恒为 Win10）
        return win_asset::win_os_version();
    }
    trim(&run_output("uname", &["-r"]))
}

fn arch() -> String {
    if cfg!(windows) {
        return match std::env::consts::ARCH {
            "x86_64" => "x86_64".to_string(),
            "aarch64" => "arm64".to_string(),
            other => other.to_string(),
        };
    }
    trim(&run_output("uname", &["-m"]))
}

fn cpu() -> String {
    if cfg!(target_os = "macos") {
        trim(&run_output("sysctl", &["-n", "machdep.cpu.brand_string"]))
    } else if cfg!(windows) {
        // Windows 11 已移除 wmic；原生注册表优先，wmic 仅作回退
        win_asset::win_cpu()
    } else {
        // Linux: /proc/cpuinfo 的 model name 首行
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in content.lines() {
                if line.starts_with("model name") {
                    if let Some(idx) = line.find(':') {
                        return trim(&line[idx + 1..]);
                    }
                }
            }
        }
        String::new()
    }
}

fn memory_gb() -> i64 {
    if cfg!(target_os = "macos") {
        let bytes = trim(&run_output("sysctl", &["-n", "hw.memsize"]))
            .parse::<f64>()
            .unwrap_or(0.0);
        (bytes / 1e9).round() as i64
    } else if cfg!(windows) {
        // Windows 11 已移除 wmic；原生 GlobalMemoryStatusEx 优先，wmic 仅作回退
        win_asset::win_memory_gb_()
    } else {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(idx) = line.find(':') {
                        let kb = trim(&line[idx + 1..]).replace("kB", "").trim().to_string();
                        if let Ok(k) = kb.parse::<f64>() {
                            return (k / 1048576.0).round() as i64;
                        }
                    }
                }
            }
        }
        0
    }
}

fn disk_gb() -> i64 {
    if cfg!(windows) {
        // Windows 11 已移除 wmic；原生 GetDiskFreeSpaceExW 优先，wmic 仅作回退
        return win_asset::win_disk_gb_();
    }
    {
        // df -k / -> 第二行第二列为 1K-blocks
        let out = run_output("df", &["-k", "/"]);
        if let Some(line) = out.lines().nth(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 2 {
                if let Ok(k) = cols[1].parse::<f64>() {
                    return (k / 1048576.0).round() as i64;
                }
            }
        }
        0
    }
}

// 解析 ifconfig / ip / ipconfig，取首个非回环 IPv4 与 MAC
fn net_info() -> (String, String) {
    let mut ip = String::new();
    let mut mac = String::new();
    let text = if cfg!(windows) {
        // 中文系统 ipconfig 输出为 CP936，用 GBK 路径读取
        run_output_gbk("ipconfig", &["/all"])
    } else if cfg!(target_os = "linux") {
        run_output("ip", &["addr"])
    } else {
        run_output("ifconfig", &[])
    };

    if cfg!(windows) {
        // 原生 Win32 路径优先：ipconfig 输出随系统语言本地化且为 GBK 编码，
        // 文本解析在中/英系统上不可靠（见 win_net.rs 注释）。
        // 优先取「同属一张网卡」的 IP+MAC 配对，避免 IP 与 MAC 来自不同适配器。
        let (pair_ip, pair_mac) = win_net::win_ip_mac_pair();
        let native_mac = if pair_mac.is_empty() {
            win_net::win_mac_addr()
        } else {
            pair_mac
        };
        let native_ip = if pair_ip.is_empty() {
            win_net::win_outbound_ip()
        } else {
            pair_ip
        };
        if !native_mac.is_empty() {
            mac = native_mac;
        }
        if !native_ip.is_empty() {
            ip = native_ip;
        }
        if !mac.is_empty() && !ip.is_empty() {
            return (ip, mac);
        }
        // 原生路径不完整时才回退 ipconfig 文本解析
    }

    if cfg!(windows) {
        // 简单扫描：IPv4 Address ... : x.x.x.x  /  Physical Address ... : xx-xx-...
        // 注意：仅在英文系统上有效（中文系统标签为「IPv4 地址」「物理地址」）。
        for line in text.lines() {
            let l = line.trim();
            if ip.is_empty() && l.contains("IPv4 Address") {
                if let Some(idx) = l.find(':') {
                    let v = trim(&l[idx + 1..]).trim_matches('(').trim_matches(')').to_string();
                    if v != "127.0.0.1" && v.contains('.') {
                        ip = v;
                    }
                }
            }
            if mac.is_empty() && l.contains("Physical Address") {
                if let Some(idx) = l.find(':') {
                    mac = trim(&l[idx + 1..]).replace('-', ":").to_uppercase();
                }
            }
        }
    } else {
        let mut in_loopback = false;
        for line in text.lines() {
            let l = line.trim();
            if cfg!(target_os = "linux") {
                if l.starts_with("lo:") || l.starts_with("1: lo:") {
                    in_loopback = true;
                    continue;
                }
                if l.starts_with(char::is_numeric) && !l.contains("lo:") && !l.contains("<LOOPBACK>") {
                    in_loopback = false;
                }
            } else {
                // mac ifconfig: 接口名单独一行，回环接口为 lo0
                if l.starts_with("lo0:") {
                    in_loopback = true;
                    continue;
                }
                if l.ends_with(":") && !l.starts_with("lo0") {
                    in_loopback = false;
                }
            }
            if in_loopback {
                continue;
            }
            if ip.is_empty() {
                if let Some(idx) = l.find("inet ") {
                    let rest = &l[idx + 5..];
                    let candidate = rest.split_whitespace().next().unwrap_or("").to_string();
                    if candidate != "127.0.0.1" && candidate.contains('.') {
                        ip = candidate;
                    }
                }
                // linux 可能写成 "inet 1.2.3.4/24"
                if ip.is_empty() {
                    if let Some(idx) = l.find("inet ") {
                        let rest = &l[idx + 5..];
                        let candidate = rest.split(|c| c == ' ' || c == '/').next().unwrap_or("").to_string();
                        if candidate != "127.0.0.1" && candidate.contains('.') {
                            ip = candidate;
                        }
                    }
                }
            }
            if mac.is_empty() {
                if let Some(idx) = l.find("ether ") {
                    mac = trim(&l[idx + 6..]).to_uppercase();
                } else if let Some(idx) = l.find("link/ether ") {
                    mac = trim(&l[idx + 10..]).to_uppercase();
                } else if let Some(idx) = l.find("HWaddr ") {
                    mac = trim(&l[idx + 7..]).to_uppercase();
                }
            }
        }
    }
    (ip, mac)
}

fn serial_no() -> String {
    if cfg!(target_os = "macos") {
        let out = run_output("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]);
        for line in out.lines() {
            if line.contains("IOPlatformSerialNumber") {
                if let Some(eq) = line.find('=') {
                    let rest = &line[eq + 1..];
                    if let Some(q) = rest.find('"') {
                        let after = &rest[q + 1..];
                        if let Some(end) = after.find('"') {
                            return after[..end].to_string();
                        }
                    }
                }
            }
        }
        String::new()
    } else if cfg!(windows) {
        // Windows 11 已移除 wmic；BIOS 序列号 → MachineGuid → wmic
        win_asset::win_serial_no()
    } else {
        // Linux: /sys/class/dmi/id/product_serial（需权限，尽力而为）
        std::fs::read_to_string("/sys/class/dmi/id/product_serial")
            .map(|s| trim(&s))
            .unwrap_or_default()
    }
}

#[derive(Clone)]
struct Assets {
    hostname: String,
    os: String,
    os_version: String,
    arch: String,
    cpu: String,
    memory_gb: i64,
    disk_gb: i64,
    serial_no: String,
    mac: String,
    ip: String,
    agent_version: String,
}

fn collect_assets() -> Assets {
    let (ip, mac) = net_info();
    let agent_version = "0.1.0-rust".to_string();
    Assets {
        hostname: hostname(),
        os: detect_os(),
        os_version: os_version(),
        arch: arch(),
        cpu: cpu(),
        memory_gb: memory_gb(),
        disk_gb: disk_gb(),
        serial_no: serial_no(),
        mac,
        ip: ip.clone(),
        agent_version,
    }
}

// ===================== WebSocket 客户端（ws:// 明文 / wss:// openssl 管道，std-only） =====================

/// 读侧：ws:// 为 TcpStream，wss:// 为 openssl s_client 的 stdout 管道。
type WsReader = BufReader<Box<dyn Read + Send>>;
/// 写侧：对应写入 TcpStream 或 openssl stdin 管道。
type WsWriter = Arc<Mutex<Box<dyn Write + Send>>>;

struct WsClient {
    reader: WsReader,
    writer: WsWriter,
    /// wss 模式下保活 openssl 子进程；WsClient  drop（会话结束/重连）时 kill，避免残留管道进程。
    tls_child: Option<Child>,
    /// pin 模式下临时 CAfile 路径；Drop 时删除，确保 openssl 子进程整个生命周期内文件存在
    /// （openssl 以 -CAfile 路径自行 fopen 读取，删除时机早于子进程读取会导致握手失败 / TOCTOU）。
    pin_ca: Option<String>,
}

impl Drop for WsClient {
    fn drop(&mut self) {
        if let Some(c) = &mut self.tls_child {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(p) = &self.pin_ca {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[derive(Debug)]
enum Frame {
    Text(Vec<u8>),
    Close,
}

impl WsClient {
    fn connect(url: &str) -> std::io::Result<WsClient> {
        // 解析 ws:// 或 wss://，取 authority 与 path
        let (rest, default_port, is_tls) = if let Some(r) = url.strip_prefix("wss://") {
            (r, 443u16, true)
        } else if let Some(r) = url.strip_prefix("ws://") {
            (r, 80u16, false)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "only ws:// or wss:// supported",
            ));
        };
        let (authority, path) = match rest.find('/') {
            Some(idx) => (rest[..idx].to_string(), rest[idx..].to_string()),
            None => (rest.to_string(), "/".to_string()),
        };
        let (sni_host, port) = match authority.find(':') {
            Some(i) => (
                authority[..i].to_string(),
                authority[i + 1..]
                    .parse::<u16>()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
            ),
            None => (authority.clone(), default_port),
        };
        let addr = format!("{}:{}", sni_host, port);

        // 传输层：ws:// 直连 TCP；wss:// 以 openssl s_client 子进程做 TLS 管道代理。
        // （std 无 TLS 实现；openssl 为系统常驻二进制，符合零第三方依赖约束。）
        // pin 模式临时 CAfile 路径：声明在 if/else 之外，连接成功后存入 WsClient，在 Drop 中删除。
        let mut pinned_ca: Option<String> = None;
        let (reader_box, mut writer_box, child): (Box<dyn Read + Send>, Box<dyn Write + Send>, Option<Child>) =
            if is_tls {
                // 证书固定（RFC 7469 SPKI 指纹）：YUDUAN_TLS_PIN 设置时，抓取并校验服务端证书，
                // 校验通过则把该证书作为临时 CAfile 供数据隧道严格信任（pin = 仅信任此证书，避免 TOCTOU）。
                if let Ok(pin) = std::env::var("YUDUAN_TLS_PIN") {
                    if !pin.trim().is_empty() {
                        match crate::tls::verify_server_pin(&addr, &sni_host, &pin) {
                            Some(pem) => match crate::tls::write_temp_ca(&pem) {
                                Some(p) => pinned_ca = Some(p),
                                None => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        "TLS 证书固定：无法写入临时 CA 文件",
                                    ))
                                }
                            },
                            None => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "TLS 证书固定校验失败：SPKI 不匹配或服务端证书不可达",
                                ))
                            }
                        }
                    }
                }

                let mut cmd = Command::new("openssl");
                cmd.arg("s_client")
                    .arg("-connect")
                    .arg(&addr)
                    .arg("-servername")
                    .arg(&sni_host)
                    .arg("-quiet")
                    .arg("-ign_eof"); // stdin EOF 不自动断开，由本进程生命周期管理
                // 优先使用固定证书（临时 CAfile）；其次若配置了 CA 文件则严格校验；
                // 二者皆无 = 缺省接受自签名（仅限受信局域网，生产应配置 CA 或固定指纹）。
                if let Some(ca) = &pinned_ca {
                    cmd.arg("-CAfile").arg(ca).arg("-verify_return_error");
                } else if let Ok(cafile) = std::env::var("YUDUAN_TLS_CAFILE") {
                    if !cafile.is_empty() {
                        cmd.arg("-CAfile").arg(&cafile).arg("-verify_return_error");
                    }
                }
                // mTLS 客户端证书（YUDUAN_CLIENT_CERT / YUDUAN_CLIENT_KEY）
                if let Ok(cert) = std::env::var("YUDUAN_CLIENT_CERT") {
                    if !cert.is_empty() {
                        cmd.arg("-cert").arg(&cert);
                    }
                }
                if let Ok(key) = std::env::var("YUDUAN_CLIENT_KEY") {
                    if !key.is_empty() {
                        cmd.arg("-key").arg(&key);
                    }
                }
                let mut c = cmd
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::inherit())
                    .spawn()
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("spawn openssl failed: {} (wss 需要系统 openssl)", e),
                        )
                    })?;
                // 注意：临时 CAfile 不能在 spawn 后立即删除——openssl 以 -CAfile 路径自行 fopen 读取，
                // 子进程启动后并不会继承该 fd，文件需在子进程整个生命周期内存在；删除交由 WsClient::Drop。
                let sin = c
                    .stdin
                    .take()
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "openssl stdin pipe"))?;
                let sout = c
                    .stdout
                    .take()
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "openssl stdout pipe"))?;
                (Box::new(sout), Box::new(sin), Some(c))
            } else {
                let stream = TcpStream::connect(&addr)?;
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)?;
                let w = stream.try_clone()?;
                (Box::new(stream), Box::new(w), None)
            };

        // 随机 Sec-WebSocket-Key = base64(16 字节)（握手用，非密码学即可）
        let key = base64_encode(&Lcg::new().bytes(16));

        let handshake = format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        // 先构造 WsClient（含 tls_child / pin_ca）：握手失败提前 return 时，
        // WsClient 离开作用域触发 Drop，统一清理 openssl 子进程与临时 CAfile（错误路径也不残留）。
        let mut ws = WsClient {
            reader: BufReader::new(reader_box),
            writer: Arc::new(Mutex::new(writer_box)),
            tls_child: child,
            pin_ca: pinned_ca,
        };

        {
            let mut w = ws.writer.lock().unwrap();
            w.write_all(handshake.as_bytes())?;
            w.flush()?;
        }

        // 读取 101 响应头直至空行
        let mut header = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = ws.reader.read(&mut byte)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during handshake",
                ));
            }
            header.push(byte[0]);
            if header.len() >= 4 && &header[header.len() - 4..] == b"\r\n\r\n" {
                break;
            }
        }
        let header_str = String::from_utf8_lossy(&header);
        if !header_str.contains("101") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("handshake failed: {}", header_str.lines().next().unwrap_or("")),
            ));
        }

        // 握手成功：openssl 子进程的 TLS 握手已在返回隧道数据前完成（已读取 -CAfile），
        // 此处即可安全删除临时 CAfile；即便后续被 SIGTERM 终止也不会残留（信号安全）。
        // 置空 pin_ca，Drop 再次删除时为空操作。
        if let Some(ca) = &ws.pin_ca {
            let _ = std::fs::remove_file(ca);
            ws.pin_ca = None;
        }

        Ok(ws)
    }

    // 发送掩码文本帧（客户端必须加掩码）
    fn send_text(&self, data: &[u8]) -> std::io::Result<()> {
        send_ws_text(&mut *self.writer.lock().unwrap(), data)
    }

    fn send_pong(&self, payload: &[u8]) -> std::io::Result<()> {
        let mut w = self.writer.lock().unwrap();
        let len = payload.len();
        let mask_bit = 0x80u8;
        let mut header = vec![0x8A, (len as u8) | mask_bit];
        let mask = Lcg::new().bytes(4);
        header.extend_from_slice(&mask);
        w.write_all(&header)?;
        let mut masked = Vec::with_capacity(len);
        for (i, &b) in payload.iter().enumerate() {
            masked.push(b ^ mask[i % 4]);
        }
        w.write_all(&masked)?;
        w.flush()?;
        Ok(())
    }

    // 读取一帧，自动处理 ping -> pong，close -> Close
    fn read_frame(&mut self) -> std::io::Result<Frame> {
        loop {
            let mut b0 = [0u8; 1];
            if self.reader.read_exact(&mut b0).is_err() {
                return Ok(Frame::Close);
            }
            let mut b1 = [0u8; 1];
            self.reader.read_exact(&mut b1)?;
            let opcode = b0[0] & 0x0f;
            let masked = (b1[0] & 0x80) != 0;
            let mut len = (b1[0] & 0x7f) as usize;
            if len == 126 {
                let mut ext = [0u8; 2];
                self.reader.read_exact(&mut ext)?;
                len = u16::from_be_bytes(ext) as usize;
            } else if len == 127 {
                let mut ext = [0u8; 8];
                self.reader.read_exact(&mut ext)?;
                len = u64::from_be_bytes(ext) as usize;
            }
            let mut mask = [0u8; 4];
            if masked {
                self.reader.read_exact(&mut mask)?;
            }
            let mut payload = vec![0u8; len];
            self.reader.read_exact(&mut payload)?;
            if masked {
                for i in 0..len {
                    payload[i] ^= mask[i % 4];
                }
            }
            match opcode {
                0x8 => return Ok(Frame::Close),
                0x9 => {
                    // ping -> pong
                    let _ = self.send_pong(&payload);
                    continue;
                }
                0xA => continue, // pong
                0x1 | 0x0 => return Ok(Frame::Text(payload)),
                _ => continue, // 未知 opcode 忽略
            }
        }
    }
}

// ===================== 信封构建 =====================

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn build_envelope(
    rng: &mut Lcg,
    seq: &mut u64,
    msg_type: &str,
    payload: &str,
) -> String {
    *seq += 1;
    let key = rng.bytes(9);
    let msg_id = format!("rust-{}", sha256::hex_encode(&key));
    format!(
        "{{\"ver\":1,\"msg_id\":{},\"ts\":{},\"type\":{},\"seq\":{},\"payload\":{},\"sig\":\"\"}}",
        json_string(&msg_id),
        now_secs(),
        json_string(msg_type),
        *seq,
        payload
    )
}

// ===================== 指令处理 =====================

fn handle_command(
    env: &Json,
    writer: WsWriter,
    rng: Arc<Mutex<Lcg>>,
    seq: Arc<Mutex<u64>>,
    _device_id: Arc<Mutex<String>>,
) {
    let payload = match env.get("payload") {
        Some(Json::Obj(_)) => env.get("payload").unwrap().clone(),
        _ => return,
    };
    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let task_id = payload.get("task_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let command = payload.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // 在子线程执行，避免阻塞读循环
    thread::spawn(move || {
        let (state, exit_code, output_log) = match action.as_str() {
            "shell" => run_shell(&command),
            "collect" => run_collect(),
            "sw_install" => {
                // M5 软件分发：下载安装包 → 哈希/签名校验 → 按平台静默安装（swdist.rs）
                let url = payload.get("software_url").and_then(|v| v.as_str()).unwrap_or("");
                let platform = payload.get("platform").and_then(|v| v.as_str()).unwrap_or("");
                let pkg = payload.get("pkg_name").and_then(|v| v.as_str()).unwrap_or("");
                // 验签参数：payload 优先，缺省回退到 YUDUAN_SW_PUBKEY（受信签名公钥）
                let env_pk = std::env::var("YUDUAN_SW_PUBKEY").unwrap_or_default();
                let pk_field = payload.get("signer").and_then(|v| v.as_str()).unwrap_or("");
                let v = swdist::PkgVerify {
                    sha256: payload.get("sha256").and_then(|v| v.as_str()).unwrap_or(""),
                    signature: payload.get("signature").and_then(|v| v.as_str()).unwrap_or(""),
                    pubkey: if pk_field.is_empty() { &env_pk } else { pk_field },
                };
                let o = swdist::handle_sw_install(url, platform, pkg, &v);
                (o.state, o.exit_code, o.output_log)
            }
            other => (
                "failed".to_string(),
                1,
                format!("rust agent: 未知 action={}", other),
            ),
        };

        let payload_obj = format!(
            "{{\"task_id\":{},\"state\":{},\"exit_code\":{},\"output_log\":{}}}",
            json_string(&task_id),
            json_string(&state),
            exit_code,
            json_string(&output_log)
        );
        let mut rng_g = rng.lock().unwrap();
        let mut seq_g = seq.lock().unwrap();
        let msg = build_envelope(&mut rng_g, &mut seq_g, "result", &payload_obj);
        drop(rng_g);
        drop(seq_g);
        if let Err(e) = send_ws_text(&mut *writer.lock().unwrap(), msg.as_bytes()) {
            eprintln!("[agent] 发送 result 失败: {}", e);
        } else {
            eprintln!("[agent] 已回 result task={} state={}", task_id, state);
        }
    });
}

// 发送一个掩码文本帧（客户端必须加掩码）。
// 写成自由函数而非 trait：写侧在 ws:// 下是 TcpStream、wss:// 下是 openssl stdin 管道，
// 经 Box<dyn Write + Send> 统一收敛，心跳 / 指令回执 / 远控帧线程共用同一出口。
// 掩码用本地 LCG：避免与心跳/指令线程的「先 rng 后 writer」加锁顺序形成环（防死锁）；
// 掩码值不影响安全性（仅防缓存污染），非密码学即可。
fn send_ws_text<W: Write + ?Sized>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    let len = data.len();
    let mut header = Vec::with_capacity(10);
    let mask_bit = 0x80u8;
    if len < 126 {
        header.push(0x81);
        header.push((len as u8) | mask_bit);
    } else if len <= 0xffff {
        header.push(0x81);
        header.push(126 | mask_bit);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(0x81);
        header.push(127 | mask_bit);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask = Lcg::new().bytes(4);
    header.extend_from_slice(&mask);
    w.write_all(&header)?;
    let mut masked = Vec::with_capacity(len);
    for (i, &b) in data.iter().enumerate() {
        masked.push(b ^ mask[i % 4]);
    }
    w.write_all(&masked)?;
    w.flush()?;
    Ok(())
}

// 发送一个掩码二进制帧（opcode 0x2）：远控二进制媒体帧（§8.3）经长连接中继时使用
// （P2P 直连走 TcpStream，不经此函数；中继兜底/浏览器主端场景经 ws/wss 透传）。
// 头部长度的 126/127 扩展分支与 send_ws_text 完全一致，仅 opcode 不同。
fn send_ws_binary<W: Write + ?Sized>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    let len = data.len();
    let mut header = Vec::with_capacity(10);
    let mask_bit = 0x80u8;
    if len < 126 {
        header.push(0x82);
        header.push((len as u8) | mask_bit);
    } else if len <= 0xffff {
        header.push(0x82);
        header.push(126 | mask_bit);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(0x82);
        header.push(127 | mask_bit);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask = Lcg::new().bytes(4);
    header.extend_from_slice(&mask);
    w.write_all(&header)?;
    let mut masked = Vec::with_capacity(len);
    for (i, &b) in data.iter().enumerate() {
        masked.push(b ^ mask[i % 4]);
    }
    w.write_all(&masked)?;
    w.flush()?;
    Ok(())
}

fn run_shell(command: &str) -> (String, i64, String) {
    let (shell, flag) = if cfg!(windows) {
        ("cmd", "/c")
    } else {
        ("sh", "-c")
    };
    let out = Command::new(shell)
        .arg(flag)
        .arg(command)
        .output();
    match out {
        Ok(o) => {
            let mut log = String::new();
            log.push_str(&String::from_utf8_lossy(&o.stdout));
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.is_empty() {
                if !log.is_empty() {
                    log.push('\n');
                }
                log.push_str(&err);
            }
            let code = o.status.code().unwrap_or(-1);
            (if code == 0 { "success" } else { "failed" }.to_string(), code as i64, log)
        }
        Err(e) => ("failed".to_string(), 127, format!("执行失败: {}", e)),
    }
}

fn run_collect() -> (String, i64, String) {
    let a = collect_assets();
    let log = format!(
        "re-collected: host={} os={} os_version={} arch={} cpu={} mem_gb={} disk_gb={} serial={} mac={} ip={} agent={}",
        a.hostname, a.os, a.os_version, a.arch, a.cpu, a.memory_gb, a.disk_gb, a.serial_no, a.mac, a.ip, a.agent_version
    );
    ("success".to_string(), 0, log)
}

// ===================== 主流程 =====================

fn build_register_payload(assets: &Assets, token: &str) -> String {
    format!(
        "{{\"hostname\":{},\"os\":{},\"os_version\":{},\"arch\":{},\"cpu\":{},\"memory_gb\":{},\"disk_gb\":{},\"serial_no\":{},\"mac\":{},\"ip\":{},\"agent_version\":{},\"token\":{}}}",
        json_string(&assets.hostname),
        json_string(&assets.os),
        json_string(&assets.os_version),
        json_string(&assets.arch),
        json_string(&assets.cpu),
        assets.memory_gb,
        assets.disk_gb,
        json_string(&assets.serial_no),
        json_string(&assets.mac),
        json_string(&assets.ip),
        json_string(&assets.agent_version),
        json_string(token)
    )
}

fn build_heartbeat(load: f64, ip: &str) -> String {
    format!("{{\"load\":{},\"ip\":{}}}", load, json_string(ip))
}

fn session(url: &str) -> std::io::Result<()> {
    // 安全基座：指令验签密钥（与 Go 中枢 YUDUAN_HMAC_SECRET 一致才启用；为空 = 开发态放行）
    let hmac_secret = std::env::var("YUDUAN_HMAC_SECRET").unwrap_or_default();
    let nonce_guard = Arc::new(secure::NonceGuard::new(8192));

    let rng = Arc::new(Mutex::new(Lcg::new()));
    let ws = WsClient::connect(url)?;
    eprintln!(
        "[agent] WebSocket 握手成功: {}（验签 {}）",
        url,
        if hmac_secret.is_empty() { "未启用（开发态）" } else { "已启用" }
    );

    // 共享状态
    let device_id: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let token: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let seq: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let registered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    // 设备身份持久化（Windows 实机验证报告建议项）：恢复上次注册的 token，
    // hub 按 token 复用设备身份——重启不再产生新设备条目。
    let (saved_did, saved_tok) = agentstate::load();
    if !saved_tok.is_empty() {
        *token.lock().unwrap() = saved_tok;
        eprintln!(
            "[agent] 已恢复本地设备身份 device_id={}（复用 token 注册；YUDUAN_STATE_FILE 可覆盖存储位置）",
            saved_did
        );
    }

    // 注册
    let assets = collect_assets();
    let reg_payload = {
        let t = token.lock().unwrap().clone();
        build_register_payload(&assets, &t)
    };
    {
        let mut rng_g = rng.lock().unwrap();
        let mut seq_g = seq.lock().unwrap();
        let msg = build_envelope(&mut rng_g, &mut seq_g, "register", &reg_payload);
        ws.send_text(msg.as_bytes())?;
        eprintln!("[agent] 已发送 register (host={}, os={}, arch={})", assets.hostname, assets.os, assets.arch);
    }

    // 心跳线程：每 30s 发送（注册成功后）
    {
        let writer = ws.writer.clone();
        let registered = registered.clone();
        let seq = seq.clone();
        let rng = rng.clone();
        let ip = assets.ip.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(30));
                if !*registered.lock().unwrap() {
                    continue;
                }
                let hb = build_heartbeat(0.0, &ip);
                let mut rng_g = rng.lock().unwrap();
                let mut seq_g = seq.lock().unwrap();
                let msg = build_envelope(&mut rng_g, &mut seq_g, "heartbeat", &hb);
                drop(rng_g);
                drop(seq_g);
                if let Err(e) = send_ws_text(&mut *writer.lock().unwrap(), msg.as_bytes()) {
                    eprintln!("[agent] 心跳发送失败: {}", e);
                    break;
                } else {
                    eprintln!("[agent] 心跳已发送 ip={}", ip);
                }
            }
        });
    }

    // 读循环
    let mut ws = ws;
    loop {
        let frame = ws.read_frame()?;
        match frame {
            Frame::Close => {
                eprintln!("[agent] 收到 close 帧，断开");
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "closed"));
            }
            Frame::Text(data) => {
                let parsed = parse_json(&data);
                let env = match parsed {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[agent] JSON 解析失败（忽略）: {}", e);
                        continue;
                    }
                };
                let msg_type = match env.get("type").and_then(|v| v.as_str()) {
                    Some(t) => t.to_string(),
                    None => continue,
                };

                // 铁律 4：远控指令（remote_control）与 command 同口径——HMAC 验签 +
                // nonce 防重放。此前仅 command 走门禁，rc_* 直通执行，意味着任何能连上
                // 副端或伪造中枢的一方都可无签名发起远控会话并注入键鼠。
                // 密钥未配置 = 开发态放行（NoSecret），行为与改造前一致。
                if secure::is_rc_control(&msg_type) {
                    let frame = String::from_utf8_lossy(&data).to_string();
                    if let outcome @ (secure::VerifyOutcome::BadSignature
                    | secure::VerifyOutcome::Replayed
                    | secure::VerifyOutcome::TimeSkew
                    | secure::VerifyOutcome::Malformed) =
                        secure::verify_command(&hmac_secret, &frame, &env, &nonce_guard)
                    {
                        let reason = match outcome {
                            secure::VerifyOutcome::BadSignature => "HMAC 验签失败",
                            secure::VerifyOutcome::Replayed => "nonce 重放被拒",
                            secure::VerifyOutcome::TimeSkew => "时间窗超限",
                            _ => "信封字段缺失/无法解析",
                        };
                        eprintln!("[agent] 拒绝执行远控指令 {}：{}", msg_type, reason);
                        // 回执 rc_event(kind=error)：主端可提示，而非静默失败
                        let sid = env
                            .get("payload")
                            .and_then(|p| p.get("session_id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let ev = format!(
                            "{{\"session_id\":{},\"kind\":\"error\",\"message\":{}}}",
                            json_string(&sid),
                            json_string(&format!("远控指令被拒（{}）", reason))
                        );
                        let msg = {
                            let mut rng_g = rng.lock().unwrap();
                            let mut seq_g = seq.lock().unwrap();
                            let m = build_envelope(&mut rng_g, &mut seq_g, "rc_event", &ev);
                            drop(rng_g);
                            drop(seq_g);
                            m
                        };
                        let _ = send_ws_text(&mut *ws.writer.lock().unwrap(), msg.as_bytes());
                        continue;
                    }
                }

                match msg_type.as_str() {
                    "register_ack" => {
                        if let Some(p) = env.get("payload") {
                            let did = p.get("device_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let tok = p.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let ok = p.get("ok").and_then(|v| v.as_bool().or_else(|| Some(true))).unwrap_or(true);
                            if !did.is_empty() {
                                *device_id.lock().unwrap() = did.clone();
                                *token.lock().unwrap() = tok.clone();
                                *registered.lock().unwrap() = true;
                                eprintln!("[agent] 注册成功 device_id={} token={} ok={}", did, tok, ok);
                                agentstate::save(&did, &tok); // 身份落盘，重启复用（不阻塞注册）
                            } else {
                                eprintln!("[agent] register_ack 缺少 device_id（忽略）");
                            }
                        }
                    }
                    "command" => {
                        let did = device_id.lock().unwrap().clone();
                        if did.is_empty() {
                            eprintln!("[agent] 收到 command 但尚未注册（忽略）");
                            continue;
                        }
                        // 安全基座：HMAC 验签 + nonce 防重放（与 Go 参考副端同语义：
                        // 密钥未配置 = 开发态放行；配置后验签失败/重放一律拒绝并回执 failed）
                        let frame = String::from_utf8_lossy(&data).to_string();
                        match secure::verify_command(&hmac_secret, &frame, &env, &nonce_guard) {
                            secure::VerifyOutcome::Ok | secure::VerifyOutcome::NoSecret => {}
                            outcome => {
                                let reason = match outcome {
                                    secure::VerifyOutcome::BadSignature => "HMAC 验签失败",
                                    secure::VerifyOutcome::Replayed => "nonce 重放被拒",
                                    secure::VerifyOutcome::TimeSkew => "时间窗超限",
                                    secure::VerifyOutcome::Malformed => "信封字段缺失/无法解析",
                                    _ => "验签失败",
                                };
                                eprintln!("[agent] 拒绝执行指令: {}", reason);
                                // 回执 failed（任务快速失败，不静默丢弃），与 Go 副端行为一致
                                let tid = env
                                    .get("payload")
                                    .and_then(|p| p.get("task_id"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let payload_obj = format!(
                                    "{{\"task_id\":{},\"state\":\"failed\",\"exit_code\":-1,\"output_log\":{}}}",
                                    json_string(&tid),
                                    json_string(&format!("rust agent: 指令被拒（{}）", reason))
                                );
                                let msg = {
                                    let mut rng_g = rng.lock().unwrap();
                                    let mut seq_g = seq.lock().unwrap();
                                    build_envelope(&mut rng_g, &mut seq_g, "result", &payload_obj)
                                };
                                if let Err(e) = send_ws_text(&mut *ws.writer.lock().unwrap(), msg.as_bytes()) {
                                    eprintln!("[agent] 发送拒绝回执失败: {}", e);
                                }
                                continue;
                            }
                        }
                        handle_command(
                            &env,
                            ws.writer.clone(),
                            rng.clone(),
                            seq.clone(),
                            device_id.clone(),
                        );
                    }
                    // M4 远控：请求会话（合规提示 + rc_ready + 帧循环）
                    "rc_request" => {
                        if let Some(p) = env.get("payload") {
                            let sid = p.get("session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let did = device_id.lock().unwrap().clone();
                            eprintln!("[agent] rc 请求 session={} device={}", sid, did);
                            rc::start_rc(ws.writer.clone(), rng.clone(), seq.clone(), sid, did);
                        }
                    }
                    // M4 远控：键鼠输入注入
                    "rc_input" => {
                        if let Some(p) = env.get("payload") {
                            let sid = p.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
                            rc::apply_input(&ws.writer.clone(), &rng, &seq, sid, p);
                        }
                    }
                    // M4 远控：结束会话（session_id 精确匹配，防旧会话残留指令误杀新会话）
                    "rc_stop" => {
                        let sid = env
                            .get("payload")
                            .and_then(|p| p.get("session_id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        eprintln!("[agent] rc 会话结束指令 session={}", if sid.is_empty() { "<空>" } else { &sid });
                        rc::handle_rc_stop(&sid);
                    }
                    // M4 远控（§8.3）：主端协商结果——建立 P2P 直连媒体通道（失败回退中枢二进制中继）
                    "rc_select" => {
                        if let Some(p) = env.get("payload") {
                            let sid = p.get("session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            rc::handle_rc_select(&ws.writer.clone(), &rng, &seq, &sid, p);
                        }
                    }
                    // M4 远控（§8.3 ICE-lite）：主端批量/增量上报 P2P 候选地址，逐个尝试直连升级
                    "rc_offer" => {
                        if let Some(p) = env.get("payload") {
                            rc::handle_rc_offer(&ws.writer.clone(), &rng, &seq, p);
                        }
                    }
                    "rc_candidate" => {
                        if let Some(p) = env.get("payload") {
                            rc::handle_rc_candidate(&ws.writer.clone(), &rng, &seq, p);
                        }
                    }
                    // 生产化（§8.3.9 带宽自适应闭环）：主端反馈目标帧率（解码/渲染实测或用户调节），
                    // 副端夹取后逐轮应用——会话中途升降立即生效。
                    "rc_qos" => {
                        if let Some(p) = env.get("payload") {
                            rc::handle_rc_qos(p);
                        }
                    }
                    // §8.3.11 传输级自适应：主端 RTT 探测，副端原样回显 t0
                    "rc_ping" => {
                        if let Some(p) = env.get("payload") {
                            rc::handle_rc_ping(&ws.writer.clone(), &rng, &seq, p);
                        }
                    }
                    _ => {
                        // 其它类型优雅忽略，不崩溃
                        eprintln!("[agent] 忽略未知/不相关消息类型: {}", msg_type);
                    }
                }
            }
        }
    }
}

fn main() {
    // Windows：先设 DPI-aware（必须在任何 GetSystemMetrics/SendInput 之前），
    // 否则开启显示缩放的机器上注入坐标与采集坐标系错位（点击落点偏移）。
    #[cfg(target_os = "windows")]
    rc::set_dpi_aware_windows();

    // 生产化加固：启动前防篡改自检（自校验 + 反调试 + 代码签名）。
    let reports = tamper::self_check();
    let (blocked, summary) = tamper::summarize(&reports);
    eprintln!("[agent] 防篡改自检：\n{}", summary);
    if blocked && tamper::enforce() {
        eprintln!(
            "[agent] 防篡改自检未通过且已启用强制阻断（YUDUAN_AGENT_ENFORCE_TAMPER=1），退出。",
        );
        std::process::exit(2);
    }

    // §8.4：中枢地址解析——显式配置优先；否则 UDP 自动发现并「安装即注册」：
    // 启动时持续重探（中枢可能比副端晚启动），不落到写死的兜底地址。
    let explicit_hub = std::env::var("YUDUAN_HUB")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let mut url = match explicit_hub.clone() {
        Some(u) => u,
        None => discover_or_wait(),
    };
    eprintln!("[agent] 御端 Rust 副端启动，目标中枢: {}", url);
    eprintln!(
        "[agent] 配置: 验签密钥={} (YUDUAN_HMAC_SECRET{})",
        if std::env::var("YUDUAN_HMAC_SECRET").map(|v| !v.is_empty()).unwrap_or(false) {
            "已配置"
        } else {
            "未配置（开发态放行）"
        },
        if url.starts_with("wss://") { "，TLS: openssl s_client 管道" } else { "" }
    );
    loop {
        match session(&url) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("[agent] 会话异常: {}，重连（带抖动退避，复用 token）", e);
            }
        }
        // 自动发现模式：重连前重新探测——中枢 IP 可能漂移（网段变更/换路由器/
        // DHCP 续租），探测到新地址即切换。显式配置 YUDUAN_HUB 时尊重现场配置。
        if explicit_hub.is_none() {
            if let Some(u) = discover::discover_ws(Duration::from_secs(3)) {
                if u != url {
                    eprintln!("[agent] 中枢地址已变化，切换: {} -> {}", url, u);
                    url = u;
                }
            }
        }
        // 重连退避 + 抖动（§：规模容量）：固定 5s 会在中枢重启/开机风暴时造成
        // 惊群——2000 台同一秒重试必然再撞 listen backlog（macOS 实测瞬时并发
        // 超 ~128 个握手就被 reset）。这里 3~9s 抖动 randomization 摊开峰值。
        thread::sleep(Duration::from_secs_f64(reconnect_delay_secs()));
    }
}

/// 自动发现中枢（§8.4）：持续广播重探直到找到——副端「安装即注册」，
/// 中枢比副端晚启动/DHCP 晚分配时也能等到，不落到写死的兜底地址。
fn discover_or_wait() -> String {
    loop {
        eprintln!(
            "[agent] UDP 广播自动发现中枢（255.255.255.255:{}，单轮 3s）…",
            discover::DISCOVERY_PORT
        );
        if let Some(u) = discover::discover_ws(Duration::from_secs(3)) {
            eprintln!("[agent] 已自动发现中枢: {}", u);
            return u;
        }
        eprintln!("[agent] 本轮未发现中枢，2s 后重探（中枢上线后将自动注册）…");
        thread::sleep(Duration::from_secs(2));
    }
}

/// 重连退避秒数：3s 基础 + 0~6s 抖动（微秒级熵取自系统时钟，无第三方依赖）。
fn reconnect_delay_secs() -> f64 {
    let base = std::env::var("YUDUAN_RECONNECT_BASE_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(3.0);
    let jitter = std::env::var("YUDUAN_RECONNECT_JITTER_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| *v >= 0.0)
        .unwrap_or(6.0);
    // 熵源说明：macOS 的 SystemTime 亚秒位并非纳秒级（低位常被量化），直接取
    // `subsec_nanos % 1000` 会拿到恒零的二进制低位。故先乘一个大质数做位混合，
    // 再取模——只要时钟有毫秒级以上变化，结果就会均匀铺开。
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    let frac = ((nanos.wrapping_mul(2654435761)) % 1_000_000) as f64 / 1_000_000.0;
    base + frac * jitter
}

#[cfg(test)]
mod stress_tests {
    use super::reconnect_delay_secs;

    #[test]
    fn reconnect_backoff_is_jittered_and_configurable() {
        // 固定退避会在大规模重连时惊群（实测 2000 台瞬时重连会撞 listen backlog），
        // 故退避必须落在一个区间内而非定值；区间由环境变量可配。
        std::env::remove_var("YUDUAN_RECONNECT_BASE_SECS");
        std::env::remove_var("YUDUAN_RECONNECT_JITTER_SECS");
        let mut vals = Vec::new();
        for _ in 0..8 {
            let d = reconnect_delay_secs();
            assert!(d >= 3.0 && d <= 9.0, "默认退避应落在 3~9s，实际 {}", d);
            vals.push(d);
            // 抖动取自系统时钟微秒位：取样间隔需大于时钟分辨率才能观察到变化
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        // 抖动必须真的变化（否则等于固定退避）
        assert!(
            vals.windows(2).any(|w| (w[0] - w[1]).abs() > 1e-9),
            "退避应有抖动"
        );

        std::env::set_var("YUDUAN_RECONNECT_BASE_SECS", "1");
        std::env::set_var("YUDUAN_RECONNECT_JITTER_SECS", "0");
        let mut ok = true;
        for _ in 0..5 {
            ok = ok && (reconnect_delay_secs() - 1.0).abs() < 1e-9;
        }
        assert!(ok, "抖动置 0 时应等于基础值");
        std::env::remove_var("YUDUAN_RECONNECT_BASE_SECS");
        std::env::remove_var("YUDUAN_RECONNECT_JITTER_SECS");
    }
}

/// Windows 实机资产采集冒烟测试（仅 Windows 生效）。
///
/// 覆盖 Win11 已移除 wmic 后的原生采集路径：注册表 / Win32 API / IP-MAC 配对。
/// 任一字段为空即视为采集失败（wmic 回退在 Win11 上必然拿不到数据，
/// 因此空值说明原生路径没生效）。
#[cfg(all(test, windows))]
mod windows_asset_tests {
    use super::collect_assets;

    #[test]
    fn collect_assets_fills_all_fields_on_windows() {
        let a = collect_assets();
        println!(
            "assets: host={} os={} os_version={} arch={} cpu={} mem_gb={} disk_gb={} serial={} mac={} ip={}",
            a.hostname, a.os, a.os_version, a.arch, a.cpu, a.memory_gb, a.disk_gb,
            a.serial_no, a.mac, a.ip
        );

        // 主机名：中文系统下 hostname 输出为 CP936，必须正确解码（不能是乱码）。
        assert!(!a.hostname.is_empty(), "hostname 为空");
        assert!(
            !a.hostname.chars().any(|c| c == '\u{FFFD}'),
            "hostname 含替换字符 U+FFFD，说明 CP936 解码失败：{}",
            a.hostname
        );

        assert_eq!(a.os, "windows", "os 判定错误：{}", a.os);
        assert!(!a.arch.is_empty(), "arch 为空");
        assert!(!a.os_version.is_empty(), "os_version 为空（注册表 CurrentBuildNumber 未读到）");
        assert!(!a.cpu.is_empty(), "cpu 为空（注册表 ProcessorNameString 未读到）");
        assert!(a.memory_gb > 0, "memory_gb 应 > 0，实际 {}", a.memory_gb);
        assert!(a.disk_gb > 0, "disk_gb 应 > 0，实际 {}", a.disk_gb);
        assert!(!a.serial_no.is_empty(), "serial_no 为空（注册表 SystemSerialNumber 未读到）");
        assert!(!a.ip.is_empty(), "ip 为空（ipconfig /all 解析失败）");
        assert!(!a.mac.is_empty(), "mac 为空（GetAdaptersAddresses 未读到）");
        // 格式为冒号分隔的 6 段大写十六进制（win_net.rs: parts.join(":")）
        assert_eq!(
            a.mac.split(':').count(),
            6,
            "mac 应为 6 段冒号分隔，实际：{}",
            a.mac
        );
        assert!(
            a.mac.split(':').all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())),
            "mac 段格式异常（应为 2 位十六进制）：{}",
            a.mac
        );
    }
}
