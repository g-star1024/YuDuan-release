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
// 中枢端点（v0.4.40 优先级，见 resolve_hub）：
//   1) agent-hub.json        --set-hub 写入的持久化端点（运维最新意图，优先级最高）
//   2) YUDUAN_HUB           环境变量 / 部署脚本注入（可能是陈旧快照）
//   3) UDP 自动发现          以上都没有时，启动时持续重探（无写死兜底地址）
//   --set-hub <url> 可在服务运行中热切换端点（无需重启服务进程），并写 agent-status.json
//   供 --status 观测端点 / 来源 / 最近错误。
// 环境变量：
//   YUDUAN_HUB              中枢地址（ws:// 或 wss://）；被 agent-hub.json 覆盖
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 副端版本标识。v0.4.10（实测报告问题 1）改为**构建期注入**：CI 以环境变量
/// YUDUAN_AGENT_VERSION 传入发布号（去 v 前缀），彻底杜绝「发版忘 bump 常量」
/// 的版本串回归（v0.4.8 实锤：包是 0.4.8、自报 0.4.7）。本地构建回落到下方默认值。
/// 上报中枢资产台账 agent_version 字段，多版本混跑时可定位实际副端版本。
pub const AGENT_VERSION: &str = match option_env!("YUDUAN_AGENT_VERSION") {
    Some(v) => v,
    None => "0.4.10",
};

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
mod config;
mod devicekey;
mod discover;
mod dpapi;
mod ed25519;
mod httpget;
mod jpegenc;
mod locks;
mod rc;
mod rc_media;
mod rc_wave2;
mod secure;
mod sha256;
mod swdist;
mod swinv;
mod tamper;
mod tls;
// 波次 3/4/5：与 Go 参考副端同构的业务指令（铁律 2/9：三端同一套 action 与语义）。
mod wave3;
mod wave4;
mod wave5a;
mod wave5b;
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
// Windows 服务控制管理器（SCM）集成：被 SCM 拉起时完成 StartServiceCtrlDispatcherW
// 握手，使副端成为真正的系统服务（开机自启 + 失败自动重启 = 断联/崩溃守卫）。
// 非 Windows 平台提供同名桩，调用点都在 cfg!(windows) 运行时分支内，桩永不执行。
#[cfg(windows)]
mod win_service;
#[cfg(not(windows))]
mod win_service {
    use std::time::Duration;

    pub fn run_service(_name: &str, f: Box<dyn FnOnce() + Send>) -> bool {
        // 非 Windows 无 SCM：直接以普通进程身份执行闭包
        f();
        false
    }
    pub fn stop_requested() -> bool { false }
    pub fn is_service_mode() -> bool { false }
    pub fn sleep(d: Duration) { std::thread::sleep(d) }
    pub fn install(_name: &str, _display: &str, _bin: &str) -> Result<(), String> {
        Err("仅 Windows 支持系统服务安装".into())
    }
    pub fn uninstall(_name: &str) -> Result<(), String> {
        Err("仅 Windows 支持系统服务卸载".into())
    }
    pub fn status(_name: &str) -> Result<String, String> {
        // v0.4.40：无 SCM，但仍展示状态文件（端点/来源/最近错误），--status 不空手而归。
        Ok(crate::config::format_agent_status())
    }
    /// 非 Windows 无 SCM 服务；--set-hub 直接落盘，靠主循环每轮重读文件生效（轮询兜底）。
    pub fn notify_hub_changed(_name: &str) -> Result<(), String> { Ok(()) }
    pub fn is_installed(_name: &str) -> bool { false }
    pub fn start(_name: &str) -> Result<(), String> {
        Err("仅 Windows 支持服务启动".into())
    }
}

// 一键自安装（Windows）：双击 exe 即完成「清旧配置→装服务→启动」全流程；
// 非 Windows 提供同名桩（macOS/Linux 以 launchd/systemd 模板部署）。
#[cfg(windows)]
mod setup;
#[cfg(not(windows))]
mod setup {
    pub fn ensure_installed(_name: &str, _display: &str) -> Result<bool, String> {
        Err("仅 Windows 支持一键安装".into())
    }
}

// ===================== Windows 控制台 UTF-8（交互安装链路 best-effort） =====================
//
// PS 5.1 在 `$ErrorActionPreference='Stop'` 下会把原生命令写往 stderr 的输出包装成
// NativeCommandError / terminating error——这是实测报告里 `--setup` 报错的根因。交互
// 安装链路的中文提示统一改走 stdout（见 main 各管理分支），并临时把控制台代码页切到
// CP_UTF8(65001)，避免中文 Windows 默认 GBK 代码页下 stdout 中文乱码。
//
// 仅「CLI 管理 / 双击交互」链路使用；服务运行时（run_service / run_agent_loop 及其
// 之前的所有运行时日志）不碰控制台、保持 stderr 不动。无控制台 / 服务上下文时
// SetConsoleOutputCP 返回 0 属正常，忽略返回值，不报错、不 panic。

#[cfg(windows)]
const CP_UTF8: u32 = 65001;

// 铁律：新增 extern "system" 块必须显式 #[link]，否则只在 MSVC 链接阶段才暴露缺失符号。
#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetConsoleOutputCP() -> u32;
    fn SetConsoleOutputCP(cp: u32) -> i32;
}

/// 切换控制台到 UTF-8，返回原代码页供恢复。无控制台时 FFI 返回 0，原样回传。
#[cfg(windows)]
fn set_console_utf8() -> u32 {
    let old = unsafe { GetConsoleOutputCP() };
    let _ = unsafe { SetConsoleOutputCP(CP_UTF8) }; // 返回 0 属正常，忽略
    old
}

/// 恢复控制台代码页。old==0（无控制台 / 设置未生效）为 no-op。
#[cfg(windows)]
fn restore_console_cp(old: u32) {
    if old != 0 {
        let _ = unsafe { SetConsoleOutputCP(old) };
    }
}

// 非 Windows：同名 no-op 桩，保证 `rustc -O src/main.rs` 在 macOS/Linux 编译单元
// 完全不解析 Windows FFI 符号（extern 块与 CP_UTF8 均被 cfg(windows) 排除）。
#[cfg(not(windows))]
fn set_console_utf8() -> u32 {
    0
}
#[cfg(not(windows))]
fn restore_console_cp(_old: u32) {}

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
    // v0.4.7（实测报告问题 7）：agent_version 与发布号对齐——此前固定 0.1.0-rust，
    // 多版本混跑时中枢台账无法区分实际副端版本。每次发版随本常量同步更新。
    let agent_version = AGENT_VERSION.to_string();
    // v0.4.8：测试/容器环境身份覆盖（YUDUAN_HOSTNAME / YUDUAN_MAC / YUDUAN_SERIAL），
    // 与 Go 参考副端同构——幂等注册按硬件身份复用设备，e2e 模拟多台设备必须能伪造身份。
    let hostname = std::env::var("YUDUAN_HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(hostname);
    let mac = std::env::var("YUDUAN_MAC")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or(mac);
    let serial_no = std::env::var("YUDUAN_SERIAL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(serial_no);
    Assets {
        hostname,
        os: detect_os(),
        os_version: os_version(),
        arch: arch(),
        cpu: cpu(),
        memory_gb: memory_gb(),
        disk_gb: disk_gb(),
        serial_no,
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

// ===================== v0.4.40：端点热切换中断（--set-hub / SCM 自定义控制） =====================
//
// 难点：在线 WS 会话的读循环阻塞在 read_frame()（ws:// 的 TcpStream 设了
// set_read_timeout(None)，wss:// 读的是 openssl 子进程 stdout 管道），没有入站帧时
// 永不返回——仅靠「主循环每轮重读文件」无法打断一个正在跑的在线会话，这正是
// --set-hub 必须绕开「等下一次自然重连」的根因。
//
// 方案（双保险）：
//   1) SCM 自定义控制码（--set-hub 写完文件后 ControlService 触发）→ 控制处理器
//      置 RELOAD_HUB 并调用 interrupt_active_session()，强制关闭当前活跃会话的
//      底层 socket / openssl 子进程，使 read_frame() 立即返回 Frame::Close，
//      session() 返回，主循环随即重新解析端点并用新地址重连。
//   2) 控制码失败（权限 / 旧服务 / 非服务前台模式）时，主循环每轮重连都重读
//      agent-hub.json，最迟下一次自然重连（3~9s + 退避）生效（文件轮询兜底）。

/// SCM 控制处理器（win_service::handle_ex）置位：请求立即重新解析中枢端点。
/// main 主循环 / session 读循环读取；win_service::sleep 也据此提前结束退避。
static RELOAD_HUB: AtomicBool = AtomicBool::new(false);

/// 活跃会话的可中断句柄。SCM 控制处理器线程与会话线程共享：
/// - ws://  直连：持有 TcpStream 克隆，shutdown(Both) 令 read_exact 立即返回 EOF；
/// - wss:// 管道：持有 openssl 子进程 Arc<Mutex<Child>>，kill 令 stdout 管道 EOF。
enum ActiveInterrupt {
    Tcp(TcpStream),
    Tls(Arc<Mutex<Child>>),
}
static ACTIVE_INTERRUPT: Mutex<Option<ActiveInterrupt>> = Mutex::new(None);

fn set_active_interrupt(h: ActiveInterrupt) {
    *ACTIVE_INTERRUPT.lock().unwrap_or_else(|p| p.into_inner()) = Some(h);
}
fn clear_active_interrupt() {
    *ACTIVE_INTERRUPT.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// 强制断开当前活跃 WS 会话（若有）。控制处理器在 STOP / 重载中枢时调用，
/// 令阻塞在 read_frame() 的会话立即返回，进程 / 主循环可继续推进。
#[allow(dead_code)] // 非 Windows 无 SCM 控制处理器，此函数仅在 Windows 服务路径被调用
pub(crate) fn interrupt_active_session() {
    let h = ACTIVE_INTERRUPT
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take();
    match h {
        Some(ActiveInterrupt::Tcp(s)) => {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        Some(ActiveInterrupt::Tls(c)) => {
            if let Ok(mut ch) = c.lock() {
                let _ = ch.kill();
            }
        }
        None => {}
    }
}

/// --set-hub 的 SCM 控制码处理器调用：置重载标志 + 立即打断在线会话。
#[allow(dead_code)] // 仅 Windows 服务控制处理器调用；非 Windows 无 SCM，保留供交叉编译
pub(crate) fn request_hub_reload() {
    RELOAD_HUB.store(true, Ordering::SeqCst);
    interrupt_active_session();
}

struct WsClient {
    reader: WsReader,
    writer: WsWriter,
    /// wss 模式下保活 openssl 子进程；WsClient drop（会话结束/重连）时 kill，避免残留管道进程。
    /// v0.4.40 改为 Arc<Mutex<Child>>：与控制处理器共享，使 --set-hub / STOP 能从 SCM
    /// 线程 kill 子进程、关闭 stdout 管道，从而打断阻塞在 read_frame() 的在线会话。
    tls_child: Option<Arc<Mutex<Child>>>,
    /// pin 模式下临时 CAfile 路径；Drop 时删除，确保 openssl 子进程整个生命周期内文件存在
    /// （openssl 以 -CAfile 路径自行 fopen 读取，删除时机早于子进程读取会导致握手失败 / TOCTOU）。
    pin_ca: Option<String>,
}

impl Drop for WsClient {
    fn drop(&mut self) {
        if let Some(c) = &self.tls_child {
            if let Ok(mut ch) = c.lock() {
                let _ = ch.kill();
                let _ = ch.wait();
            }
        }
        if let Some(p) = &self.pin_ca {
            let _ = std::fs::remove_file(p);
        }
        // 会话结束：清掉全局中断句柄（连接失败路径也由此兜底，不留陈旧 socket/子进程）。
        clear_active_interrupt();
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
        // v0.4.40：child 改为 Arc<Mutex<Child>>，同一句柄同时交给 WsClient 生命周期管理
        // 与全局中断注册表（SCM 控制线程可 kill 子进程打断 wss 在线会话的阻塞读）。
        let (reader_box, mut writer_box, child): (
            Box<dyn Read + Send>,
            Box<dyn Write + Send>,
            Option<Arc<Mutex<Child>>>,
        ) = if is_tls {
                // v0.4.25：CAFILE 与 PIN 为 **AND 叠加**（都配则 PIN 带外比对 + 客户 CAFILE 作
                // 信任锚），由 tls.rs 统一规划；claim https 引导通道复用同一套逻辑，杜绝两条通道
                // 的参数漂移。两者皆未配置时 plan=None → 不加任何严格校验参数，与 v0.4.24 逐字节一致。
                let verify_plan = crate::tls::plan_verify(&addr, &sni_host).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                })?;
                if let Some(p) = &verify_plan {
                    if let Some(tmp) = &p.temp_ca {
                        // 仅 PIN 单轨的历史自签兼容路径：临时 CAfile 交给 WsClient::Drop 清理
                        pinned_ca = Some(tmp.clone());
                    }
                }

                let mut cmd = Command::new(crate::tls::openssl_bin());
                cmd.arg("s_client")
                    .arg("-connect")
                    .arg(&addr)
                    .arg("-servername")
                    .arg(&sni_host)
                    .arg("-quiet")
                    .arg("-ign_eof"); // stdin EOF 不自动断开，由本进程生命周期管理
                // 严格校验：仅当显式 CAFILE/PIN 存在才追加 -CAfile + -verify_return_error；
                // 缺省 = 接受自签名（受信局域网信任模型，生产应显式配置信任锚）。
                crate::tls::apply_verify_args(&mut cmd, verify_plan.as_ref());
                // mTLS 客户端证书（YUDUAN_CLIENT_CERT / YUDUAN_CLIENT_KEY）
                crate::tls::apply_client_cert_args(&mut cmd);
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
                // v0.4.40：登记可中断句柄（kill 子进程 → stdout 管道 EOF → read_frame 返回）。
                let shared = Arc::new(Mutex::new(c));
                set_active_interrupt(ActiveInterrupt::Tls(shared.clone()));
                (Box::new(sout), Box::new(sin), Some(shared))
            } else {
                let stream = TcpStream::connect(&addr)?;
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)?;
                let w = stream.try_clone()?;
                // v0.4.40：登记 socket 克隆（shutdown(Both) 令阻塞 read_exact 返回 EOF）。
                let interrupt = stream.try_clone()?;
                set_active_interrupt(ActiveInterrupt::Tcp(interrupt));
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
            let mut w = ws.writer.lock().unwrap_or_else(|p| p.into_inner());
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
        send_ws_text(&mut *self.writer.lock().unwrap_or_else(|p| p.into_inner()), data)
    }

    fn send_pong(&self, payload: &[u8]) -> std::io::Result<()> {
        let mut w = self.writer.lock().unwrap_or_else(|p| p.into_inner());
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

pub(crate) fn build_envelope(
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
            // ---- 波次 3：软件分发升级（W3-2 分发安装 / W3-3 差异升级）----
            // 载荷扩展参数承载在 command 字段（SwDistDetail JSON），与 Go 副端同构。
            "sw_dist" => wave3::handle_sw_dist(&payload, &command),
            // ---- 波次 4：后台文件分发与采集（file.* 六指令）----
            a if a.starts_with("file.") => wave4::handle(a, &command),
            // ---- 波次 5a：合规采集 / 卸载 / 补丁 ----
            "compliance_collect" | "sw_uninstall" | "patch_apply" => wave5a::handle(action.as_str(), &command),
            // ---- 波次 5b：外设管控 / 网络准入 ----
            "peripheral_apply" | "nac_apply" => wave5b::handle(action.as_str(), &command),
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
        let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
        let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
        let msg = build_envelope(&mut rng_g, &mut seq_g, "result", &payload_obj);
        drop(rng_g);
        drop(seq_g);
        if let Err(e) = send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes()) {
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
pub(crate) fn send_ws_text<W: Write + ?Sized>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
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
    // W1-1 软件资产清单：与 Go 参考副端同构上报（黑名单/漏洞/版本比对的共同上游）。
    let software = swinv::to_json_array(&swinv::software());
    // v0.4.31 §9.2：仅当本地设备密钥就绪时追加 agent_pubkey（omitempty 语义：
    // 密钥不可用则完全不带该字段，旧副端 / 旧中枢逐字节不受影响）。
    let agent_pubkey = devicekey::public_key_hex()
        .map(|pk| format!(",\"agent_pubkey\":{}", json_string(&pk)))
        .unwrap_or_default();
    // v0.4.10（实测报告问题 4）："id" = 硬件指纹稳定设备 ID（Go/Rust 同构，hub 采纳防漂移）。
    format!(
        "{{\"hostname\":{},\"os\":{},\"os_version\":{},\"arch\":{},\"cpu\":{},\"memory_gb\":{},\"disk_gb\":{},\"serial_no\":{},\"mac\":{},\"ip\":{},\"agent_version\":{},\"token\":{},\"id\":{},\"software\":{}{}}}",
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
        json_string(token),
        json_string(&stable_device_id(assets)),
        software,
        agent_pubkey
    )
}

/// 硬件指纹稳定设备 ID（v0.4.10，实测报告问题 4）：与 Go 副端 collect.StableDeviceID
/// **同构**——规范串 "yuduan-device|serial|mac|hostname"（trim+小写归一）取 SHA-256
/// 前 16 hex。同一台机器无论 hub 台账是否被清空，上报 ID 恒定。规范串改动必须
/// Go/Rust/e2e 三方同步。
fn stable_device_id(a: &Assets) -> String {
    let norm = |s: &str| s.trim().to_lowercase();
    let canonical = format!(
        "yuduan-device|{}|{}|{}",
        norm(&a.serial_no),
        norm(&a.mac),
        norm(&a.hostname)
    );
    let hex = crate::sha256::hex_encode(&crate::sha256::sha256(canonical.as_bytes()));
    hex[..16].to_string()
}

fn build_heartbeat(load: f64, ip: &str) -> String {
    format!("{{\"load\":{},\"ip\":{}}}", load, json_string(ip))
}

// v0.4.20 密钥轮换自愈状态（进程级）：本轮会话是否应答过注册挑战 / 注册成功，
// 以及连续「已应答挑战但未注册成功」的轮数——连续 3 轮即判定本地密钥与中枢
// 不配对（典型：中枢重装 / -ResetConfig 轮换密钥），自动清落盘密钥重新 claim。
// 判据说明：中枢对未握手 register 一律 nack「unauthenticated」（正常流程不算拒），
// 真正的凭据拒绝特征 = 已应答挑战后被中枢断开（MAC 不匹配）或 token 绑定不符。
static SESS_ANSWERED_CHALLENGE: AtomicBool = AtomicBool::new(false);
static SESS_REGISTERED: AtomicBool = AtomicBool::new(false);
static AUTH_REJECT_STREAK: AtomicUsize = AtomicUsize::new(0);

fn session(url: &str) -> std::io::Result<()> {
    SESS_ANSWERED_CHALLENGE.store(false, Ordering::SeqCst);
    SESS_REGISTERED.store(false, Ordering::SeqCst);
    // 安全基座：指令验签密钥（与 Go 中枢 YUDUAN_HMAC_SECRET 一致才启用；为空 = 开发态放行）。
    // 来源优先级：引导落盘配置（档位 A，claim 自动获取并 DPAPI 加密持久化）→ 环境变量。
    let hmac_secret = config::effective_hmac_secret();
    let nonce_guard = Arc::new(secure::NonceGuard::new(8192));

    let rng = Arc::new(Mutex::new(Lcg::new()));
    let ws = WsClient::connect(url)?;
    eprintln!(
        "[agent] WebSocket 握手成功: {}（验签 {}）",
        url,
        if hmac_secret.is_empty() { "未启用（开发态）" } else { "已启用" }
    );
    // v0.4.40：握手成功 → 状态文件标记「已连接」并清空最近错误（供 --status 观测）。
    config::status_note_connected();

    // 共享状态
    let device_id: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let token: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let seq: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let registered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    // 设备身份持久化（Windows 实机验证报告建议项）：恢复上次注册的 token，
    // hub 按 token 复用设备身份——重启不再产生新设备条目。
    let (saved_did, saved_tok) = agentstate::load();
    if !saved_tok.is_empty() {
        *token.lock().unwrap_or_else(|p| p.into_inner()) = saved_tok;
        eprintln!(
            "[agent] 已恢复本地设备身份 device_id={}（复用 token 注册；YUDUAN_STATE_FILE 可覆盖存储位置）",
            saved_did
        );
    }

    // 注册
    let assets = collect_assets();
    let reg_payload = {
        let t = token.lock().unwrap_or_else(|p| p.into_inner()).clone();
        build_register_payload(&assets, &t)
    };
    {
        let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
        let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
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
                if !*registered.lock().unwrap_or_else(|p| p.into_inner()) {
                    continue;
                }
                let hb = build_heartbeat(0.0, &ip);
                let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
                let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
                let msg = build_envelope(&mut rng_g, &mut seq_g, "heartbeat", &hb);
                drop(rng_g);
                drop(seq_g);
                if let Err(e) = send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes()) {
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
        // v0.4.40 中断点：--set-hub 的 SCM 控制码置 RELOAD_HUB、STOP 置 win_service::STOP，
        // 两者都要求尽快结束当前会话，让主循环重新解析端点 / 干净退出。
        // 控制处理器同时会强制关闭底层 socket / openssl 子进程，故即便此刻已阻塞在
        // 下面的 read_frame()（无入站帧时永不返回），也会被 EOF 打断返回 Frame::Close。
        // 两路合起来保证「在线会话可被中断」。
        if RELOAD_HUB.load(Ordering::SeqCst) || win_service::stop_requested() {
            eprintln!("[agent] 收到端点重载 / 服务停止信号，结束当前会话");
            return Ok(());
        }
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
                            let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
                            let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
                            let m = build_envelope(&mut rng_g, &mut seq_g, "rc_event", &ev);
                            drop(rng_g);
                            drop(seq_g);
                            m
                        };
                        let _ = send_ws_text(&mut *ws.writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes());
                        continue;
                    }
                }

                match msg_type.as_str() {
                    // §9.1 注册凭据握手：中枢在连接建立后即下发随机挑战，副端须以共享
                    // 密钥自证后方可纳管。未实现本握手的客户端会被拒绝注册——这是 S-3
                    // 「任意内网主机可零成本注册假设备 / 顶替他人设备」的修复面。
                    // 顺序无关：本轮次在直发 register 之后也能补做握手，完成后重发 register。
                    "auth_challenge" => {
                        let ch_token = token.lock().unwrap_or_else(|p| p.into_inner()).clone();
                        let nonce = env
                            .get("payload")
                            .and_then(|p| p.get("nonce"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if nonce.is_empty() {
                            eprintln!("[agent] auth_challenge 缺少 nonce（忽略）");
                            continue;
                        }
                        let mac = secure::register_auth_mac(&hmac_secret, &nonce, &ch_token);
                        if hmac_secret.is_empty() {
                            eprintln!(
                                "[agent] 警告：未配置 HMAC 密钥，注册凭据以空密钥计算，任何人可伪造（仅本机开发可用）"
                            );
                        }
                        // §9.2 设备证明：默认关闭。仅当中枢显式 require_attest=true
                        // 且本地设备密钥、二进制度量、挑战 ts 都就绪时才附加；否则 resp
                        // 与旧副端逐字节一致（原三字段）。计算只在握手期一次性发生，
                        // 绝不进心跳路径（build_heartbeat / 心跳线程未改）。
                        // ts 的**唯一来源** = 中枢下发的 auth_challenge.ts（unix 秒原值）：
                        // 绝不用 now_secs() 现取本地时间签名；副端不做 ±300s 归一/窗口判定
                        // （由中枢接线时对 challenge.TS 旁路做），不改写 ts 值，规范串用
                        // 原始整数。nonce 取 challenge.nonce 原样，token 取本应答声明的
                        // ch_token，measurement 取 tamper::self_sha256() 的小写 hex。
                        let require_attest = env
                            .get("payload")
                            .and_then(|p| p.get("require_attest"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false); // 宽松读取可选字段，缺失即 false
                        let ch_ts = env
                            .get("payload")
                            .and_then(|p| p.get("ts"))
                            .and_then(|v| v.as_i64()); // 挑战下发 ts；缺失则不启用 attestation
                        let attest: Option<(String, String, String)> = if require_attest {
                            match ch_ts {
                                None => {
                                    eprintln!("[agent] 挑战缺少 ts，跳过设备证明（仍回旧三字段；绝不用本地时间签名）");
                                    None
                                }
                                Some(ts) => match (devicekey::load(), tamper::self_sha256()) {
                                    (Some(dk), Some(measurement)) => secure::sign_attestation(
                                        &dk.seed, &nonce, &ch_token, &measurement, ts,
                                    )
                                    .map(|(pubkey, sig)| (pubkey, sig, measurement)),
                                    _ => {
                                        eprintln!("[agent] 设备密钥或二进制度量不可用，跳过设备证明（仍回旧三字段）");
                                        None
                                    }
                                },
                            }
                        } else {
                            None
                        };
                        if attest.is_some() {
                            eprintln!("[agent] 已附带设备证明（require_attest=true，握手期一次性）");
                        }
                        let resp = secure::build_auth_response(
                            &nonce,
                            &mac,
                            &ch_token,
                            attest
                                .as_ref()
                                .map(|(p, s, m)| (p.as_str(), s.as_str(), m.as_str())),
                        );
                        {
                            let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
                            let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
                            let msg = build_envelope(&mut rng_g, &mut seq_g, "auth_response", &resp);
                            drop(rng_g);
                            drop(seq_g);
                            if let Err(e) = send_ws_text(&mut *ws.writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes()) {
                                eprintln!("[agent] 注册凭据应答发送失败: {}", e);
                                continue;
                            }
                        }
                        eprintln!("[agent] 已应答注册凭据挑战（nonce={}）", &nonce[..nonce.len().min(8)]);
                        SESS_ANSWERED_CHALLENGE.store(true, Ordering::SeqCst);
                        // 补发 register：首次直发的 register 已被中枢 nack（未认证）。
                        let re_reg_payload = build_register_payload(&assets, &ch_token);
                        {
                            let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
                            let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
                            let msg = build_envelope(&mut rng_g, &mut seq_g, "register", &re_reg_payload);
                            drop(rng_g);
                            drop(seq_g);
                            let _ = send_ws_text(&mut *ws.writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes());
                        }
                    }
                    "register_ack" => {
                        if let Some(p) = env.get("payload") {
                            let did = p.get("device_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let tok = p.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let ok = p.get("ok").and_then(|v| v.as_bool().or_else(|| Some(true))).unwrap_or(true);
                            if !did.is_empty() {
                                *device_id.lock().unwrap_or_else(|p| p.into_inner()) = did.clone();
                                *token.lock().unwrap_or_else(|p| p.into_inner()) = tok.clone();
                                *registered.lock().unwrap_or_else(|p| p.into_inner()) = true;
                                eprintln!("[agent] 注册成功 device_id={} token={} ok={}", did, tok, ok);
                                SESS_REGISTERED.store(true, Ordering::SeqCst);
                                AUTH_REJECT_STREAK.store(0, Ordering::SeqCst);
                                agentstate::save(&did, &tok); // 身份落盘，重启复用（不阻塞注册）
                            } else {
                                // nack：把中枢给的理由打出来。此前只打印「缺少 device_id」，
                                // 运维面对「注册一直失败」无从下手（§9.1 未握手时尤其常见）。
                                let reason = p
                                    .get("reason")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("未提供原因");
                                eprintln!("[agent] 注册被拒 ok=false reason={}", reason);
                            }
                        }
                    }
                    "command" => {
                        let did = device_id.lock().unwrap_or_else(|p| p.into_inner()).clone();
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
                                    let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
                                    let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
                                    build_envelope(&mut rng_g, &mut seq_g, "result", &payload_obj)
                                };
                                if let Err(e) = send_ws_text(&mut *ws.writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes()) {
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
                            let did = device_id.lock().unwrap_or_else(|p| p.into_inner()).clone();
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
                    // ---- 波次 2：远控会话内协作 ----
                    // W2-3 画面控制（黑屏防窥 / 水印）：设置采集后处理状态，回告实际生效结果。
                    "rc_display" => {
                        if let Some(p) = env.get("payload") {
                            let blank = p.get("blank").and_then(|v| v.as_bool()).unwrap_or(false);
                            let wm = p.get("watermark").and_then(|v| v.as_bool()).unwrap_or(false);
                            let text = p.get("text").and_then(|v| v.as_str()).unwrap_or("");
                            let (b, w2, used) = rc_wave2::set_display(blank, wm, text);
                            eprintln!("[agent] 画面控制 黑屏={} 水印={} 文本={}", b, w2, used);
                            let ev = format!(
                                "{{\"session_id\":{},\"kind\":\"display_state\",\"message\":{}}}",
                                json_string(&rc::current_session_id()),
                                json_string(&format!("黑屏={} 水印={}", b, w2))
                            );
                            let m = {
                                let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
                                let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
                                build_envelope(&mut rng_g, &mut seq_g, "rc_event", &ev)
                            };
                            let _ = send_ws_text(&mut *ws.writer.lock().unwrap_or_else(|p| p.into_inner()), m.as_bytes());
                        }
                    }
                    // W2-2 会话内消息：被控端系统通知提示 + 回告送达
                    "rc_chat" => {
                        if let Some(p) = env.get("payload") {
                            let text = p.get("text").and_then(|v| v.as_str()).unwrap_or("");
                            let from = p.get("from").and_then(|v| v.as_str()).unwrap_or("operator");
                            rc_wave2::handle_chat(&ws.writer.clone(), &rng, &seq, text, from);
                        }
                    }
                    // W2-1 会话内文件传输（push 接收 / pull 发送，pull 需 YUDUAN_RC_PULL_ROOT）
                    "rc_file_offer" => {
                        if let Some(p) = env.get("payload") {
                            rc_wave2::handle_file_offer(&ws.writer.clone(), &rng, &seq, p);
                        }
                    }
                    "rc_file_accept" => {
                        if let Some(p) = env.get("payload") {
                            rc_wave2::handle_file_accept(&ws.writer.clone(), &rng, &seq, p);
                        }
                    }
                    "rc_file_chunk" => {
                        if let Some(p) = env.get("payload") {
                            rc_wave2::handle_file_chunk(&ws.writer.clone(), &rng, &seq, p);
                        }
                    }
                    // rc_file_done 由对端发出：仅清理本地残留状态
                    "rc_file_done" => {
                        if let Some(p) = env.get("payload") {
                            let tid = p.get("transfer_id").and_then(|v| v.as_str()).unwrap_or("");
                            let ok = p.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                            eprintln!("[agent] 传输结束 tid={} ok={}", tid, ok);
                            if !ok {
                                rc_wave2::cleanup_transfers();
                            }
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
    // v0.4.10（实测报告问题 1）：--version 输出版本标识。CI 各平台构建后立即运行
    // 自检「二进制版本 == 发布号」——option_env! 注入的短字符串会被编译器内联为
    // 指令立即数（不连续存在于 .rodata），对二进制 grep 断言不可靠，运行时输出才可信。
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("yuduan-agent {}", AGENT_VERSION);
        return;
    }
    // Windows：先设 DPI-aware（必须在任何 GetSystemMetrics/SendInput 之前），
    // 否则开启显示缩放的机器上注入坐标与采集坐标系错位（点击落点偏移）。
    #[cfg(target_os = "windows")]
    rc::set_dpi_aware_windows();

    // 远控助手进程（仅 Windows：由服务 CreateProcessAsUserW 拉起，运行于用户会话内采集/注入）。
    // 参数：--rc-helper <port> <session_id>；连接 127.0.0.1:<port> 中继。
    #[cfg(target_os = "windows")]
    {
        if let Some(pos) = std::env::args().position(|a| a == "--rc-helper") {
            let args: Vec<String> = std::env::args().collect();
            match args.get(pos + 1) {
                Some(port) => {
                    let addr = format!("127.0.0.1:{}", port);
                    rc::rc_helper::run(&addr);
                }
                None => {
                    eprintln!("[agent] --rc-helper 缺少端口参数");
                    std::process::exit(2);
                }
            }
        }
    }

    // ===== 交互管理链路：收敛到统一出口 =====
    // 会终止进程的分支不直接 std::process::exit（exit 不跑 Drop，RAII guard 无效，
    // 且逐个 exit 前恢复代码页极易漏），而是把「退出码 + 待恢复的旧控制台代码页」
    // 记入 pending_exit，由 main 末尾统一 restore_console_cp 后单次 exit。
    let mut pending_exit: Option<(i32, u32)> = None;

    // CLI 管理命令：--setup / --install / --uninstall / --status / --console /
    // --set-hub <url> / --help。console 落入下方 run_agent_loop（服务运行时），
    // 不切代码页；其余为交互命令。
    if let Some(cmd) = cli_service_command() {
        let name = service_name();
        let old_cp = if matches!(&cmd, CliCmd::Console) {
            0 // console 走运行时主循环，不碰控制台代码页
        } else {
            set_console_utf8()
        };
        match cmd {
            CliCmd::Console => { /* 前台调试：落入下方 run_agent_loop */ }
            CliCmd::Setup => {
                let display = std::env::var("YUDUAN_SERVICE_DISPLAY")
                    .unwrap_or_else(|_| "YuDuan Agent".into());
                println!("[agent] 一键安装（清旧配置 → 装服务 → 启动）");
                match setup::ensure_installed(&name, &display) {
                    Ok(true) => pending_exit = Some((0, old_cp)),
                    Ok(false) => pending_exit = Some((0, old_cp)), // 已转交 UAC 提权子进程
                    Err(e) => {
                        println!("[agent] 一键安装失败: {}", e);
                        pause_before_exit();
                        pending_exit = Some((1, old_cp));
                    }
                }
            }
            CliCmd::Install => {
                let display = std::env::var("YUDUAN_SERVICE_DISPLAY")
                    .unwrap_or_else(|_| "YuDuan Agent".into());
                // 当前可执行文件路径；含引号以兼容含空格路径（C:\Program Files\...）
                let bin = std::env::current_exe()
                    .ok()
                    .map(|p| format!("\"{}\"", p.display()))
                    .unwrap_or_else(|| "yuduan-agent.exe".into());
                println!("[agent] 安装服务：{} (bin={})", name, bin);
                let result = win_service::install(&name, &display, &bin)
                    .map(|_| format!("服务 {} 安装成功（开机自启 + 失败自动重启）", name));
                pending_exit = Some((report_cli_result(result), old_cp));
            }
            CliCmd::Uninstall => {
                println!("[agent] 卸载服务：{}", name);
                let result =
                    win_service::uninstall(&name).map(|_| format!("服务 {} 已卸载", name));
                pending_exit = Some((report_cli_result(result), old_cp));
            }
            CliCmd::Status => {
                // v0.4.40：win_service::status 内部先读状态文件（端点/来源/最近错误，
                // 普通用户无需管理员即可读），再叠加 SCM 状态。即便 SCM 查询失败
                // （win32 5）也降级展示文件内容，而不是整条命令失败。
                let s = match win_service::status(&name) {
                    Ok(s) => s,
                    Err(s) => s,
                };
                println!("[agent] {}", s);
                pending_exit = Some((0, old_cp));
            }
            CliCmd::Help => {
                print_usage();
                pending_exit = Some((0, old_cp));
            }
            CliCmd::SetHub(url) => {
                if !valid_hub_url(&url) {
                    println!("[agent] --set-hub 需要一个非空、ws:// 或 wss:// 开头且不含空白/引号的中枢地址");
                    println!("[agent] 用法: yuduan-agent.exe --set-hub wss://hub.example.com:8443/ws/agent");
                    pause_before_exit();
                    pending_exit = Some((1, old_cp));
                } else {
                    match maybe_elevate_set_hub(&url) {
                        Ok(true) => {
                            // 已转交 UAC 提权子进程，父进程直接退出（子进程完整执行写文件 + 通知）。
                            println!("[agent] 已在管理员窗口执行设置（UAC 提权）");
                            pending_exit = Some((0, old_cp));
                        }
                        Err(e) => {
                            println!("[agent] 需要管理员权限写入 ProgramData：{}", e);
                            println!("[agent] 请右键「以管理员身份运行」后重试：yuduan-agent.exe --set-hub <url>");
                            pause_before_exit();
                            pending_exit = Some((1, old_cp));
                        }
                        Ok(false) => match config::save_hub_url(&url) {
                            Ok(()) => {
                                // 通知运行中的服务立即热切换；失败不影响「文件已落盘 + 轮询兜底」。
                                if let Err(e) = win_service::notify_hub_changed(&name) {
                                    eprintln!(
                                        "[agent] 通知运行中服务失败（端点已写入，将走文件轮询兜底）: {}",
                                        e
                                    );
                                }
                                println!("[agent] 已设置中枢端点: {}", url.trim());
                                println!("[agent] 已写入 agent-hub.json，并通知运行中的服务立即热切换重连（无需重启服务进程）。");
                                println!("[agent] 若服务不可达 / 控制码不被识别，端点最迟在下次自然重连（3~9s + 退避）生效。");
                                pending_exit = Some((0, old_cp));
                            }
                            Err(e) => {
                                println!("[agent] 写入 agent-hub.json 失败: {}（请以管理员身份运行）", e);
                                pause_before_exit();
                                pending_exit = Some((1, old_cp));
                            }
                        },
                    }
                }
            }
        }
        // console 未收敛到 pending_exit → 继续走服务握手/前台主循环；其余命令已记录退出码。
    }

    // Windows 服务模式优先：SCM 拉起（无命令行参数）时在此完成 dispatcher
    // 握手并阻塞运行至服务停止；双击/终端等交互场景立即返回 false（1063），
    // 继续走下方交互分支。顺序不能颠倒——否则服务进程会被误判为双击而退出。
    // 仅在「没有待处理的交互退出」时尝试握手：服务进程无控制台、set_console_utf8
    // 从未被调用，服务运行时路径不受 CP 逻辑影响。
    #[cfg(windows)]
    if pending_exit.is_none()
        && win_service::run_service(&service_name(), Box::new(run_agent_loop))
    {
        return; // 已按服务模式完整跑到停止
    }

    // Windows 双击直装/状态确认（交互运行、无命令行参数、非服务模式时）：
    //   未安装 → 自动 UAC 提权执行一键安装（小白零操作）；
    //   已安装 → 显示服务状态后退出（后台服务在跑，前台再跑一份会双实例冲突）。
    #[cfg(windows)]
    if pending_exit.is_none() && cli_service_command().is_none() {
        let old_cp = set_console_utf8();
        let name = service_name();
        if !win_service::is_installed(&name) {
            println!("[agent] 检测到首次运行：正在进行一键安装（请在 UAC 弹窗中允许管理员权限）");
            let display = std::env::var("YUDUAN_SERVICE_DISPLAY")
                .unwrap_or_else(|_| "YuDuan Agent".into());
            match setup::ensure_installed(&name, &display) {
                Ok(_) => pending_exit = Some((0, old_cp)),
                Err(e) => {
                    println!("[agent] 一键安装失败: {}", e);
                    pause_before_exit();
                    pending_exit = Some((1, old_cp));
                }
            }
        } else {
            // v0.4.7（实测报告问题 6）：状态查询失败（如普通用户 win32 5 无 SCM 权限）时
            // 不得假报「已常驻」并 exit 0——实施人员会误信副端在跑。显式区分两条出口。
            match win_service::status(&name) {
                Ok(s) => {
                    println!("[agent] {}", s);
                    println!(
                        "[agent] 副端已作为系统服务常驻（开机自启 + 崩溃自动重启）。\
前台调试请运行 --console。注意：双击 exe 不会升级版本、也不会重领密钥；\
升级或中枢换密钥后请以管理员运行 --setup（v0.4.20 起注册被拒也会自动重领）。"
                    );
                    pending_exit = Some((0, old_cp));
                }
                Err(e) => {
                    println!("[agent] 服务已安装，但当前权限无法确认运行状态：{}", e);
                    println!(
                        "[agent] 请以管理员身份运行 `yuduan-agent.exe --status` 核实；\
未确认 RUNNING 前不要假定副端已在后台运行。"
                    );
                    pause_before_exit();
                    pending_exit = Some((1, old_cp));
                }
            }
        }
    }

    // 统一出口：显式恢复旧控制台代码页后再 exit（exit 不跑 Drop，RAII guard 无效）。
    // old_cp==0（无控制台 / 非 Windows / 未设置）时 restore_console_cp 为 no-op。
    if let Some((code, old_cp)) = pending_exit {
        restore_console_cp(old_cp);
        std::process::exit(code);
    }

    // 非服务进程（前台 / 开发态 / 非 Windows / console）
    run_agent_loop();
}

/// CLI 管理命令结果输出并返回退出码；由 main 统一收尾（先恢复控制台代码页再 exit），
/// 避免 exit 不跑 Drop 导致 RAII guard 失效、逐个出口漏恢复。
fn report_cli_result(result: Result<String, String>) -> i32 {
    match result {
        Ok(s) => {
            println!("[agent] {}", s);
            0
        }
        Err(e) => {
            println!("[agent] 操作失败: {}", e);
            pause_before_exit();
            1
        }
    }
}

/// 双击场景收尾：等回车防止窗口闪退。v0.4.8：stdin 非控制台（管道/重定向/服务
/// 上下文）时立即返回——`read_exact` 对「打开但无数据」的管道同样会无限阻塞，
/// 与 --setup 挂起（v0.4.7 报告问题 3）同根因，统一用 setup::stdin_is_interactive 门控。
/// v0.4.10（报告问题 3 连续两轮复现）：提权脚本链的 stdin 是真控制台，非交互探测
/// 放行不了——再加 15s 超时兜底，控制台交互但无人敲回车时自动放行。
fn pause_before_exit() {
    // 仅 Windows 有管道/服务上下文的挂起差异（setup 模块亦为 cfg(windows)）
    #[cfg(windows)]
    if !setup::stdin_is_interactive() {
        return;
    }
    #[cfg(not(windows))]
    {
        // 非 Windows：保持原行为——仅 EOF/错误时立即返回
    }
    print!("按回车关闭窗口（15 秒后自动退出）...");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut b = [0u8; 1];
        let _ = std::io::stdin().read_exact(&mut b);
        let _ = tx.send(());
    });
    for left in (1..=15u64).rev() {
        print!("\r{} 秒后自动退出...  ", left);
        let _ = std::io::stdout().flush();
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(_) => {
                println!();
                return;
            }
            Err(_) => {}
        }
    }
    println!();
}

/// 服务名（可经 YUDUAN_SERVICE_NAME 覆盖，默认 yuduan-agent）。
fn service_name() -> String {
    std::env::var("YUDUAN_SERVICE_NAME").unwrap_or_else(|_| "yuduan-agent".into())
}

/// CLI 管理命令（v0.4.40 起携带 --set-hub 的 <url> 位置参数）。
enum CliCmd {
    Setup,
    Console,
    Install,
    Uninstall,
    Status,
    SetHub(String),
    Help,
}

/// 解析 CLI 管理命令：--setup / --install / --uninstall / --status / --console /
/// --set-hub <url> / --help / -h。
/// 用带下标的遍历（而非 for-skip 丢弃位置值）捕获 --set-hub 后面的 <url>，
/// 手法与 --rc-helper 的 position() 抓取一致。
fn cli_service_command() -> Option<CliCmd> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--setup" => return Some(CliCmd::Setup),
            "--console" => return Some(CliCmd::Console),
            "--install" => return Some(CliCmd::Install),
            "--uninstall" => return Some(CliCmd::Uninstall),
            "--status" => return Some(CliCmd::Status),
            "--help" | "-h" => return Some(CliCmd::Help),
            "--set-hub" => {
                // 捕获紧随其后的位置参数；缺失时给空串，由分发分支统一报参数错误。
                let url = args.get(i + 1).cloned().unwrap_or_default();
                return Some(CliCmd::SetHub(url));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// --help 用法文本（列出全部管理命令，含 v0.4.40 新增的 --set-hub）。
fn print_usage() {
    println!("御端副端 yuduan-agent {} —— 管理命令：", AGENT_VERSION);
    println!("  --setup              一键安装（清旧配置 → 装服务 → 启动，需管理员/UAC）");
    println!("  --install            注册 Windows 服务（开机自启 + 崩溃自动重启）");
    println!("  --uninstall          卸载服务");
    println!("  --status             查看服务状态 + 当前中枢端点/来源/最近错误（优先读状态文件，无需管理员）");
    println!("  --set-hub <url>      设置/切换中枢端点（ws:// 或 wss://），写入 agent-hub.json；");
    println!("                       通知运行中的服务立即热切换重连，无需重启服务进程。需管理员。");
    println!("  --console            前台调试运行（不注册服务）");
    println!("  --help, -h           显示本帮助");
    println!("  --version, -V        显示版本");
}

/// --set-hub URL 校验：非空、ws/wss 前缀、不含空白/引号/控制符（可安全作为单个命令行参数）。
fn valid_hub_url(u: &str) -> bool {
    let u = u.trim();
    if u.is_empty() {
        return false;
    }
    if !(u.starts_with("ws://") || u.starts_with("wss://")) {
        return false;
    }
    !u.chars().any(|c| c.is_whitespace() || c == '"' || c.is_control())
}

/// Windows：写 ProgramData / 发服务控制码需要管理员。未提权时 UAC 重拉自身并原样
/// 携带 --set-hub <url>，返回 Ok(true) 表示已转交提权子进程（调用方应直接退出）；
/// 已提权或非 Windows 返回 Ok(false)（调用方继续写文件）。Err = 提权失败需明确报错。
/// 用两个 cfg 函数而非 cfg 块，避免「属性作用于块表达式」的稳定性歧义。
#[cfg(windows)]
fn maybe_elevate_set_hub(url: &str) -> Result<bool, String> {
    if setup::is_user_admin() {
        return Ok(false);
    }
    // url 已由 valid_hub_url 保证不含空白/引号，可安全透传为单个命令行参数。
    setup::relaunch_elevated(&format!("--set-hub {}", url))?;
    Ok(true)
}
#[cfg(not(windows))]
fn maybe_elevate_set_hub(_url: &str) -> Result<bool, String> {
    Ok(false)
}

/// v0.4.40 端点优先级：持久化 agent-hub.json（--set-hub，运维最新意图，优先）
/// → 环境变量 YUDUAN_HUB（部署脚本注入，可能陈旧）→ None（走 UDP 自动发现）。
/// 返回 (端点, 来源标签)；来源标签供 --status 展示。
fn resolve_hub() -> (Option<String>, &'static str) {
    if let Some(u) = config::load_hub_url() {
        return (Some(u), "persisted");
    }
    if let Some(u) = std::env::var("YUDUAN_HUB")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return (Some(u), "env");
    }
    (None, "discovery")
}

/// 副端主循环（前台/服务共用）：连接中枢 → 会话处理 → 重连退避。
fn run_agent_loop() {
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

    // v0.4.31 §9.2：启动期设备身份密钥自检（main 的服务运行入口，全进程一次）。
    // 生成/加载 keypair 并落盘，中文日志，失败不阻断服务（仅 attestation 不产出）。
    devicekey::startup_self_check();

    // §8.4 + v0.4.40：中枢地址解析，优先级：
    //   持久化 agent-hub.json（--set-hub，运维最新意图，优先）
    //   → 环境变量 YUDUAN_HUB（部署脚本注入，可能陈旧）
    //   → UDP 自动发现（安装即注册，启动时持续重探，不落到写死的兜底地址）。
    // 显式端点（前两者）存在时，重连阶段跳过发现漂移；只有纯发现模式才允许改地址。
    let (explicit_opt, src) = resolve_hub();
    let mut url = match explicit_opt {
        Some(u) => u,
        None => discover_or_wait(),
    };
    // v0.4.40：启动即写状态文件，--status 能立刻看到端点/来源（无需等首轮会话）。
    config::status_note_connect(&url, src);
    // 设备引导（档位 A）：验签密钥未配置时，用广播注册令牌向中枢 claim 获取并
    // 本机加密落盘——部署零手动填密钥。失败不阻塞（开发态放行照常运行）。
    ensure_bootstrap_config();
    eprintln!("[agent] 御端 Rust 副端启动，目标中枢: {}", url);
    eprintln!(
        "[agent] 运行模式: {} · 配置: 验签密钥={} (YUDUAN_HMAC_SECRET/引导下发{})",
        if win_service::is_service_mode() { "Windows 系统服务（SCM 托管）" } else { "前台进程（开发/手动）" },
        if !config::effective_hmac_secret().is_empty() {
            "已配置"
        } else {
            "未配置（开发态放行）"
        },
        if url.starts_with("wss://") {
            if std::env::var("YUDUAN_OPENSSL").map(|v| !v.trim().is_empty()).unwrap_or(false) {
                "，TLS: openssl s_client 管道 (YUDUAN_OPENSSL 覆盖)"
            } else {
                "，TLS: openssl s_client 管道"
            }
        } else {
            ""
        }
    );
    loop {
        if win_service::stop_requested() {
            eprintln!("[agent] 收到服务停止指令，退出主循环");
            break;
        }

        // v0.4.40 端点热切换：每轮重连都重新解析显式端点（--set-hub 写入的
        // agent-hub.json 优先 → 环境变量兜底），与当前 url 不同即立即切换并用新
        // 端点重连。这就是「文件轮询兜底」：控制码不可用时，最迟下一轮重连生效。
        // RELOAD_HUB（SCM 自定义控制置位）在此清零；它同时让 session 读循环 /
        // 退避 sleep 提前返回，构成「在线会话可被打断」的即时路径。
        RELOAD_HUB.store(false, Ordering::SeqCst);
        let (explicit, source) = resolve_hub();
        if let Some(ref u) = explicit {
            if *u != url {
                eprintln!("[agent] 中枢端点已更新: {} -> {}", url, u);
                url = u.clone();
            }
        }

        // 状态文件：记录本轮连接尝试的端点 + 来源，先标记未连接（握手成功再置已连接）。
        config::status_note_connect(&url, source);
        match session(&url) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("[agent] 会话异常: {}，重连（带抖动退避，复用 token）", e);
                config::status_note_error(&e.to_string());
            }
        }
        // v0.4.20 密钥轮换自愈：本轮应答过注册挑战但始终未注册成功 = 中枢不认
        // 我们的凭据（MAC 不匹配被断开 / token 绑定不符）。连续 3 轮即清落盘
        // 密钥，下次重连 ensure_bootstrap_config 自动重新 claim 当前中枢密钥。
        // 清密钥本身无害（重新 claim 取回的就是当前中枢密钥），判据取连续 3 轮
        // 以免网络闪断误触发。
        if SESS_REGISTERED.load(Ordering::SeqCst) {
            AUTH_REJECT_STREAK.store(0, Ordering::SeqCst);
        } else if SESS_ANSWERED_CHALLENGE.load(Ordering::SeqCst) {
            let n = AUTH_REJECT_STREAK.fetch_add(1, Ordering::SeqCst) + 1;
            eprintln!("[agent] 疑似注册凭据与中枢不配对（连续第 {} 轮被拒）", n);
            if n >= 3 {
                eprintln!(
                    "[agent] 连续 3 轮注册被拒：清除本地缓存密钥并重新领取（中枢可能重装/-ResetConfig 轮换过密钥）"
                );
                config::delete_config_file();
                AUTH_REJECT_STREAK.store(0, Ordering::SeqCst);
            }
        }
        // 自动发现模式：重连前重新探测——中枢 IP 可能漂移（网段变更/换路由器/
        // DHCP 续租），探测到新地址即切换。v0.4.40：ANY 显式端点（持久化 agent-hub.json
        // 或环境变量 YUDUAN_HUB）都跳过漂移（尊重现场配置）；重载中则跳过 3s 探测，
        // 直接按新端点重连，避免 --set-hub 被一次发现探测白白拖慢。
        if explicit.is_none() && !RELOAD_HUB.load(Ordering::SeqCst) {
            if let Some(u) = discover::discover_ws(Duration::from_secs(3)) {
                if u != url {
                    eprintln!("[agent] 中枢地址已变化，切换: {} -> {}", url, u);
                    url = u;
                }
            }
        }
        // 引导重试（档位 A）：密钥仍为空时随重连再试 claim——中枢可能比副端晚
        // 上线（开机风暴/重启窗口），首次引导失败不该永久卡在开发态放行。
        // 幂等：已拿到配置（落盘或 env）时立即返回。
        ensure_bootstrap_config();
        // 重连退避 + 抖动（§：规模容量）：固定 5s 会在中枢重启/开机风暴时造成
        // 惊群——2000 台同一秒重试必然再撞 listen backlog（macOS 实测瞬时并发
        // 超 ~128 个握手就被 reset）。这里 3~9s 抖动 randomization 摊开峰值。
        // win_service::sleep 在 Windows 服务模式下可被停止信号打断（250ms 粒度）。
        let mut delay = reconnect_delay_secs();
        // v0.4.34（测试报告 N2）：注册被拒后做指数退避，缓解「拒绝风暴」——
        // S3 窗口曾因恒定 5~9s 重试把 hub.log 刷满、网络持续抖动。连续被拒第 n 轮
        // 额外叠加 5·2^(n-1) 秒（5→10→20→40，封顶 60s）；成功注册或清密钥后
        // AUTH_REJECT_STREAK 归零，退避自动复位。
        let streak = AUTH_REJECT_STREAK.load(Ordering::SeqCst);
        if streak > 0 {
            let exp = (5.0 * 2f64.powi(((streak as i32) - 1).max(0).min(3))) as u64;
            let exp = (exp as f64).min(60.0);
            eprintln!(
                "[agent] 注册被拒退避：基础 {:.1}s + 拒绝指数退避 {:.0}s（连续 {} 轮）",
                delay, exp, streak
            );
            delay += exp;
        }
        // v0.4.40：重载信号已置位 → 跳过退避，立即用新端点重连（不等 3~9s + 退避）。
        // win_service::sleep 在服务模式下也会轮询 RELOAD_HUB 提前结束长退避。
        if RELOAD_HUB.load(Ordering::SeqCst) {
            delay = 0.0;
        }
        win_service::sleep(Duration::from_secs_f64(delay));
    }
}

/// 设备引导（档位 A）：验签密钥未配置时，广播拿一次性注册令牌 → 中枢 claim
/// 换取 HMAC 密钥 → 本机加密落盘（Windows DPAPI / 其它平台 0600），重启自动复用。
/// 已有配置（落盘或 env）则跳过；claim 失败仅告警不阻塞——开发态放行照常运行。
/// 安全边界：广播只携带一次性短时效令牌，HMAC 密钥仅在 claim 响应中传输一次；
/// 中枢启 TLS 时广播 ws= 为 wss（claim 自动走 https），明文场景醒目告警。
fn ensure_bootstrap_config() {
    if !config::effective_hmac_secret().is_empty() {
        return; // 已有配置（落盘复用或显式 env），不重复 claim
    }
    eprintln!("[agent] 验签密钥未配置，尝试引导获取（广播令牌 → /api/agent/claim）…");
    // 复盘 S-2：令牌单次消费——同批并发引导的副端可能拿到已被消费的令牌（4003）。
    // 有界重试：重广播即取到中枢重发的新令牌，收敛到全批引导成功；不阻塞启动。
    let device = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "agent".into());
    for attempt in 0..3u32 {
        let Some(d) = discover::discover_hub(Duration::from_secs(3)) else {
            eprintln!("[agent] ⚠️ 第 {} 轮未发现中枢（无注册令牌），跳过引导", attempt + 1);
            break;
        };
        if d.token.is_empty() {
            eprintln!("[agent] ⚠️ 中枢广播未携带注册令牌（旧版中枢？），跳过引导");
            return;
        }
        match config::claim_from_ws(&d.ws, &d.token, &device) {
            Ok(c) => {
                config::save_hmac_secret(&c.hmac_secret);
                eprintln!(
                    "[agent] ✅ 引导配置获取成功（中枢 {}，传输 {}）：验签密钥已落盘并即刻生效",
                    c.hub_id,
                    if c.via_tls { "TLS/https" } else { "明文 http（内网信任）" }
                );
                return;
            }
            Err(e) => {
                let delay = 2 * (attempt + 1);
                if attempt < 2 {
                    eprintln!(
                        "[agent] ⚠️ 引导获取失败（{}）——{}s 后重试（令牌或已被同批副端消费，重广播取新令牌）",
                        e, delay
                    );
                    win_service::sleep(Duration::from_secs(delay as u64));
                } else {
                    eprintln!(
                        "[agent] ⚠️ 引导获取重试耗尽（{}）——可稍后重启，或用 YUDUAN_HMAC_SECRET 显式配置",
                        e
                    );
                }
            }
        }
    }
}

/// 自动发现中枢（§8.4）：持续广播重探直到找到——副端「安装即注册」，
/// 中枢比副端晚启动/DHCP 晚分配时也能等到，不落到写死的兜底地址。
fn discover_or_wait() -> String {
    loop {
        if win_service::stop_requested() {
            eprintln!("[agent] 收到服务停止指令，退出自动发现等待");
            std::process::exit(0);
        }
        eprintln!(
            "[agent] UDP 广播自动发现中枢（255.255.255.255:{}，单轮 3s）…",
            discover::discovery_port()
        );
        if let Some(u) = discover::discover_ws(Duration::from_secs(3)) {
            eprintln!("[agent] 已自动发现中枢: {}", u);
            return u;
        }
        eprintln!("[agent] 本轮未发现中枢，2s 后重探（中枢上线后将自动注册）…");
        win_service::sleep(Duration::from_secs(2));
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
    use super::{reconnect_delay_secs, stable_device_id, Assets};

    // v0.4.10（实测报告问题 4）：稳定设备 ID 黄金向量——与 Go 副端
    // collect.StableDeviceID 的 collect_test.go 共用同一期望值，规范串漂移即暴露。
    #[test]
    fn stable_device_id_golden_vector() {
        let a = Assets {
            hostname: "Host1".to_string(),
            os: String::new(),
            os_version: String::new(),
            arch: String::new(),
            cpu: String::new(),
            memory_gb: 0,
            disk_gb: 0,
            serial_no: " Serial1 ".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            ip: String::new(),
            agent_version: String::new(),
        };
        assert_eq!(stable_device_id(&a), "2f4a3ec08455b175");
    }

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

// ===================== v0.4.40：--set-hub URL 校验与端点优先级单测 =====================
#[cfg(test)]
mod hub_tests {
    use super::{resolve_hub, valid_hub_url};

    #[test]
    fn valid_hub_url_accepts_ws_wss_and_rejects_bad() {
        assert!(valid_hub_url("ws://127.0.0.1:8080/ws/agent"));
        assert!(valid_hub_url("wss://hub.example.com:8443/ws/agent"));
        assert!(valid_hub_url("  wss://hub.example.com/ws/agent  "));
        assert!(!valid_hub_url(""));
        assert!(!valid_hub_url("   "));
        assert!(!valid_hub_url("http://hub.example.com"));
        assert!(!valid_hub_url("wss://hub example.com"));    // 空白
        assert!(!valid_hub_url("wss://hub\"example.com"));   // 引号
        assert!(!valid_hub_url("wss://hub\nexample.com"));   // 控制符
    }

    #[test]
    fn resolve_hub_precedence_persisted_over_env_over_discovery() {
        let _g = crate::test_lock();
        let dir = std::env::temp_dir().join(format!("yd-resolve-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("YUDUAN_CONFIG_FILE", dir.join("agent-config.json"));
        std::env::remove_var("YUDUAN_HUB");

        // 都无 → 发现模式
        let (u, s) = resolve_hub();
        assert!(u.is_none());
        assert_eq!(s, "discovery");

        // 仅 env
        std::env::set_var("YUDUAN_HUB", "wss://env.example/ws/agent");
        let (u, s) = resolve_hub();
        assert_eq!(u.as_deref(), Some("wss://env.example/ws/agent"));
        assert_eq!(s, "env");

        // 持久化端点出现 → 覆盖陈旧 env（--set-hub 运维最新意图优先）
        crate::config::save_hub_url("wss://persisted.example/ws/agent").unwrap();
        let (u, s) = resolve_hub();
        assert_eq!(u.as_deref(), Some("wss://persisted.example/ws/agent"));
        assert_eq!(s, "persisted");

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("YUDUAN_HUB");
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }
}
