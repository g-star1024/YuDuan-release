// 御端 Rust 副端 —— 远控媒体层（P2P 直连 + 二进制帧 + 编码器协商 + 原生编码器 ABI）。
//
// 对应 protocol.md §4 / §8.3 的生产化目标：M4 MVP 为「中枢居中中继 + JPEG base64」；
// 本模块演进为：二进制帧（固定头 + payload）、编解码器能力协商、P2P 直连媒体通道
// （直连失败回退中枢中继）、原生编码器 C-ABI（H.264/H.265/VP8/VP9/AV1），以及纯 Rust
// 回退编码器（RAW_RGBA / JPEG 透传）。
//
// 零第三方依赖约束：链接系统 C 库（libdl / kernel32）做运行时 dlopen，与项目既有
// 做法（rc.rs 链接 CoreGraphics / X11 / user32）一致，不引入任何第三方 crate。

// 本模块为生产化远控（§8.3）提供的库原语（帧格式 / 协商 / 编码器 / 直连传输），
// 尚未全部接入运行时指令环（MVP 仍走 JSON 中继兜底），故放行 dead_code 提示。
#![allow(dead_code)]

use crate::Json;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// ===================== 二进制帧格式 =====================
// 固定 24 字节头（小端）+ payload：
//   magic:    u32  = 0x59445946 ('YDYF')
//   version:  u8   = 1
//   stream:   u8   = 0 屏幕 / 1 输入回显 / 2 音频
//   codec:    u8   = 见 CODEC_* 常量
//   flags:    u8   = bit0 I 帧 / bit1 黑屏 / bit2 水印
//   seq:      u32
//   width:    u16
//   height:   u16
//   pts_ms:   u32  呈现时间戳（毫秒）
//   len:      u32   payload 字节数
//   payload:  bytes[len]

pub const FRAME_MAGIC: u32 = 0x59445946;
pub const FRAME_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 24;

pub const STREAM_SCREEN: u8 = 0;
pub const STREAM_INPUT_ECHO: u8 = 1;
pub const STREAM_AUDIO: u8 = 2;

pub const CODEC_RAW_RGBA: u8 = 0;
pub const CODEC_JPEG: u8 = 1;
pub const CODEC_H264: u8 = 2;
pub const CODEC_H265: u8 = 3;
pub const CODEC_VP8: u8 = 4;
pub const CODEC_VP9: u8 = 5;
pub const CODEC_AV1: u8 = 6;

pub const FLAG_KEYFRAME: u8 = 0b0000_0001;
pub const FLAG_BLACK: u8 = 0b0000_0010;
pub const FLAG_WATERMARK: u8 = 0b0000_0100;

pub fn codec_name(c: u8) -> &'static str {
    match c {
        CODEC_RAW_RGBA => "raw_rgba",
        CODEC_JPEG => "jpeg",
        CODEC_H264 => "h264",
        CODEC_H265 => "h265",
        CODEC_VP8 => "vp8",
        CODEC_VP9 => "vp9",
        CODEC_AV1 => "av1",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub stream: u8,
    pub codec: u8,
    pub flags: u8,
    pub seq: u32,
    pub width: u16,
    pub height: u16,
    pub pts_ms: u32,
}

/// 将帧头 + payload 序列化为二进制帧（24 字节头 + 负载）。
pub fn encode_frame(hdr: &FrameHeader, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
    buf.push(FRAME_VERSION);
    buf.push(hdr.stream);
    buf.push(hdr.codec);
    buf.push(hdr.flags);
    buf.extend_from_slice(&hdr.seq.to_le_bytes());
    buf.extend_from_slice(&hdr.width.to_le_bytes());
    buf.extend_from_slice(&hdr.height.to_le_bytes());
    buf.extend_from_slice(&hdr.pts_ms.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// 解析二进制帧；返回（帧头，payload 切片）。payload 为零拷贝切片。
pub fn decode_frame(buf: &[u8]) -> Result<(FrameHeader, &[u8]), String> {
    if buf.len() < HEADER_LEN {
        return Err(format!("帧过短: {} < {}", buf.len(), HEADER_LEN));
    }
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != FRAME_MAGIC {
        return Err(format!("magic 不匹配: {:#x}", magic));
    }
    let version = buf[4];
    if version != FRAME_VERSION {
        return Err(format!("帧版本不支持: {}", version));
    }
    let stream = buf[5];
    let codec = buf[6];
    let flags = buf[7];
    let seq = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let width = u16::from_le_bytes([buf[12], buf[13]]);
    let height = u16::from_le_bytes([buf[14], buf[15]]);
    let pts_ms = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let len = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]) as usize;
    if buf.len() < HEADER_LEN + len {
        return Err(format!("payload 截断: 需要 {} 实际 {}", len, buf.len() - HEADER_LEN));
    }
    let header = FrameHeader { stream, codec, flags, seq, width, height, pts_ms };
    let payload = &buf[HEADER_LEN..HEADER_LEN + len];
    Ok((header, payload))
}

// ===================== 编解码器与能力协商 =====================

/// 是否为需原生编码器支持的编解码器（纯 Rust 回退不覆盖）。
pub fn is_native_codec(c: u8) -> bool {
    matches!(c, CODEC_H264 | CODEC_H265 | CODEC_VP8 | CODEC_VP9 | CODEC_AV1)
}

/// 协商：viewer 偏好列表（有序）中第一个 agent 也支持的编解码器；无交集返回 None。
/// agent_codecs 为 agent 可产出的编解码器集合（含回退与已加载的原生编解码器）。
pub fn negotiate(agent_codecs: &[u8], viewer_pref: &[u8]) -> Option<u8> {
    for &p in viewer_pref {
        if agent_codecs.contains(&p) {
            return Some(p);
        }
    }
    None
}

/// 设备端远控能力声明（JSON，经控制长连接 rc_capabilities 下发）。
#[derive(Debug, Clone)]
pub struct Capabilities {
    pub codecs: Vec<u8>,
    pub max_w: u16,
    pub max_h: u16,
    pub fps: u8,
}

impl Capabilities {
    /// 扁平字段序列（不含外层花括号）：便于嵌入 rc_capabilities 信封载荷（§8.3 扁平载荷）。
    pub fn to_payload_fields(&self) -> String {
        let mut s = String::from("\"codecs\":[");
        for (i, code) in self.codecs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&code.to_string());
        }
        s.push_str(&format!(
            "],\"max_w\":{},\"max_h\":{},\"fps\":{}",
            self.max_w, self.max_h, self.fps
        ));
        s
    }

    /// 完整 JSON 对象（含外层花括号）。
    pub fn to_json(&self) -> String {
        format!("{{{}}}", self.to_payload_fields())
    }
}

/// 解析 rc_capabilities / rc_select 的 JSON（无 serde，复用极简 JSON 解析）。
pub fn parse_capabilities(s: &str) -> Option<Capabilities> {
    let j = crate::parse_json(s.as_bytes()).ok()?;
    let codecs = match j.get("codecs") {
        Some(Json::Arr(a)) => a
            .iter()
            .filter_map(|x| if let Json::Num(n) = x { Some(*n as u8) } else { None })
            .collect(),
        _ => Vec::new(),
    };
    let max_w = j.get("max_w").and_then(|v| v.as_i64()).unwrap_or(1920) as u16;
    let max_h = j.get("max_h").and_then(|v| v.as_i64()).unwrap_or(1080) as u16;
    let fps = j.get("fps").and_then(|v| v.as_i64()).unwrap_or(15) as u8;
    Some(Capabilities { codecs, max_w, max_h, fps })
}

/// Agent 默认可产出编解码器：RAW_RGBA + JPEG 始终可用（纯 Rust 回退）；
/// 配置了 YUDUAN_ENCODER_LIB 时，逐个探测原生编解码器（H264/H265/VP8/VP9/AV1），
/// 仅宣告库真实支持（能创建句柄）的——不虚标能力。
/// 原生编码器探测缓存（进程级）：探测要真实创建编码器会话（含预热），
/// 编码器服务异常时单次探测可达数十秒，必须缓存避免每次会话重复惩罚。
pub fn native_probe_cached(codec: u8) -> bool {
    use std::sync::Mutex;
    static CACHE: Mutex<Vec<(u8, bool)>> = Mutex::new(Vec::new());
    let mut cache = CACHE.lock().unwrap();
    if let Some(&(_, ok)) = cache.iter().find(|(c, _)| *c == codec) {
        return ok;
    }
    // 探测用小尺寸会话（仅验证库能否创建该编解码器句柄，立即销毁）。
    let ok = NativeEncoder::try_load(codec, 640, 360).is_some();
    cache.push((codec, ok));
    ok
}

pub fn agent_codecs() -> Vec<u8> {
    let mut v = vec![CODEC_RAW_RGBA, CODEC_JPEG];
    if std::env::var("YUDUAN_ENCODER_LIB")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        for &c in &[CODEC_H264, CODEC_H265, CODEC_VP8, CODEC_VP9, CODEC_AV1] {
            if native_probe_cached(c) {
                v.push(c);
            }
        }
    }
    v
}

pub fn default_capabilities() -> Capabilities {
    Capabilities {
        codecs: agent_codecs(),
        max_w: 1920,
        max_h: 1080,
        fps: 15,
    }
}

// ===================== 编码器（纯 Rust 回退 + 原生 ABI） =====================

/// 编码器抽象：将 RGBA 缓冲（或已编码字节）编码为指定编解码器的帧 payload（不含帧头）。
pub trait Encoder: Send {
    fn encode(&mut self, rgba: &[u8], w: u32, h: u32) -> Result<Vec<u8>, String>;
    fn codec(&self) -> u8;
    /// 会话中途码率重参数化（§8.3.15）。默认无操作：RAW/JPEG 透传路径不适用；
    /// 原生编码器按库是否导出 yuduan_enc_set_bitrate 决定实际效果。
    fn set_bitrate(&mut self, _kbps: u64) {}
}

/// 纯 Rust 回退：RAW_RGBA（零压缩，便于无原生库时仍走二进制帧通道）。
pub struct RawRgbaEncoder;
impl Encoder for RawRgbaEncoder {
    fn encode(&mut self, rgba: &[u8], w: u32, h: u32) -> Result<Vec<u8>, String> {
        let need = w as usize * h as usize * 4;
        if rgba.len() < need {
            return Err(format!("RGBA 缓冲不足: 需 {} 实 {}", need, rgba.len()));
        }
        Ok(rgba[..need].to_vec())
    }
    fn codec(&self) -> u8 {
        CODEC_RAW_RGBA
    }
}

/// 纯 Rust 回退：JPEG 透传（capture 工具已产出 jpeg 字节，仅包裹；不重新编码）。
pub struct JpegPassthroughEncoder;
impl Encoder for JpegPassthroughEncoder {
    fn encode(&mut self, jpeg: &[u8], _w: u32, _h: u32) -> Result<Vec<u8>, String> {
        if jpeg.len() < 2 || jpeg[0] != 0xFF || jpeg[1] != 0xD8 {
            return Err("非 JPEG 数据（缺 SOI 标记）".into());
        }
        Ok(jpeg.to_vec())
    }
    fn codec(&self) -> u8 {
        CODEC_JPEG
    }
}

// ===================== 原生编码器 C-ABI =====================
// 部署期由外部 .so / .dylib / .dll 提供，纯 Rust 不内置 H.264/H.265 等复杂编码器。
// 约定符号（C ABI）：
//   void*    yuduan_enc_create (const char* codec, uint32_t width, uint32_t height);
//   uint32_t yuduan_enc_encode (void* h, const uint8_t* rgba, uint32_t rgba_len,
//                              uint8_t* out, uint32_t out_cap);
//   void     yuduan_enc_destroy(void* h);
// 编码约定：yuduan_enc_encode 写入 out（上限 out_cap），返回实际写入字节数；
//   返回 0 且 rgba 合法 = 缓冲区不足，调用方扩张 out 后重试（上限 = rgba_len*4 视为异常）。
// 与项目既有做法一致：以 #[link] 链接系统 C 库（libdl / kernel32），不引入第三方 crate。

#[cfg(target_os = "linux")]
#[link(name = "dl")]
extern "C" {
    fn dlopen(filename: *const std::os::raw::c_char, flag: std::os::raw::c_int) -> *mut std::os::raw::c_void;
    fn dlsym(handle: *mut std::os::raw::c_void, symbol: *const std::os::raw::c_char) -> *mut std::os::raw::c_void;
}

#[cfg(not(target_os = "linux"))]
extern "C" {
    fn dlopen(filename: *const std::os::raw::c_char, flag: std::os::raw::c_int) -> *mut std::os::raw::c_void;
    fn dlsym(handle: *mut std::os::raw::c_void, symbol: *const std::os::raw::c_char) -> *mut std::os::raw::c_void;
}

#[cfg(windows)]
extern "system" {
    fn LoadLibraryA(lp_file_name: *const std::os::raw::c_char) -> *mut std::os::raw::c_void;
    fn GetProcAddress(h_module: *mut std::os::raw::c_void, lp_proc_name: *const std::os::raw::c_char)
        -> *mut std::os::raw::c_void;
}

const RTLD_NOW: std::os::raw::c_int = 0x2;

/// 跨平台解析动态库符号（返回裸指针；调用方负责类型转换与生命周期）。
/// Unix: dlopen + dlsym；Windows: LoadLibraryA + GetProcAddress。
unsafe fn load_symbol(lib: &str, sym: &str) -> Option<*mut std::os::raw::c_void> {
    let to_cstr = |s: &str| -> Vec<std::os::raw::c_char> {
        s.bytes()
            .chain(std::iter::once(0u8))
            .map(|b| b as std::os::raw::c_char)
            .collect()
    };
    #[cfg(windows)]
    {
        let lib_c = to_cstr(lib);
        let handle = LoadLibraryA(lib_c.as_ptr());
        if handle.is_null() {
            return None;
        }
        let sym_c = to_cstr(sym);
        let f = GetProcAddress(handle, sym_c.as_ptr());
        if f.is_null() {
            return None;
        }
        Some(f)
    }
    #[cfg(not(windows))]
    {
        let lib_c = to_cstr(lib);
        let handle = dlopen(lib_c.as_ptr(), RTLD_NOW);
        if handle.is_null() {
            return None;
        }
        let sym_c = to_cstr(sym);
        let f = dlsym(handle, sym_c.as_ptr());
        if f.is_null() {
            return None;
        }
        Some(f)
    }
}

type EncCreate = unsafe extern "C" fn(
    *const std::os::raw::c_char,
    std::os::raw::c_uint,
    std::os::raw::c_uint,
) -> *mut std::os::raw::c_void;
type EncEncode = unsafe extern "C" fn(
    *mut std::os::raw::c_void,
    *const u8,
    std::os::raw::c_uint,
    *mut u8,
    std::os::raw::c_uint,
) -> std::os::raw::c_uint;
type EncDestroy = unsafe extern "C" fn(*mut std::os::raw::c_void);
/// 可选导出（§8.3.15 码率重参数化）：会话中途调整目标码率。
/// 库未导出该符号 = 不支持动态重参数化（副端诚实记录，不重试不报错）。
///   void yuduan_enc_set_bitrate(void* h, uint32_t kbps);
type EncSetBitrate = unsafe extern "C" fn(*mut std::os::raw::c_void, std::os::raw::c_uint);

/// 原生编码器封装：从 YUDUAN_ENCODER_LIB 动态库加载，按编解码器创建句柄。
/// 句柄来自已加载的动态库且由本结构独占，断言 Send 以便跨线程持有（单线程使用）。
pub struct NativeEncoder {
    handle: *mut std::os::raw::c_void,
    encode: EncEncode,
    destroy: EncDestroy,
    set_bitrate_fn: Option<EncSetBitrate>,
    codec: u8,
}

unsafe impl Send for NativeEncoder {}

impl NativeEncoder {
    /// 尝试从 YUDUAN_ENCODER_LIB 指定动态库加载原生编码器；失败返回 None（回退纯 Rust）。
    /// w/h 为编码会话尺寸：帧循环须把采集帧缩放到同一尺寸后送编码（fit_dims/downscale_rgba）。
    pub fn try_load(codec: u8, w: u32, h: u32) -> Option<NativeEncoder> {
        let lib = std::env::var("YUDUAN_ENCODER_LIB").ok()?;
        if lib.trim().is_empty() {
            return None;
        }
        let create = unsafe { std::mem::transmute::<*mut std::os::raw::c_void, EncCreate>(load_symbol(&lib, "yuduan_enc_create")?) };
        let encode = unsafe { std::mem::transmute::<*mut std::os::raw::c_void, EncEncode>(load_symbol(&lib, "yuduan_enc_encode")?) };
        let destroy = unsafe { std::mem::transmute::<*mut std::os::raw::c_void, EncDestroy>(load_symbol(&lib, "yuduan_enc_destroy")?) };
        // §8.3.15：set_bitrate 为可选导出——缺失时该编码器不支持会话中途码率重参数化。
        let set_bitrate_fn = unsafe { load_symbol(&lib, "yuduan_enc_set_bitrate") }
            .map(|p| unsafe { std::mem::transmute::<*mut std::os::raw::c_void, EncSetBitrate>(p) });
        let codec_name = match codec {
            CODEC_H264 => "h264\0",
            CODEC_H265 => "h265\0",
            CODEC_VP8 => "vp8\0",
            CODEC_VP9 => "vp9\0",
            CODEC_AV1 => "av1\0",
            _ => return None,
        };
        unsafe {
            let handle = create(codec_name.as_ptr() as *const std::os::raw::c_char, w, h);
            if handle.is_null() {
                return None;
            }
            Some(NativeEncoder {
                handle,
                encode,
                destroy,
                set_bitrate_fn,
                codec,
            })
        }
    }
}

impl Encoder for NativeEncoder {
    fn encode(&mut self, rgba: &[u8], _w: u32, _h: u32) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; rgba.len().max(4096)];
        loop {
            let written = unsafe {
                (self.encode)(
                    self.handle,
                    rgba.as_ptr(),
                    rgba.len() as std::os::raw::c_uint,
                    out.as_mut_ptr(),
                    out.len() as std::os::raw::c_uint,
                )
            };
            if written == 0 {
                // 缓冲区不足：扩张重试（上限 rgba_len*4，超出视为异常）
                if out.len() >= rgba.len() * 4 {
                    return Err("原生编码器输出异常（缓冲区扩张超限）".into());
                }
                out.resize(out.len() * 2, 0);
                continue;
            }
            out.truncate(written as usize);
            return Ok(out);
        }
    }
    fn codec(&self) -> u8 {
        self.codec
    }
    fn set_bitrate(&mut self, kbps: u64) {
        if let Some(f) = self.set_bitrate_fn {
            unsafe { (f)(self.handle, kbps.min(u32::MAX as u64) as std::os::raw::c_uint) };
        }
    }
}

impl Drop for NativeEncoder {
    fn drop(&mut self) {
        unsafe { (self.destroy)(self.handle); }
    }
}

/// 选择编码器：原生编解码器优先走 NativeEncoder（若库已加载），否则回退：
/// JPEG 用透传，其余（含 RAW）用 RawRgbaEncoder。
/// w/h = 编码会话尺寸（原生库按 create(codec,w,h) 创建会话，帧循环送同尺寸帧）。
pub fn make_encoder(codec: u8, w: u32, h: u32) -> Box<dyn Encoder> {
    if is_native_codec(codec) {
        if let Some(e) = NativeEncoder::try_load(codec, w, h) {
            return Box::new(e);
        }
        eprintln!(
            "[agent] 原生编码器 {} 不可用（未配置 YUDUAN_ENCODER_LIB 或加载失败），回退 RAW_RGBA",
            codec_name(codec)
        );
        return Box::new(RawRgbaEncoder);
    }
    match codec {
        CODEC_JPEG => Box::new(JpegPassthroughEncoder),
        _ => Box::new(RawRgbaEncoder),
    }
}

// ===================== 媒体环性能：目标尺寸与降采样（§8.3.7） =====================

/// 保比缩放至 max_w×max_h 内（只缩不放），并取偶（H.264/HEVC 要求偶数尺寸）。
/// 返回 (目标宽, 目标高)；max 为 0 视为不限制（保持原尺寸，仍取偶）。
pub fn fit_dims(cw: u32, ch: u32, max_w: u32, max_h: u32) -> (u32, u32) {
    let even = |v: u32| v & !1;
    let (mw, mh) = if max_w == 0 || max_h == 0 {
        (cw, ch)
    } else {
        (max_w, max_h)
    };
    if cw == 0 || ch == 0 {
        return (1, 1);
    }
    // 只缩不放：已小于上限则保持原尺寸（取偶）
    if cw <= mw && ch <= mh {
        return (even(cw).max(2), even(ch).max(2));
    }
    let scale = (mw as f64 / cw as f64).min(mh as f64 / ch as f64);
    let tw = ((cw as f64 * scale).round() as u32).max(2);
    let th = ((ch as f64 * scale).round() as u32).max(2);
    (even(tw).max(2), even(th).max(2))
}

/// RGBA 最近邻缩放（紧凑 RGBA8 → 紧凑 RGBA8）。目标尺寸 ≤ 源（只缩不放）。
pub fn downscale_rgba(data: &[u8], w: u32, h: u32, tw: u32, th: u32) -> Vec<u8> {
    let (tw, th) = fit_dims(w, h, tw, th); // 防御：目标不超源
    let mut out = vec![0u8; tw as usize * th as usize * 4];
    for y in 0..th as usize {
        let sy = (y as u64 * h as u64 / th as u64) as usize;
        let src_row = &data[sy * w as usize * 4..(sy + 1) * w as usize * 4];
        let dst_row = &mut out[y * tw as usize * 4..(y + 1) * tw as usize * 4];
        for x in 0..tw as usize {
            let sx = (x as u64 * w as u64 / tw as u64) as usize;
            let s = &src_row[sx * 4..sx * 4 + 4];
            let d = &mut dst_row[x * 4..x * 4 + 4];
            d.copy_from_slice(s);
        }
    }
    out
}

// ===================== P2P 直连媒体通道（中继兜底） =====================

/// 直连优先：尝试 dial 对端媒体地址；失败返回 Err（调用方改用中枢中继）。
pub fn dial_direct(addr: &str) -> Result<TcpStream, String> {
    let socket_addr = addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("地址解析失败 {}: {}", addr, e))?;
    let s = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))
        .map_err(|e| format!("P2P 直连失败 {}: {}", addr, e))?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    Ok(s)
}

/// 在已建立的媒体流上发送一帧：先写 4 字节小端长度前缀，再写帧体（便于对端按帧切分）。
pub fn send_frame(stream: &mut TcpStream, frame: &[u8]) -> Result<(), String> {
    stream
        .write_all(&(frame.len() as u32).to_le_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(frame).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

/// 从媒体流读取一帧：读 4 字节小端长度前缀 + 帧体。
pub fn recv_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("读帧长度失败: {}", e))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("读帧体失败: {}", e))?;
    Ok(buf)
}

// ===================== 测试 =====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_all_codecs() {
        for codec in [
            CODEC_RAW_RGBA,
            CODEC_JPEG,
            CODEC_H264,
            CODEC_H265,
            CODEC_VP8,
            CODEC_VP9,
            CODEC_AV1,
        ] {
            let hdr = FrameHeader {
                stream: STREAM_SCREEN,
                codec,
                flags: FLAG_KEYFRAME,
                seq: 7,
                width: 1280,
                height: 720,
                pts_ms: 1234,
            };
            let payload = vec![0xABu8; 256];
            let frame = encode_frame(&hdr, &payload);
            assert_eq!(frame.len(), HEADER_LEN + 256);
            let (got, pl) = decode_frame(&frame).unwrap();
            assert_eq!(got, hdr);
            assert_eq!(pl, &payload[..]);
        }
    }

    #[test]
    fn decode_rejects_bad_magic_and_truncated() {
        let hdr = FrameHeader {
            stream: STREAM_SCREEN,
            codec: CODEC_RAW_RGBA,
            flags: 0,
            seq: 1,
            width: 10,
            height: 10,
            pts_ms: 0,
        };
        let frame = encode_frame(&hdr, &[0u8; 40]);
        // 破坏 magic
        let mut bad = frame.clone();
        bad[0] = 0x00;
        assert!(decode_frame(&bad).is_err());
        // 截断
        assert!(decode_frame(&frame[..10]).is_err());
        // payload 不足声明长度
        assert!(decode_frame(&frame[..HEADER_LEN + 5]).is_err());
    }

    #[test]
    fn negotiate_prefers_first_common_codec() {
        let agent = [CODEC_RAW_RGBA, CODEC_JPEG, CODEC_H264];
        // viewer 偏好 H264 在前 → 命中 H264
        assert_eq!(negotiate(&agent, &[CODEC_H264, CODEC_H265, CODEC_JPEG]), Some(CODEC_H264));
        // viewer 偏好 AV1（agent 无）→ 落 JPEG
        assert_eq!(negotiate(&agent, &[CODEC_AV1, CODEC_JPEG]), Some(CODEC_JPEG));
        // 完全无交集
        assert_eq!(negotiate(&agent, &[CODEC_VP9, CODEC_AV1]), None);
    }

    #[test]
    fn caps_json_roundtrip() {
        let caps = Capabilities {
            codecs: vec![CODEC_RAW_RGBA, CODEC_JPEG, CODEC_H264],
            max_w: 2560,
            max_h: 1440,
            fps: 24,
        };
        let json = caps.to_json();
        let parsed = parse_capabilities(&json).expect("解析失败");
        assert_eq!(parsed.codecs, vec![CODEC_RAW_RGBA, CODEC_JPEG, CODEC_H264]);
        assert_eq!(parsed.max_w, 2560);
        assert_eq!(parsed.max_h, 1440);
        assert_eq!(parsed.fps, 24);
    }

    #[test]
    fn raw_rgba_encoder_produces_exact_bytes() {
        let mut enc = RawRgbaEncoder;
        let rgba = vec![1u8, 2, 3, 4, 5, 6, 7, 8]; // 2x1 RGBA
        let out = enc.encode(&rgba, 2, 1).unwrap();
        assert_eq!(out, rgba);
        assert_eq!(enc.codec(), CODEC_RAW_RGBA);
    }

    #[test]
    fn jpeg_passthrough_accepts_soi_rejects_other() {
        let mut enc = JpegPassthroughEncoder;
        let jpg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(enc.encode(&jpg, 0, 0).unwrap(), jpg);
        let bad = vec![0x00u8, 0x01, 0x02];
        assert!(enc.encode(&bad, 0, 0).is_err());
    }

    #[test]
    fn make_encoder_falls_back_without_native_lib() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        // 未配置 YUDUAN_ENCODER_LIB：原生编解码器回退 RAW_RGBA，JPEG 走透传。
        std::env::remove_var("YUDUAN_ENCODER_LIB");
        let e = make_encoder(CODEC_H264, 640, 360);
        assert_eq!(e.codec(), CODEC_RAW_RGBA);
        let j = make_encoder(CODEC_JPEG, 640, 360);
        assert_eq!(j.codec(), CODEC_JPEG);
        let r = make_encoder(CODEC_RAW_RGBA, 640, 360);
        assert_eq!(r.codec(), CODEC_RAW_RGBA);
    }

    #[test]
    fn native_encoder_load_fails_gracefully() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        // 未配置 / 文件不存在 → try_load 返回 None（不影响回退）。
        std::env::remove_var("YUDUAN_ENCODER_LIB");
        assert!(NativeEncoder::try_load(CODEC_H264, 640, 360).is_none());
        std::env::set_var("YUDUAN_ENCODER_LIB", "/no/such/encoder.lib");
        assert!(NativeEncoder::try_load(CODEC_H265, 640, 360).is_none());
        std::env::remove_var("YUDUAN_ENCODER_LIB");
    }

    #[test]
    fn fit_dims_preserves_aspect_and_even() {
        // 3584×2240 → min(1920/3584,1080/2240)=0.4821 → 1728×1080（保比、偶数）
        assert_eq!(fit_dims(3584, 2240, 1920, 1080), (1728, 1080));
        // 已小于上限：保持原尺寸（取偶）
        assert_eq!(fit_dims(1280, 800, 1920, 1080), (1280, 800));
        // 只缩不放：一边超限
        assert_eq!(fit_dims(2560, 1080, 1920, 1080), (1920, 810));
        // 奇数尺寸取偶
        assert_eq!(fit_dims(641, 481, 0, 0), (640, 480));
        // 极端比例
        assert_eq!(fit_dims(3840, 2160, 1920, 1080), (1920, 1080));
        assert_eq!(fit_dims(1000, 1000, 100, 500), (100, 100));
        // 0 尺寸防御
        assert_eq!(fit_dims(0, 0, 1920, 1080), (1, 1));
    }

    #[test]
    fn downscale_rgba_nearest_neighbor() {
        // 2×2 → 2×2（不变）
        let src: Vec<u8> = vec![
            1, 2, 3, 255, 4, 5, 6, 255,
            7, 8, 9, 255, 10, 11, 12, 255,
        ];
        let out = downscale_rgba(&src, 2, 2, 2, 2);
        assert_eq!(out, src);
        // 4×4 → 2×2：取 (0,0) (2,0) (0,2) (2,2)
        let mut src4 = vec![0u8; 4 * 4 * 4];
        for y in 0..4 {
            for x in 0..4 {
                let v = (y * 4 + x) as u8;
                src4[(y * 4 + x) * 4] = v;
            }
        }
        let out2 = downscale_rgba(&src4, 4, 4, 2, 2);
        assert_eq!(out2.len(), 2 * 2 * 4);
        assert_eq!(out2[0], 0); // (0,0)
        assert_eq!(out2[4], 2); // (2,0)
        assert_eq!(out2[8], 8); // (0,2)
        assert_eq!(out2[12], 10); // (2,2)
        // 3×3 → 2×2（最近邻取样，长度正确即可，取样点实现相关）
        let src3 = vec![9u8; 3 * 3 * 4];
        let out3 = downscale_rgba(&src3, 3, 3, 2, 2);
        assert_eq!(out3, vec![9u8; 2 * 2 * 4]);
    }

    #[test]
    fn media_peer_loopback_exchange() {
        use std::net::TcpListener;
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            let frame = recv_frame(&mut peer).unwrap();
            // 回显同一帧（模拟对端收到后解码）
            send_frame(&mut peer, &frame).unwrap();
        });
        let mut client = dial_direct(&addr.to_string()).unwrap();
        let hdr = FrameHeader {
            stream: STREAM_SCREEN,
            codec: CODEC_RAW_RGBA,
            flags: FLAG_KEYFRAME,
            seq: 42,
            width: 4,
            height: 4,
            pts_ms: 99,
        };
        let payload = vec![0x10u8; 4 * 4 * 4];
        let frame = encode_frame(&hdr, &payload);
        send_frame(&mut client, &frame).unwrap();
        let echoed = recv_frame(&mut client).unwrap();
        let (got, pl) = decode_frame(&echoed).unwrap();
        assert_eq!(got, hdr);
        assert_eq!(pl, &payload[..]);
    }
}
