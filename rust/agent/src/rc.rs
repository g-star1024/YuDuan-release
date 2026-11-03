// 御端 Rust 副端 —— M4 远程控制（参考互通版）。
// 采集：macOS screencapture / Linux scrot|import（无工具则上报未就绪，不造假帧）。
// 输入：macOS CoreGraphics FFI（CGEvent）/ Linux X11 XTest FFI（xdotool 兜底）/ Windows user32 SendInput FFI。
// 合规：会话开启即发 consent_required + 本地通知（远端提示铁律：员工知情、可拒绝）。
// 协议与 Go 参考实现完全一致：rc_ready / rc_frame / rc_event / rc_input / rc_stop。

use crate::base64_encode;
use crate::json_string;
use crate::rc_media::{default_capabilities, encode_frame, make_encoder, Encoder, FrameHeader};
use crate::send_ws_binary;
use crate::sha256::base64_decode;
use crate::send_ws_text;
use std::io::Write;
use std::os::raw::{c_int, c_uint, c_ushort, c_void};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;

type Writer = Arc<Mutex<Box<dyn Write + Send>>>;

// ===================== macOS CoreGraphics FFI（键鼠注入） =====================

#[cfg(target_os = "macos")]
mod cg {
    use std::os::raw::c_void;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct CGPoint {
        pub x: f64,
        pub y: f64,
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        pub fn CGEventCreateMouseEvent(
            source: *const c_void,
            mouse_type: u32,
            pos: CGPoint,
            button: u32,
        ) -> *const c_void;
        pub fn CGEventPost(tap: u32, event: *const c_void);
        pub fn CGEventCreateKeyboardEvent(
            source: *const c_void,
            virtual_key: u16,
            down: bool,
        ) -> *const c_void;
        /// 非可变参数变体（FFI 安全）：三轴滚轮，仅用 wheel1。
        pub fn CGEventCreateScrollWheelEvent2(
            source: *const c_void,
            units: u32,
            wheel_count: u32,
            wheel1: i32,
            wheel2: i32,
            wheel3: i32,
        ) -> *const c_void;
    }

    pub const K_CG_HID_EVENT_TAP: u32 = 0;
    pub const MOUSE_MOVED: u32 = 5;
    pub const MOUSE_LEFT_DOWN: u32 = 1;
    pub const MOUSE_LEFT_UP: u32 = 2;
    pub const MOUSE_RIGHT_DOWN: u32 = 3;
    pub const MOUSE_RIGHT_UP: u32 = 4;
    pub const BUTTON_LEFT: u32 = 0;
    pub const BUTTON_RIGHT: u32 = 1;
    pub const SCROLL_UNIT_PIXEL: u32 = 1;
}

/// 键名 → macOS 虚拟键码（常见子集）。
#[cfg(target_os = "macos")]
fn key_code_of(name: &str) -> Option<u16> {
    Some(match name.to_ascii_lowercase().as_str() {
        "enter" | "return" => 36,
        "tab" => 48,
        "space" => 49,
        "backspace" | "delete" => 51,
        "esc" | "escape" => 53,
        "left" => 123,
        "right" => 124,
        "down" => 125,
        "up" => 126,
        "f1" => 122,
        "home" => 115,
        "end" => 119,
        "pageup" => 116,
        "pagedown" => 121,
        _ => return None,
    })
}

// ===================== Linux X11/XTest FFI（键鼠注入） =====================

#[cfg(target_os = "linux")]
mod xt {
    use std::os::raw::{c_char, c_int, c_uint, c_ulong};

    #[link(name = "X11")]
    extern "C" {
        pub fn XOpenDisplay(name: *const c_char) -> *mut std::os::raw::c_void;
        pub fn XCloseDisplay(d: *mut std::os::raw::c_void) -> c_int;
        pub fn XFlush(d: *mut std::os::raw::c_void) -> c_int;
        pub fn XStringToKeysym(s: *const c_char) -> c_ulong;
        pub fn XKeysymToKeycode(d: *mut std::os::raw::c_void, keysym: c_ulong) -> c_uint;
    }

    #[link(name = "Xtst")]
    extern "C" {
        pub fn XTestFakeMotionEvent(
            d: *mut std::os::raw::c_void,
            screen: c_int,
            x: c_int,
            y: c_int,
            delay: c_ulong,
        ) -> c_int;
        pub fn XTestFakeButtonEvent(
            d: *mut std::os::raw::c_void,
            button: c_uint,
            press: c_int,
            delay: c_ulong,
        ) -> c_int;
        pub fn XTestFakeKeyEvent(
            d: *mut std::os::raw::c_void,
            keycode: c_uint,
            press: c_int,
            delay: c_ulong,
        ) -> c_int;
    }
}

/// 键名 → X11 keysym（XK_* 常量，纯函数便于跨平台单测）。
#[allow(dead_code)] // 非 Linux 主机上仅测试引用
fn keysym_of(name: &str) -> Option<u64> {
    Some(match name.to_ascii_lowercase().as_str() {
        "enter" | "return" => 0xff0d,  // XK_Return
        "tab" => 0xff09,               // XK_Tab
        "space" => 0x020,              // XK_space
        "backspace" => 0xff08,         // XK_BackSpace
        "delete" => 0xffff,            // XK_Delete
        "esc" | "escape" => 0xff1b,    // XK_Escape
        "left" => 0xff51,              // XK_Left
        "up" => 0xff52,                // XK_Up
        "right" => 0xff53,             // XK_Right
        "down" => 0xff54,              // XK_Down
        "home" => 0xff50,              // XK_Home
        "end" => 0xff57,               // XK_End
        "pageup" => 0xff55,            // XK_Page_Up
        "pagedown" => 0xff56,          // XK_Page_Down
        "f1" => 0xffbe,                // XK_F1
        _ => return None,
    })
}

// ===================== Windows user32 SendInput FFI（键鼠注入） =====================

#[cfg(target_os = "windows")]
pub(crate) mod win32 {
    use std::os::raw::{c_int, c_long, c_uint, c_ulong};

    // Win32 真实取值（winuser.h）：INPUT_MOUSE=0, INPUT_KEYBOARD=1, INPUT_HARDWARE=2。
    // ⚠️ 曾错写为 1/2：鼠标事件被 SendInput 按 KEYBDINPUT 解释（坐标字节→随机键码，
    // 即「点击乱输入/弹搜索」的根因），键盘事件按 INPUT_HARDWARE 发送必被拒
    // （SendInput 仅注入 0/N）。cargo check 查不出常量值错误，只能实测发现。
    pub const INPUT_MOUSE: c_ulong = 0;
    pub const INPUT_KEYBOARD: c_ulong = 1;
    pub const INPUT_HARDWARE: c_ulong = 2;
    pub const KEYEVENTF_KEYUP: c_ulong = 0x0002;
    pub const MOUSEEVENTF_MOVE: c_ulong = 0x0001;
    pub const MOUSEEVENTF_ABSOLUTE: c_ulong = 0x8000;
    pub const MOUSEEVENTF_VIRTUALDESK: c_ulong = 0x4000;
    pub const MOUSEEVENTF_LEFTDOWN: c_ulong = 0x0002;
    pub const MOUSEEVENTF_LEFTUP: c_ulong = 0x0004;
    pub const MOUSEEVENTF_RIGHTDOWN: c_ulong = 0x0008;
    pub const MOUSEEVENTF_RIGHTUP: c_ulong = 0x0010;
    pub const MOUSEEVENTF_WHEEL: c_ulong = 0x0800;
    pub const WHEEL_DELTA: c_long = 120;
    pub const SM_XVIRTUALSCREEN: c_int = 76;
    pub const SM_YVIRTUALSCREEN: c_int = 77;
    pub const SM_CXVIRTUALSCREEN: c_int = 78;
    pub const SM_CYVIRTUALSCREEN: c_int = 79;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MOUSEINPUT {
        pub dx: c_long,
        pub dy: c_long,
        pub mouse_data: c_ulong,
        pub dw_flags: c_ulong,
        pub time: c_ulong,
        pub dw_extra_info: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct KEYBDINPUT {
        pub w_vk: u16,
        pub w_scan: u16,
        pub dw_flags: c_ulong,
        pub time: c_ulong,
        pub dw_extra_info: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union INPUTUNION {
        pub mouse: MOUSEINPUT,
        pub keyboard: KEYBDINPUT,
    }

    #[repr(C)]
    pub struct INPUT {
        pub type_: c_ulong,
        pub u: INPUTUNION,
    }

    #[link(name = "user32")]
    extern "system" {
        pub fn SendInput(n: c_uint, inputs: *const INPUT, size: c_int) -> c_uint;
        pub fn VkKeyScanW(ch: u16) -> i16;
        pub fn GetSystemMetrics(index: c_int) -> c_int;
        pub fn GetDC(hwnd: *mut std::os::raw::c_void) -> *mut std::os::raw::c_void;
        pub fn ReleaseDC(hwnd: *mut std::os::raw::c_void, hdc: *mut std::os::raw::c_void) -> c_int;
        // DPI 感知（Win10 1703+ 首选 Per-Monitor v2，老系统退 SetProcessDPIAware）：
        // 进程非 DPI-aware 时 GetSystemMetrics 返回缩放后的虚拟值，而 SendInput
        // 绝对坐标始终按物理像素归一——开启缩放的机器上点击会错位 1.25/1.5 倍。
        pub fn SetProcessDpiAwarenessContext(ctx: isize) -> c_int;
        pub fn SetProcessDPIAware() -> c_int;
    }

    // —— 双进程远控（服务 Session 0 → 用户会话助手）：会话/进程 FFI ——
    // 服务以 SCM 在 Session 0 运行，GDI GetDC(null)+BitBlt 只能抓 Session 0 隔离桌面（空/黑），
    // 故远控采集/注入必须在活动用户会话内执行：服务用 WTS 取活动会话令牌，
    // CreateProcessAsUserW 拉起自身 `--rc-helper` 子进程（运行于用户会话），经 127.0.0.1
    // 回环 TCP 中继帧与输入。
    pub type HANDLE = *mut std::os::raw::c_void;
    pub type LPVOID = *mut std::os::raw::c_void;
    pub const WTS_IS_LOCKED: i32 = 27;
    pub const TOKEN_SESSION_ID: i32 = 12;
    pub const TOKEN_PRIMARY: i32 = 1;
    pub const SECURITY_IMPERSONATION: i32 = 2;
    pub const TOKEN_ALL_ACCESS: u32 = 0xF01FF;
    pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;
    pub const CREATE_NEW_CONSOLE: u32 = 0x00000010;
    pub const INFINITE: u32 = 0xFFFFFFFF;

    #[repr(C)]
    pub struct STARTUPINFOW {
        pub cb: u32,
        pub lp_reserved: *mut u16,
        pub lp_desktop: *mut u16,
        pub lp_title: *mut u16,
        pub dw_x: u32,
        pub dw_y: u32,
        pub dw_x_size: u32,
        pub dw_y_size: u32,
        pub dw_x_count_chars: u32,
        pub dw_y_count_chars: u32,
        pub dw_fill_attribute: u32,
        pub dw_flags: u32,
        pub w_show_window: u16,
        pub cb_reserved2: u16,
        pub lp_reserved2: *mut u8,
        pub h_std_input: HANDLE,
        pub h_std_output: HANDLE,
        pub h_std_error: HANDLE,
    }

    #[repr(C)]
    pub struct PROCESS_INFORMATION {
        pub h_process: HANDLE,
        pub h_thread: HANDLE,
        pub dw_process_id: u32,
        pub dw_thread_id: u32,
    }

    extern "system" {
        pub fn WTSGetActiveConsoleSessionId() -> u32;
        pub fn WTSQueryUserToken(session_id: u32, ph_token: *mut HANDLE) -> i32;
        pub fn WTSQuerySessionInformationW(
            h_server: HANDLE,
            session_id: u32,
            wts_info_class: i32,
            pp_buffer: *mut *mut u16,
            p_bytes_returned: *mut u32,
        ) -> i32;
        pub fn WTSFreeMemory(p_memory: HANDLE);
        pub fn DuplicateTokenEx(
            h_existing_token: HANDLE,
            dw_desired_access: u32,
            lp_token_attributes: LPVOID,
            impersonation_level: i32,
            token_type: i32,
            ph_new_token: *mut HANDLE,
        ) -> i32;
        pub fn SetTokenInformation(
            token: HANDLE,
            token_information_class: i32,
            token_information: LPVOID,
            token_information_length: u32,
        ) -> i32;
        pub fn CreateProcessAsUserW(
            h_token: HANDLE,
            lp_application_name: *const u16,
            lp_command_line: *mut u16,
            lp_process_attributes: LPVOID,
            lp_thread_attributes: LPVOID,
            b_inherit_handles: i32,
            dw_creation_flags: u32,
            lp_environment: LPVOID,
            lp_current_directory: *const u16,
            lp_startup_info: *mut STARTUPINFOW,
            lp_process_information: *mut PROCESS_INFORMATION,
        ) -> i32;
        pub fn CloseHandle(h_object: HANDLE) -> i32;
        pub fn TerminateProcess(h_process: HANDLE, u_exit_code: u32) -> i32;
    }
    pub const DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2: isize = -4;
}

/// 键名 → Windows 虚拟键码（VK_*，纯函数便于跨平台单测）。
#[allow(dead_code)] // 非 Windows 主机上仅测试引用
fn vk_of(name: &str) -> Option<u16> {
    Some(match name.to_ascii_lowercase().as_str() {
        "enter" | "return" => 0x0D, // VK_RETURN
        "tab" => 0x09,              // VK_TAB
        "space" => 0x20,            // VK_SPACE
        "backspace" => 0x08,        // VK_BACK
        "delete" => 0x2E,           // VK_DELETE
        "esc" | "escape" => 0x1B,   // VK_ESCAPE
        "left" => 0x25,             // VK_LEFT
        "up" => 0x26,               // VK_UP
        "right" => 0x27,            // VK_RIGHT
        "down" => 0x28,             // VK_DOWN
        "home" => 0x24,             // VK_HOME
        "end" => 0x23,              // VK_END
        "pageup" => 0x21,           // VK_PRIOR
        "pagedown" => 0x22,         // VK_NEXT
        "f1" => 0x70,               // VK_F1
        // 修饰键（React e.key 命名）：Mac Cmd→Win、Ctrl/Alt/Shift 直映。
        // 此前缺失：Cmd+C 的 "Meta" 落到 VkKeyScanW('M') 会真的打出字母 m——
        // 用户按 Mac 快捷键 = 往被控端打乱码。
        "meta" | "cmd" | "command" | "win" | "lwin" => 0x5B, // VK_LWIN
        "control" | "ctrl" => 0x11, // VK_CONTROL
        "alt" | "option" => 0x12,   // VK_MENU
        "shift" => 0x10,            // VK_SHIFT
        "capslock" => 0x14,         // VK_CAPITAL
        "insert" => 0x2D,           // VK_INSERT
        _ => return None,
    })
}

// ===================== 远控会话 =====================

static RC_STOP: AtomicBool = AtomicBool::new(false);
/// 会话代次：每次 start_rc/stop_rc 递增；帧循环仅当代次仍为 captured 值时继续，
/// 防止上一次会话的帧线程在新会话开始后残留（连续会话场景）。
static RC_GEN: AtomicU64 = AtomicU64::new(0);
/// 当前会话 ID（ICE-lite 候选消费时回事件用）；stop 后清空。
static RC_SESSION: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
/// 主端选择了 p2p 传输：即使首跳 dial 失败也保持等待，候选地址（rc_offer/rc_candidate）
/// 到达后逐个尝试，全部失败才维持中枢中继（ICE-lite 单侧监听模型：viewer 监听、agent 拨号）。
static RC_WANT_P2P: AtomicBool = AtomicBool::new(false);
/// 协商目标尺寸（§8.3.7 性能）：capabilities.max_w/h 与实际采集分辨率保比取偶的结果。
/// RAW/原生路径按此降采样后送编码；原生编码器会话按同一尺寸创建（create(codec,w,h)）。
static RC_TARGET: std::sync::Mutex<Option<(u32, u32)>> = std::sync::Mutex::new(None);
/// 主端 QoS 反馈的目标帧率（§8.3.9 带宽自适应闭环）：rc_qos 到达后覆盖 capabilities.fps，
/// 帧循环逐轮读取（会话中途可动态升降）；0 = 未设置（用默认）。新会话开始时清零。
static RC_FPS_QOS: AtomicU64 = AtomicU64::new(0);
/// 主端实测媒体路径 RTT（ms，§8.3.11）；0 = 未知/未探测（不夹上限）。
static RC_RTT_MS: AtomicU64 = AtomicU64::new(0);
/// 主端实测丢帧率（%，§8.3.15，帧序号缺口统计）；0 = 无丢包/未上报。
static RC_LOSS_PCT: AtomicU64 = AtomicU64::new(0);
/// 连续无丢包的 rc_qos 报告次数（§8.3.15 码率恢复升档节流：连续 3 次才升一档）。
static RC_LOSS_CLEAR: AtomicU64 = AtomicU64::new(0);
/// 码率目标（kbps，§8.3.15）；0 = 未设置（编码器用默认码率）。
static RC_KBPS_TARGET: AtomicU64 = AtomicU64::new(0);
/// 已应用到编码器的码率目标（kbps）；仅用于检测变化避免重复调用原生 set_bitrate。
static RC_KBPS_APPLIED: AtomicU64 = AtomicU64::new(0);
/// JPEG 路径动态质量（§8.3.15 码率闭环换算）；新会话恢复 80（内置编码器默认档）。
static RC_JPEG_Q: AtomicU64 = AtomicU64::new(80);

// ===================== P2P / 二进制帧媒体环（§8.3 运行时接入） =====================

/// 媒体通道：rc_select 协商的产物。
/// - P2p：与主端的直连 TCP（dial_direct 成功；主端 Tauri/原生客户端监听媒体端口）。
/// - Relay：经中枢长连接的二进制 WS 帧中继（P2P 不可达时的兜底；浏览器主端固定走此路径，
///   浏览器无法监听裸 TCP，故 rc.html 只发 transport=relay 的 rc_select）。
enum MediaChannel {
    P2p {
        stream: std::net::TcpStream,
        codec: u8,
        encoder: Box<dyn Encoder>,
    },
    Relay {
        codec: u8,
        encoder: Box<dyn Encoder>,
    },
}

/// 当前会话的媒体通道；None = 未协商二进制通道，帧循环走 JSON rc_frame 兜底（M4 MVP 兼容）。
static RC_MEDIA: std::sync::Mutex<Option<MediaChannel>> = std::sync::Mutex::new(None);

impl MediaChannel {
    fn codec(&self) -> u8 {
        match self {
            MediaChannel::P2p { codec, .. } | MediaChannel::Relay { codec, .. } => *codec,
        }
    }
    fn encoder_mut(&mut self) -> &mut Box<dyn crate::rc_media::Encoder> {
        match self {
            MediaChannel::P2p { encoder, .. } | MediaChannel::Relay { encoder, .. } => encoder,
        }
    }
}

/// 当前媒体通道是否要求 RAW/原生码流（即帧循环须采集 RGBA 而非 JPEG）。
fn media_wants_raw() -> bool {
    match RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        Some(ch) => ch.codec() != crate::rc_media::CODEC_JPEG,
        None => false,
    }
}

/// 当前是否已建立 P2P 直连通道。
fn has_p2p() -> bool {
    matches!(RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()).as_ref(), Some(MediaChannel::P2p { .. }))
}

/// 协商编解码器：把主端选择收敛到运行时可产出集（诚实回退，不造假帧）。
/// - rgba_ok：RGBA 采集源可用（capture_rgba 探测）；
/// - native_ok：原生编码器库可加载该编解码器（NativeEncoder::try_load 探测）。
fn clamp_runtime_codec(want: u8, rgba_ok: bool, native_ok: bool) -> u8 {
    match want {
        crate::rc_media::CODEC_JPEG => crate::rc_media::CODEC_JPEG,
        crate::rc_media::CODEC_RAW_RGBA if rgba_ok => crate::rc_media::CODEC_RAW_RGBA,
        c if crate::rc_media::is_native_codec(c) && rgba_ok && native_ok => c,
        _ => {
            eprintln!(
                "[agent] 编解码器 {} 运行时不可产出（rgba_ok={} native_ok={}），回退 jpeg",
                crate::rc_media::codec_name(want),
                rgba_ok,
                native_ok
            );
            crate::rc_media::CODEC_JPEG
        }
    }
}

/// 原生编码器可用性探测：库已配置且能创建该编解码器句柄（进程级缓存，含预热）。
fn native_encoder_ok(codec: u8) -> bool {
    crate::rc_media::is_native_codec(codec) && crate::rc_media::native_probe_cached(codec)
}

/// 协商目标尺寸：capabilities.max_w/h 与实际采集分辨率保比取偶。
/// 未探测到采集分辨率时返回 None（帧循环按原尺寸发送）。
fn target_dims() -> Option<(u32, u32)> {
    *RC_TARGET.lock().unwrap_or_else(|p| p.into_inner())
}

/// 处理 rc_select（主端协商结果，§8.3）：
/// 1) 按主端选择协商编解码器（clamp 到运行时可产出集，回退时明确告知）；
/// 2) transport=p2p 时 dial_direct 主端媒体地址，失败不放弃——保持 RC_WANT_P2P，
///    等待 rc_offer/rc_candidate 候选到达后逐个尝试（ICE-lite）；
/// 3) 落通道并以 rc_event(media_selected) 告知主端实际通道。
pub fn handle_rc_select(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    session_id: &str,
    p: &crate::Json,
) {
    let want_codec = p
        .get("codec")
        .and_then(|v| v.as_i64())
        .unwrap_or(crate::rc_media::CODEC_JPEG as i64) as u8;
    let transport = p.get("transport").and_then(|v| v.as_str()).unwrap_or("relay");
    let media_addr = p.get("media_addr").and_then(|v| v.as_str()).unwrap_or("");

    // 能力探测（各一次）：RGBA 采集源（顺带定协商目标尺寸）+ 原生编码器库
    let rgba_ok = probe_rgba_set_target();
    let native_ok = native_encoder_ok(want_codec);
    let codec = clamp_runtime_codec(want_codec, rgba_ok, native_ok);
    if codec != want_codec {
        send_rc_event(
            writer,
            rng,
            seq,
            session_id,
            "notice",
            &format!(
                "编解码器 {} 本机不可产出，已回退 {}",
                crate::rc_media::codec_name(want_codec),
                crate::rc_media::codec_name(codec)
            ),
            false,
            false,
        );
    }
    let (tw, th) = target_dims().unwrap_or((0, 0));
    if tw > 0 {
        eprintln!(
            "[agent] 协商目标分辨率 {}x{}（capabilities 上限内保比取偶）",
            tw, th
        );
    }

    RC_WANT_P2P.store(transport == "p2p" && !media_addr.is_empty(), Ordering::SeqCst);

    let mut channel: Option<MediaChannel> = None;
    if transport == "p2p" && !media_addr.is_empty() {
        match crate::rc_media::dial_direct(media_addr) {
            Ok(stream) => {
                eprintln!(
                    "[agent] P2P 媒体直连成功 {} codec={}",
                    media_addr,
                    crate::rc_media::codec_name(codec)
                );
                channel = Some(MediaChannel::P2p { stream, codec, encoder: make_encoder(codec, tw, th) });
            }
            Err(e) => {
                eprintln!("[agent] P2P 首跳直连失败({})，等待 ICE-lite 候选/回退中枢中继", e);
            }
        }
    }
    let via_p2p = channel.is_some();
    if channel.is_none() {
        channel = Some(MediaChannel::Relay { codec, encoder: make_encoder(codec, tw, th) });
    }
    *RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()) = channel;

    let via = if via_p2p { "p2p 直连" } else { "中枢二进制中继" };
    send_rc_event(
        writer,
        rng,
        seq,
        session_id,
        "media_selected",
        &format!("媒体通道就绪：{} + {}", via, crate::rc_media::codec_name(codec)),
        false,
        false,
    );
}

/// 尝试用候选地址升级/建立 P2P 直连（ICE-lite：viewer 监听、agent 拨号）。
/// 成功则替换当前媒体通道（保留协商 codec）；失败仅记录，维持现有通道（中继兜底）。
fn try_candidate(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    session_id: &str,
    candidate: &str,
) -> bool {
    if !RC_WANT_P2P.load(Ordering::SeqCst) || has_p2p() {
        return false;
    }
    match crate::rc_media::dial_direct(candidate) {
        Ok(stream) => {
            let codec = current_codec();
            let (tw, th) = target_dims().unwrap_or((0, 0));
            eprintln!(
                "[agent] P2P 候选直连成功 {} codec={}",
                candidate,
                crate::rc_media::codec_name(codec)
            );
            *RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(MediaChannel::P2p { stream, codec, encoder: make_encoder(codec, tw, th) });
            send_rc_event(
                writer,
                rng,
                seq,
                session_id,
                "media_selected",
                &format!("媒体通道就绪：p2p 候选直连 {} + {}", candidate, crate::rc_media::codec_name(codec)),
                false,
                false,
            );
            true
        }
        Err(e) => {
            eprintln!("[agent] P2P 候选 {} 拨号失败({})", candidate, e);
            false
        }
    }
}

/// 当前通道 codec（无通道时默认 JPEG）。
fn current_codec() -> u8 {
    match RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        Some(ch) => ch.codec(),
        None => crate::rc_media::CODEC_JPEG,
    }
}

/// 处理 rc_offer：主端批量上报候选地址（§8.3 ICE-lite），逐个尝试直连。
pub fn handle_rc_offer(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    p: &crate::Json,
) {
    let session = RC_SESSION.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_default();
    let cands: Vec<String> = match p.get("candidates") {
        Some(crate::Json::Arr(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    };
    if cands.is_empty() {
        return;
    }
    for c in cands {
        if try_candidate(writer, rng, seq, &session, &c) {
            break;
        }
    }
}

/// 处理 rc_candidate：主端增量上报单个候选地址（§8.3 ICE-lite）。
pub fn handle_rc_candidate(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    p: &crate::Json,
) {
    let session = RC_SESSION.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_default();
    if let Some(c) = p.get("candidate").and_then(|v| v.as_str()) {
        try_candidate(writer, rng, seq, &session, c);
    }
}

/// 处理 rc_qos：主端反馈的目标帧率（§8.3.9 带宽自适应闭环）+ 实测 RTT（§8.3.11）。
/// 夹取规则：1..=120 fps 之外（含 0/负数/非数字）不应用本条反馈（保留当前值），
/// 避免主端异常载荷把帧循环打到忙轮询或归零；fps=0 语义为「恢复默认」→ 清覆盖。
/// rtt_ms 合法区间 0..=60000（超出忽略）；帧循环取 min(目标 fps, RTT 档位上限)。
/// 帧循环逐轮读取该值，故会话中途升降立即生效，无需重建通道。
pub fn handle_rc_qos(p: &crate::Json) {
    let fps = p.get("fps").and_then(|v| v.as_i64());
    let reason = p.get("reason").and_then(|v| v.as_str()).unwrap_or("unspecified");
    match fps {
        Some(0) => {
            RC_FPS_QOS.store(0, Ordering::SeqCst);
            eprintln!("[agent] rc_qos：主端请求恢复默认帧率（reason={}）", reason);
        }
        Some(f) if f >= 1 && f <= 120 => {
            RC_FPS_QOS.store(f as u64, Ordering::SeqCst);
            eprintln!(
                "[agent] rc_qos：主端反馈目标 {} fps（reason={}，间隔预算 {}ms）",
                f, reason, 1000 / f as u64
            );
        }
        other => {
            eprintln!("[agent] rc_qos：忽略越界反馈 fps={:?}（合法区间 1..=120，0=恢复默认）", other);
        }
    }
    // §8.3.11 传输级自适应：主端探测的媒体路径 RTT → 档位上限（与 fps 反馈独立生效）。
    if let Some(rtt) = p.get("rtt_ms").and_then(|v| v.as_i64()) {
        if (0..=60_000).contains(&rtt) {
            let prev = RC_RTT_MS.swap(rtt as u64, Ordering::SeqCst);
            match (rtt_cap_fps(rtt as u64), rtt_cap_fps(prev)) {
                (Some(now), Some(old)) if now != old => {
                    eprintln!("[agent] rc_qos：RTT {}ms → 帧率上限 {} fps（原 {} fps）", rtt, now, old);
                }
                (Some(cap), None) => {
                    eprintln!("[agent] rc_qos：RTT {}ms → 帧率上限 {} fps（原无限制）", rtt, cap);
                }
                (None, Some(_)) => {
                    eprintln!("[agent] rc_qos：RTT {}ms → 网络良好，解除帧率上限", rtt);
                }
                _ => {}
            }
        }
    }
    // §8.3.15 丢包档位：主端按帧序号缺口统计的丢帧率 → 帧率上限（与 RTT 档位取 min）。
    let mut loss_val: Option<u64> = None;
    if let Some(loss) = p.get("loss_pct").and_then(|v| v.as_i64()) {
        if (0..=100).contains(&loss) {
            loss_val = Some(loss as u64);
            let prev = RC_LOSS_PCT.swap(loss as u64, Ordering::SeqCst);
            match (loss_cap_fps(loss as u64), loss_cap_fps(prev)) {
                (Some(now), Some(old)) if now != old => {
                    eprintln!("[agent] rc_qos：丢包 {}% → 帧率上限 {} fps（原 {} fps）", loss, now, old);
                }
                (Some(cap), None) => {
                    eprintln!("[agent] rc_qos：丢包 {}% → 帧率上限 {} fps（原无限制）", loss, cap);
                }
                (None, Some(_)) => {
                    eprintln!("[agent] rc_qos：丢包 {}% → 网络良好，解除丢包帧率上限", loss);
                }
                _ => {}
            }
        }
    }
    // §8.3.15 码率重参数化：丢包降档 / 连续恢复升档；目标变化时由帧循环在编码
    // 同线程应用（原生 set_bitrate；JPEG 路径换算为质量闭环）。
    if let Some(loss) = loss_val {
        let measured = p
            .get("kbps")
            .and_then(|v| v.as_i64())
            .filter(|v| *v > 0)
            .map(|v| v as u64)
            .unwrap_or(0);
        let prev = RC_KBPS_TARGET.load(Ordering::SeqCst);
        let streak = RC_LOSS_CLEAR.load(Ordering::SeqCst);
        let (next, new_streak) = next_target_kbps(prev, measured, loss, streak);
        RC_LOSS_CLEAR.store(new_streak, Ordering::SeqCst);
        if next != prev {
            RC_KBPS_TARGET.store(next, Ordering::SeqCst);
            eprintln!(
                "[agent] rc_qos：码率目标 {} kbps（原 {}，实测 {} kbps，丢包 {}%）",
                next, prev, measured, loss
            );
        }
    }
}

/// 处理 rc_ping：主端 RTT 探测（§8.3.11）。原样回显 t0，主端 RTT = now - t0。
pub fn handle_rc_ping(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    p: &crate::Json,
) {
    let session = RC_SESSION.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_default();
    let t0 = p.get("t0").and_then(|v| v.as_i64()).unwrap_or(0);
    let payload = format!(
        "{{\"session_id\":{},\"t0\":{}}}",
        json_string(&session),
        t0
    );
    let msg = {
        let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
        let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
        crate::build_envelope(&mut rng_g, &mut seq_g, "rc_pong", &payload)
    };
    let _ = send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes());
}

/// 二进制媒体帧发送结果。
enum SendOutcome {
    /// 已按协商通道作为二进制帧发送。
    Sent,
    /// 无媒体通道（未协商/已回退），调用方走 JSON 兜底。
    NoChannel,
    /// 采集早于协商完成（首帧竞态）：载荷种类与通道编解码器不匹配，本帧丢弃、
    /// 下一轮按已协商通道重新采集。不得当作 Broken——否则会误清刚协商好的通道。
    Recapture,
    /// 通道损坏（编码失败/发送失败），调用方应清通道并回退 JSON。
    Broken,
}

/// 屏幕帧头：stream=屏幕、关键帧、seq/宽高/pts（小端 24B 头由 encode_frame 序列化）。
fn screen_header(codec: u8, w: usize, h: usize, seq: i64, pts_ms: u32) -> FrameHeader {
    FrameHeader {
        stream: crate::rc_media::STREAM_SCREEN,
        codec,
        flags: crate::rc_media::FLAG_KEYFRAME,
        seq: seq as u32,
        width: w as u16,
        height: h as u16,
        pts_ms,
    }
}

/// 将一帧采集画面按协商 codec 编码为二进制帧并按通道发送（P2P 直连 / 中枢二进制中继）。
fn send_media_frame(
    writer: &Writer,
    data: &[u8],
    w: usize,
    h: usize,
    seq: i64,
    pts_ms: u32,
    is_raw: bool,
) -> SendOutcome {
    let mut guard = RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner());
    // 载荷种类必须与通道编解码器一致：JPEG 通道收 JPEG，其余（RAW/原生）收 RGBA。
    // 若不一致说明本帧采集早于 rc_select 协商完成（首帧竞态），丢弃本帧让下一轮重采——
    // 强行编码会把 JPEG 字节塞进 H.264 编码器（缓冲区怎么扩都不可能对），必须在此拦截。
    let ch_codec = match guard.as_ref() {
        None => return SendOutcome::NoChannel,
        Some(ch) => ch.codec(),
    };
    if is_raw != (ch_codec != crate::rc_media::CODEC_JPEG) {
        return SendOutcome::Recapture;
    }
    // §8.3.15 码率重参数化：目标变化时在编码同线程应用（MF 等 COM 约束要求
    // create/encode/set_bitrate 同线程），原生编码器经可选导出生效；JPEG 路径
    // 走质量闭环（见帧循环），RAW 无码率概念不适用。
    let want_kbps = RC_KBPS_TARGET.load(Ordering::SeqCst);
    if want_kbps > 0 && RC_KBPS_APPLIED.load(Ordering::SeqCst) != want_kbps {
        guard
            .as_mut()
            .map(|ch| ch.encoder_mut().set_bitrate(want_kbps));
        RC_KBPS_APPLIED.store(want_kbps, Ordering::SeqCst);
        eprintln!("[agent] 原生编码器码率重参数化 → {} kbps", want_kbps);
    }
    match guard.as_mut() {
        None => SendOutcome::NoChannel,
        Some(MediaChannel::P2p { stream, codec, encoder }) => {
            let payload = match encoder.encode(data, w as u32, h as u32) {
                Ok(p) => p,
                Err(e) => {
                    // 诊断留痕：原生编码失败必须能看到"送进去的是什么"，否则无法判断
                    // 是编码器库问题还是采集/降采样尺寸不符（曾因此误判为缓冲区不足）。
                    eprintln!(
                        "[agent] 媒体帧编码失败({})，回退 JSON 中继 [P2P data={}B {}x{} codec={}]",
                        e, data.len(), w, h, crate::rc_media::codec_name(*codec)
                    );
                    return SendOutcome::Broken;
                }
            };
            let frame = encode_frame(&screen_header(*codec, w, h, seq, pts_ms), &payload);
            match crate::rc_media::send_frame(stream, &frame) {
                Ok(()) => SendOutcome::Sent,
                Err(e) => {
                    eprintln!("[agent] P2P 帧发送失败({})，回退 JSON 中继", e);
                    SendOutcome::Broken
                }
            }
        }
        Some(MediaChannel::Relay { codec, encoder }) => {
            let payload = match encoder.encode(data, w as u32, h as u32) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "[agent] 媒体帧编码失败({})，回退 JSON 中继 [relay data={}B {}x{} codec={}]",
                        e, data.len(), w, h, crate::rc_media::codec_name(*codec)
                    );
                    return SendOutcome::Broken;
                }
            };
            let frame = encode_frame(&screen_header(*codec, w, h, seq, pts_ms), &payload);
            match send_ws_binary(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), &frame) {
                Ok(()) => SendOutcome::Sent,
                Err(e) => {
                    eprintln!("[agent] 二进制帧中继发送失败({})，回退 JSON 中继", e);
                    SendOutcome::Broken
                }
            }
        }
    }
}

/// 开启远控：合规提示 → rc_ready → 500ms 帧循环，直至 stop。
pub fn start_rc(writer: Writer, rng: Arc<Mutex<crate::Lcg>>, seq: Arc<Mutex<u64>>, session_id: String, _device_id: String) {
    RC_STOP.store(false, Ordering::SeqCst);
    let gen = RC_GEN.fetch_add(1, Ordering::SeqCst) + 1; // 新会话代次（旧帧线程随之失效）
    RC_WANT_P2P.store(false, Ordering::SeqCst);
    RC_RTT_MS.store(0, Ordering::SeqCst); // 新会话 RTT 未知，等主端重新探测
    *RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()) = None; // 新会话重新协商媒体通道
    *RC_TARGET.lock().unwrap_or_else(|p| p.into_inner()) = None; // 新会话重新探测目标分辨率
    RC_FPS_QOS.store(0, Ordering::SeqCst); // 新会话清主端 QoS 反馈（恢复默认帧率）
    RC_LOSS_PCT.store(0, Ordering::SeqCst); // §8.3.15：新会话丢包/码率目标复位
    RC_LOSS_CLEAR.store(0, Ordering::SeqCst);
    RC_KBPS_TARGET.store(0, Ordering::SeqCst);
    RC_KBPS_APPLIED.store(0, Ordering::SeqCst);
    RC_JPEG_Q.store(80, Ordering::SeqCst);
    *RC_SESSION.lock().unwrap_or_else(|p| p.into_inner()) = Some(session_id.clone());

    // 合规：本地通知 + 事件（员工知情可拒绝；开发态自动授权见 rc_event）
    show_remote_notice();
    send_rc_event(&writer, &rng, &seq, &session_id, "consent_required",
        "管理员请求远程控制本机，您可拒绝", true, false);
    // Windows：远控采集/注入必须在用户会话执行。先拉起助手进程；失败则带原因上报并不启动帧循环。
    #[cfg(target_os = "windows")]
    {
        match rc_helper::start_for_session() {
            Ok(()) => {}
            Err(ref reason) => {
                send_rc_ready(&writer, &rng, &seq, &session_id, false, reason);
                return;
            }
        }
    }
    send_rc_ready(&writer, &rng, &seq, &session_id, true, "");

    // 光标形状流式下发（高频位置由主端本地渲染，副端只发形状变化）。
    spawn_cursor_thread(writer.clone(), rng.clone(), seq.clone(), session_id.clone(), gen);

    // 生产化（§8.3）：宣告远控媒体能力（编解码器 / 分辨率 / 帧率），供主端协商 P2P 二进制帧通道。
    // 载荷扁平（与 protocol.md §8.3 / Go proto.RCCapabilitiesPayload 一致）。
    let caps = default_capabilities().to_payload_fields();
    send_rc_capabilities(&writer, &rng, &seq, &session_id, &caps);

    thread::spawn(move || {
        let started = std::time::Instant::now();
        let mut frame_seq: i64 = 0;
        // 可变帧率（§8.3.7/§8.3.9）：目标帧率优先级 = rc_qos 主端反馈 → YUDUAN_RC_FPS → capabilities.fps。
        // 原实现每轮固定 sleep 500ms，实际帧率 = 1/(0.5s + 采集编码耗时)， negotiated fps 形同虚设；
        // 改为「到点出帧」：每轮结束算出下一帧截止时刻，sleep 只补足剩余预算——
        // 采集/编码慢时自然降帧（不叠加延迟），机器空闲时贴合目标帧率。
        // 间隔逐轮重算：主端 rc_qos 反馈（带宽/解码能力自适应）会话中途升降立即生效。
        let interval_ms = rc_frame_interval_ms();
        if interval_ms <= 500 {
            eprintln!("[agent] 远控帧率目标 {} fps（间隔预算 {}ms；YUDUAN_RC_FPS 可调）",
                1000 / interval_ms.max(1), interval_ms);
        } else {
            eprintln!("[agent] 远控帧率目标 {:.1} fps（间隔预算 {}ms；YUDUAN_RC_FPS 可调）",
                1000.0 / interval_ms as f64, interval_ms);
        }
        let mut next_tick = Instant::now() + Duration::from_millis(interval_ms);
        let mut cost_acc = Duration::from_millis(0);
        // 采集连续失败计数：Windows 上 GDI 首帧可能瞬时失败（会话切换/锁屏），
        // 旧实现一失败就 break——会话变成永久黑屏且 viewer 无提示。
        // 改为限频上报 + 1s 重试；连续 30 次（≈30s）仍失败才放弃本会话帧循环。
        let mut cap_fail: u32 = 0;
        // 代次守卫：新会话开始或 stop 后，旧帧循环立即退出（不残留）。
        while RC_GEN.load(Ordering::SeqCst) == gen && !RC_STOP.load(Ordering::SeqCst) {
            let now = Instant::now();
            if next_tick > now {
                thread::sleep(next_tick - now);
            }
            let tick = Instant::now();
            // 逐轮重算间隔：主端 rc_qos 可能在上一帧处理期间到达（§8.3.9）。
            let interval_ms = rc_frame_interval_ms();
            next_tick = tick + Duration::from_millis(interval_ms);
            if RC_GEN.load(Ordering::SeqCst) != gen || RC_STOP.load(Ordering::SeqCst) {
                break;
            }
            frame_seq += 1;
            // 采集源随协商 codec 切换：JPEG 走采集工具；RAW/原生须 RGBA 采集源（§8.3.6）。
            let raw_mode = media_wants_raw();
            // W2-3 画面控制（黑屏/水印）：
            // - 黑屏：不采集真实画面（防窥视），沿用最近尺寸发纯黑帧——会话不中断、控制权保留；
            // - 水印：必须取 RGBA 源叠加后再编码（JPEG 路径同样 RGBA→内置编码器，不伪造帧）。
            let disp = crate::rc_wave2::display_active();
            let cap: Option<(Vec<u8>, usize, usize)> = if let Some(f) = relay_frame() {
                Some(f)
            } else if disp && crate::rc_wave2::blank_active() {
                Some(crate::rc_wave2::blank_frame())
            } else if disp {
                match capture_rgba() {
                    Some((rgba, w, h)) => {
                        let (tw, th) = target_dims().map(|(a, b)| (a as usize, b as usize)).unwrap_or((w, h));
                        let (rgba, w, h) = if tw > 0 && (tw, th) != (w, h) {
                            (crate::rc_media::downscale_rgba(&rgba, w as u32, h as u32, tw as u32, th as u32), tw, th)
                        } else {
                            (rgba, w, h)
                        };
                        let out = crate::rc_wave2::apply_display(rgba, w, h);
                        if raw_mode {
                            Some((out, w, h))
                        } else {
                            crate::jpegenc::encode_rgba(&out, w as u32, h as u32, RC_JPEG_Q.load(Ordering::SeqCst).clamp(10, 95) as u32)
                                .map(|j| (j, w, h))
                        }
                    }
                    None => None,
                }
            } else if raw_mode {
                capture_rgba()
            } else {
                capture_jpeg()
            };
            let (data, w, h) = match cap {
                Some(t) => {
                    if cap_fail > 0 {
                        eprintln!("[agent] 屏幕采集恢复（此前连续失败 {} 次）", cap_fail);
                    }
                    cap_fail = 0;
                    // 记录真实采集尺寸：黑屏帧沿用，避免主端画面尺寸跳变。
                    crate::rc_wave2::note_dims(t.1, t.2);
                    t
                }
                None => {
                    cap_fail += 1;
                    if cap_fail == 1 || cap_fail % 10 == 0 {
                        eprintln!("[agent] 屏幕采集失败（连续第 {} 次），1s 后重试", cap_fail);
                        send_rc_event(&writer, &rng, &seq, &session_id, "notice",
                            if raw_mode {
                                "RGBA 采集不可用（缺屏幕录制权限/显示服务），重试中…"
                            } else {
                                "屏幕采集不可用（缺采集通道或权限），重试中…"
                            }, false, false);
                    }
                    if cap_fail >= 30 {
                        eprintln!("[agent] 屏幕采集连续失败 30 次，结束本会话帧循环");
                        break;
                    }
                    thread::sleep(Duration::from_secs(1));
                    next_tick = Instant::now() + Duration::from_millis(interval_ms);
                    continue;
                }
            };
            // 性能（§8.3.7）：RAW/原生路径按协商目标分辨率降采样（JPEG 工具链路径保持原样）。
            // 画面控制路径（disp）已在前一步完成降采样，此处不再重复处理。
            let (data, w, h) = if raw_mode && !disp {
                match target_dims() {
                    Some((tw, th)) if tw > 0 && (tw as usize != w || th as usize != h) => {
                        let scaled = crate::rc_media::downscale_rgba(&data, w as u32, h as u32, tw, th);
                        (scaled, tw as usize, th as usize)
                    }
                    _ => (data, w, h),
                }
            } else {
                (data, w, h)
            };
            // §8.3.15 JPEG 码率闭环：按码率目标换算单帧字节预算，动态调质量（下帧生效）。
            // 仅作用于 JPEG 通道 / 未协商（JSON 兜底）帧——原生会话启动期的预采帧不适用。
            if !raw_mode
                && matches!(
                    RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()).as_ref(),
                    None | Some(MediaChannel::Relay { codec: crate::rc_media::CODEC_JPEG, .. })
                        | Some(MediaChannel::P2p { codec: crate::rc_media::CODEC_JPEG, .. })
                )
            {
                let target = RC_KBPS_TARGET.load(Ordering::SeqCst);
                if target > 0 {
                    let budget = target * interval_ms / 8; // kbps×ms/8 ≈ 字节/帧
                    let prev_q = RC_JPEG_Q.load(Ordering::SeqCst);
                    let q = next_jpeg_q(prev_q, data.len(), budget);
                    if q != prev_q {
                        RC_JPEG_Q.store(q, Ordering::SeqCst);
                        eprintln!(
                            "[agent] 码率闭环：目标 {} kbps 预算 {} B/帧，上帧 {} B → 质量 {}→{}",
                            target, budget, data.len(), prev_q, q
                        );
                    }
                }
            }
            // 二进制媒体环（§8.3）：已协商通道 → 按协商 codec 编码采集帧 → 二进制帧。
            match send_media_frame(&writer, &data, w, h, frame_seq, started.elapsed().as_millis() as u32, raw_mode) {
                SendOutcome::Sent => continue,
                SendOutcome::Recapture => {
                    // 采集早于协商：本帧丢弃（不回退、不清通道），下一轮按已协商 codec 重采。
                    frame_seq -= 1; // 不计入有效帧序号
                    continue;
                }
                SendOutcome::Broken => {
                    // 通道损坏：清空回退 JSON 中继（会话不中断）
                    *RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()) = None;
                    send_rc_event(&writer, &rng, &seq, &session_id, "notice",
                        "媒体通道中断，已回退 JSON 中继", false, false);
                    if raw_mode {
                        continue; // RGBA 数据不能冒充当 JPEG；下一轮回采 JPEG 走 JSON 兜底
                    }
                }
                SendOutcome::NoChannel => {
                    if raw_mode {
                        continue; // 协商为非 JPEG 但通道已消失：下一轮回采 JPEG 走 JSON 兜底
                    }
                }
            }
            // JSON rc_frame 兜底（未协商二进制通道时，M4 MVP 兼容）
            let payload = rc_frame_payload(&session_id, frame_seq, w, h, &data);
            let msg = {
                let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
                let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
                crate::build_envelope(&mut rng_g, &mut seq_g, "rc_frame", &payload)
            };
            if let Err(e) = send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes()) {
                eprintln!("[agent] rc_frame 发送失败: {}", e);
                break;
            }
            // 出帧成本统计：每 30 帧打印一次实际平均帧率与单帧成本，便于判断
            // 目标帧率是否可达（采集/编码慢时自动降帧，不叠加延迟）。
            cost_acc += tick.elapsed();
            if frame_seq % 30 == 0 {
                let cost = cost_acc.as_secs_f64() / 30.0;
                eprintln!(
                    "[agent] 远控帧统计 seq={} 单帧成本 {:.0}ms 实际 {:.1}fps（目标 {}ms/帧）",
                    frame_seq, cost * 1000.0, 1.0 / cost.max(1e-6), interval_ms
                );
                cost_acc = Duration::from_millis(0);
            }
        }
        eprintln!("[agent] rc 会话结束 {}", session_id);
    });
}

/// 远控目标帧间隔（ms）：优先级 rc_qos 主端反馈（§8.3.9）→ YUDUAN_RC_FPS → capabilities.fps，
/// 再与 RTT 档位上限（§8.3.11）取 min。下限 1ms 防零除/忙轮询；帧循环逐轮调用。
pub(crate) fn rc_frame_interval_ms() -> u64 {
    let qos = RC_FPS_QOS.load(Ordering::SeqCst);
    let fps = if qos > 0 {
        qos
    } else {
        std::env::var("YUDUAN_RC_FPS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or_else(|| crate::rc_media::default_capabilities().fps.max(1) as u64)
    };
    let rtt = RC_RTT_MS.load(Ordering::SeqCst);
    let fps = if rtt > 0 {
        fps.min(rtt_cap_fps(rtt).unwrap_or(fps))
    } else {
        fps
    };
    // §8.3.15 丢包档位：与 RTT 档位取 min（两个独立信号，任一拥塞即生效）。
    let loss = RC_LOSS_PCT.load(Ordering::SeqCst);
    let fps = if loss > 0 {
        fps.min(loss_cap_fps(loss).unwrap_or(fps))
    } else {
        fps
    };
    (1000 / fps).max(1)
}

/// RTT → 帧率上限档位（§8.3.11 传输级自适应）。None = 网络良好不夹。
/// 档位：≤80ms 不限；≤200ms 15fps；≤400ms 8fps；>400ms 4fps（跨中继两跳 + 解码余量）。
fn rtt_cap_fps(rtt_ms: u64) -> Option<u64> {
    if rtt_ms <= 80 {
        None
    } else if rtt_ms <= 200 {
        Some(15)
    } else if rtt_ms <= 400 {
        Some(8)
    } else {
        Some(4)
    }
}

/// 丢包率 → 帧率上限档位（§8.3.15）。None = 无丢包/轻微丢包不夹。
/// 档位：≤2% 不限；≤5% 15fps；≤10% 8fps；>10% 4fps。
fn loss_cap_fps(loss_pct: u64) -> Option<u64> {
    if loss_pct <= 2 {
        None
    } else if loss_pct <= 5 {
        Some(15)
    } else if loss_pct <= 10 {
        Some(8)
    } else {
        Some(4)
    }
}

/// 编码器默认码率档（kbps）：与 encoder-mf/encoder-vt 的 YUDUAN_ENC_KBPS 默认值一致，
/// 同时作为码率升档上限（自适应只降不超默认，需要更高码率由管理员显式配置编码器）。
const DEFAULT_TARGET_KBPS: u64 = 4000;
const MIN_TARGET_KBPS: u64 = 300;

/// 码率目标阶梯（§8.3.15）。返回 (新目标, 新的连续无丢包计数)。
///   - 丢包 ≥1%：降档 ×0.8（下限 300 kbps）；基准 = 当前目标 → 实测码率 → 默认 4000。
///   - 无丢包且已有目标且连续 3 次报告无丢包：升档 ×1.25（上限 4000），计数清零。
///   - 其余保持原值（prev=0 表示编码器用默认码率，不主动抬高）。
fn next_target_kbps(prev: u64, measured_kbps: u64, loss_pct: u64, clear_streak: u64) -> (u64, u64) {
    if loss_pct >= 1 {
        let base = if prev > 0 {
            prev
        } else if measured_kbps > 0 {
            measured_kbps
        } else {
            DEFAULT_TARGET_KBPS
        };
        ((base * 4 / 5).max(MIN_TARGET_KBPS), 0)
    } else if prev > 0 && prev < DEFAULT_TARGET_KBPS && clear_streak >= 3 {
        ((prev * 5 / 4).min(DEFAULT_TARGET_KBPS), 0)
    } else {
        (prev, clear_streak + 1)
    }
}

/// JPEG 质量闭环（§8.3.15）：把码率目标换算为单帧字节预算（kbps × 间隔ms / 8 ≈ 字节），
/// 上帧超出预算 → 质量降 10（下限 30）；低于预算一半 → 升 5（上限 92）；其余不变。
/// budget=0（未设目标）不调节。
fn next_jpeg_q(prev_q: u64, frame_len: usize, budget_bytes: u64) -> u64 {
    if budget_bytes == 0 {
        return prev_q;
    }
    if frame_len as u64 > budget_bytes {
        prev_q.saturating_sub(10).max(30)
    } else if frame_len as u64 * 2 < budget_bytes {
        (prev_q + 5).min(92)
    } else {
        prev_q
    }
}

/// 当前会话 ID（供 wave2 模块回告事件使用）；无活动会话返回空串。
pub fn current_session_id() -> String {
    RC_SESSION.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_default()
}

pub fn stop_rc() {
    RC_STOP.store(true, Ordering::SeqCst);
    RC_GEN.fetch_add(1, Ordering::SeqCst); // 使旧帧循环代次失效
    RC_WANT_P2P.store(false, Ordering::SeqCst);
    *RC_SESSION.lock().unwrap_or_else(|p| p.into_inner()) = None;
    // 关闭 P2P 直连（drop TcpStream）并清通道，下次 start_rc 重新协商。
    *RC_MEDIA.lock().unwrap_or_else(|p| p.into_inner()) = None;
    // W2-3：会话结束复位黑屏/水印（避免下一次会话首帧沿用上次的防窥状态）。
    crate::rc_wave2::reset_display();
    // W2-1：清理未完成的会话内传输（防止残留缓冲占用内存）。
    crate::rc_wave2::cleanup_transfers();
}

/// 处理 rc_stop（§8.3 会话生命周期）：仅当载荷 session_id 与当前会话一致
/// （或载荷为空的历史客户端）才真正停会话。旧会话的残留 rc_stop（如主端
/// StrictMode 双挂载先停后启的竞态）到达时新会话已建立，直接忽略——
/// 否则会把刚启动的帧循环杀掉，表现为 viewer 黑屏 + 「对端结束会话」。
pub fn handle_rc_stop(incoming_session: &str) {
    let current = RC_SESSION.lock().unwrap_or_else(|p| p.into_inner()).clone();
    match current {
        None => eprintln!("[agent] rc_stop：当前无活动会话，忽略"),
        Some(cur) if !incoming_session.is_empty() && incoming_session != cur => {
            eprintln!(
                "[agent] rc_stop：session 不匹配（{} ≠ 当前 {}），忽略旧会话残留指令",
                incoming_session, cur
            );
        }
        Some(_) => stop_rc(),
    }
}

/// 处理 rc_input：注入键鼠（macOS 真实注入；其余平台记录）。
pub fn apply_input(writer: &Writer, rng: &Arc<Mutex<crate::Lcg>>, seq: &Arc<Mutex<u64>>, session_id: &str, p: &crate::Json) {
    let kind = p.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    // W2-6 Ctrl+Alt+Del 直达：安全注意序列不能由用户态 SendInput 合成（Windows 仅在
    // Winlogon 安全桌面受理），故走官方可达路径（Windows 安全屏幕）；其他平台无此语义，
    // 不做伪造注入，诚实回告不支持。
    if kind == "cad" {
        crate::rc_wave2::handle_cad(writer, rng, seq);
        return;
    }
    let x = p.get("x").and_then(|v| v.as_i64()).unwrap_or(0) as f64;
    let y = p.get("y").and_then(|v| v.as_i64()).unwrap_or(0) as f64;
    let button = p.get("button").and_then(|v| v.as_i64()).unwrap_or(0) as u32;
    let key = p.get("key").and_then(|v| v.as_str()).unwrap_or("");
    // 观测：mouse_move 高频不记，其余全量——用于排查「主端触摸板 → 副端异常打字」。
    if kind != "mouse_move" {
        eprintln!("[agent] rc_input kind={} key={:?} btn={} x={} y={}", kind, key, button, x as i64, y as i64);
    }

    // Windows：服务在 Session 0 注入无效，转发到用户会话助手注入（远控在用户会话执行）。
    if relay_send_input_json(p) {
        send_rc_event(
            writer, rng, seq, session_id, "input_received", "forwarded to session helper",
            false, false,
        );
        return;
    }

    let result = inject_input(kind, x, y, button, key);
    let ok = result.is_ok();
    if let Err(e) = result {
        eprintln!("[agent] 输入注入失败 kind={} key={:?} btn={} err={}", kind, key, button, e);
    }
    send_rc_event(writer, rng, seq, session_id, "input_received",
        &format!("received {} ({})", kind, if ok { "ok" } else { "failed" }),
        false, false);
}

/// mouse_wheel 的 key 承载滚动量（如 "-3"/"+3"）；纯函数，全平台共用。
fn p_delta(key: &str) -> i32 {
    key.parse::<i32>().unwrap_or(-3)
}

// ===================== 输入注入分发 =====================

fn inject_input(kind: &str, x: f64, y: f64, button: u32, key: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        return inject_input_macos(kind, x, y, button, key);
    }
    #[cfg(target_os = "linux")]
    {
        return inject_input_linux(kind, x, y, button, key);
    }
    #[cfg(target_os = "windows")]
    {
        return inject_input_windows(kind, x, y, button, key);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        eprintln!("[agent] 平台无输入注入实现，仅记录: kind={}", kind);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn inject_input_macos(kind: &str, x: f64, y: f64, button: u32, key: &str) -> Result<(), String> {
    unsafe {
        let src = std::ptr::null();
        match kind {
            "mouse_move" => {
                let ev = cg::CGEventCreateMouseEvent(src, cg::MOUSE_MOVED, cg::CGPoint { x, y }, cg::BUTTON_LEFT);
                if ev.is_null() {
                    return Err("CGEventCreateMouseEvent null".into());
                }
                cg::CGEventPost(cg::K_CG_HID_EVENT_TAP, ev);
            }
            "mouse_down" => {
                let (mt, btn) = match button {
                    2 => (cg::MOUSE_RIGHT_DOWN, cg::BUTTON_RIGHT),
                    _ => (cg::MOUSE_LEFT_DOWN, cg::BUTTON_LEFT),
                };
                let ev = cg::CGEventCreateMouseEvent(src, mt, cg::CGPoint { x, y }, btn);
                if !ev.is_null() {
                    cg::CGEventPost(cg::K_CG_HID_EVENT_TAP, ev);
                }
            }
            "mouse_up" => {
                let (mt, btn) = match button {
                    2 => (cg::MOUSE_RIGHT_UP, cg::BUTTON_RIGHT),
                    _ => (cg::MOUSE_LEFT_UP, cg::BUTTON_LEFT),
                };
                let ev = cg::CGEventCreateMouseEvent(src, mt, cg::CGPoint { x, y }, btn);
                if !ev.is_null() {
                    cg::CGEventPost(cg::K_CG_HID_EVENT_TAP, ev);
                }
            }
            "mouse_wheel" => {
                let dy = p_delta(key);
                let ev = cg::CGEventCreateScrollWheelEvent2(src, cg::SCROLL_UNIT_PIXEL, 1, dy, 0, 0);
                if !ev.is_null() {
                    cg::CGEventPost(cg::K_CG_HID_EVENT_TAP, ev);
                }
            }
            "key_down" | "key_up" | "key_press" => {
                let code = key_code_of(key).ok_or_else(|| format!("未知按键 {}", key))?;
                let down = kind != "key_up";
                let ev = cg::CGEventCreateKeyboardEvent(src, code, down);
                if ev.is_null() {
                    return Err("CGEventCreateKeyboardEvent null".into());
                }
                cg::CGEventPost(cg::K_CG_HID_EVENT_TAP, ev);
                if kind == "key_press" {
                    let up = cg::CGEventCreateKeyboardEvent(src, code, false);
                    if !up.is_null() {
                        cg::CGEventPost(cg::K_CG_HID_EVENT_TAP, up);
                    }
                }
            }
            _ => return Err(format!("未知 kind {}", kind)),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inject_input_linux(kind: &str, x: f64, y: f64, button: u32, key: &str) -> Result<(), String> {
    // 首选 XTest FFI；无 X 显示（Wayland/纯头）时退化 xdotool 子进程。
    unsafe {
        let disp = xt::XOpenDisplay(std::ptr::null());
        if disp.is_null() {
            return inject_input_xdotool(kind, x, y, button, key);
        }
        let r = (|| {
            match kind {
                "mouse_move" => {
                    xt::XTestFakeMotionEvent(disp, 0, x as i32, y as i32, 0);
                }
                "mouse_down" | "mouse_up" => {
                    let press = if kind == "mouse_down" { 1 } else { 0 };
                    // X 按钮编号：1=左 2=中 3=右（与 viewer 端 1/2 约定一致，2=右需换算）
                    let xb: u32 = match button {
                        2 => 3,
                        1 => 1,
                        _ => 1,
                    };
                    xt::XTestFakeButtonEvent(disp, xb, press, 0);
                }
                "mouse_wheel" => {
                    // 滚轮：button 4=上 5=下；一次 notch = 一次 press+release
                    let xb: u32 = if p_delta(key) > 0 { 4 } else { 5 };
                    xt::XTestFakeButtonEvent(disp, xb, 1, 0);
                    xt::XTestFakeButtonEvent(disp, xb, 0, 0);
                }
                "key_down" | "key_up" | "key_press" => {
                    let sym = keysym_of(key)
                        .or_else(|| {
                            // 单字符：经 XStringToKeysym（如 "a" → XK_a）
                            let mut it = key.chars();
                            match (it.next(), it.next()) {
                                (Some(c), None) => {
                                    let mut buf = [0u8; 4];
                                    let s: &str = c.encode_utf8(&mut buf);
                                    let cstr = format!("{}\0", s);
                                    Some(xt::XStringToKeysym(cstr.as_ptr() as *const std::os::raw::c_char) as u64)
                                }
                                _ => None,
                            }
                        })
                        .ok_or_else(|| format!("未知按键 {}", key))?;
                    let kc = xt::XKeysymToKeycode(disp, sym as std::os::raw::c_ulong);
                    if kc == 0 {
                        return Err(format!("keysym {:#x} 无对应 keycode", sym));
                    }
                    let down = kind != "key_up";
                    xt::XTestFakeKeyEvent(disp, kc, if down { 1 } else { 0 }, 0);
                    if kind == "key_press" {
                        xt::XTestFakeKeyEvent(disp, kc, 0, 0);
                    }
                }
                _ => return Err(format!("未知 kind {}", kind)),
            }
            xt::XFlush(disp);
            Ok(())
        })();
        xt::XCloseDisplay(disp);
        r
    }
}

/// Linux 无 X 显示时的兜底：xdotool 子进程（存在则用，不存在则明确失败，不造假成功）。
#[cfg(target_os = "linux")]
fn inject_input_xdotool(kind: &str, x: f64, y: f64, button: u32, key: &str) -> Result<(), String> {
    let has = Command::new("xdotool").arg("version").output();
    if has.is_err() {
        return Err("无 X 显示且 xdotool 不可用".into());
    }
    let xi = x as i64;
    let yi = y as i64;
    let out = match kind {
        "mouse_move" => Command::new("xdotool").args(["mousemove", &xi.to_string(), &yi.to_string()]).output(),
        "mouse_down" | "mouse_up" => {
            let xb = if button == 2 { 3 } else { 1 };
            let act = if kind == "mouse_down" { "mousedown" } else { "mouseup" };
            Command::new("xdotool").args([act, &xb.to_string()]).output()
        }
        "mouse_wheel" => {
            let btn = if p_delta(key) > 0 { 4 } else { 5 };
            Command::new("xdotool").args(["click", &btn.to_string()]).output()
        }
        "key_down" | "key_up" | "key_press" => Command::new("xdotool").args(["key", key]).output(),
        _ => return Err(format!("未知 kind {}", kind)),
    };
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!("xdotool 退出码 {:?}", o.status.code())),
        Err(e) => Err(format!("xdotool 执行失败: {}", e)),
    }
}

#[cfg(target_os = "windows")]
/// 必须在首个 GetSystemMetrics/SendInput 调用前执行（main 启动即调）。
/// 让采集与注入共用同一物理像素坐标系；顺带 GDI 采集获得原生分辨率而非放大模糊图。
pub fn set_dpi_aware_windows() {
    use self::win32::*;
    unsafe {
        if SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) == 0 {
            let _ = SetProcessDPIAware(); // Win8.1 及以下回退
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn inject_input_windows(kind: &str, x: f64, y: f64, button: u32, key: &str) -> Result<(), String> {
    use std::os::raw::{c_int, c_long, c_uint, c_ulong};
    use self::win32::*;
    unsafe {
        // 绝对坐标需按虚拟桌面归一化到 0..65535
        let vx = GetSystemMetrics(SM_XVIRTUALSCREEN) as f64;
        let vy = GetSystemMetrics(SM_YVIRTUALSCREEN) as f64;
        let cw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1) as f64;
        let ch = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1) as f64;
        let nx = (((x - vx) / cw) * 65535.0).clamp(0.0, 65535.0) as c_long;
        let ny = (((y - vy) / ch) * 65535.0).clamp(0.0, 65535.0) as c_long;
        let abs = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;

        let inputs: Vec<INPUT> = match kind {
            "mouse_move" => vec![INPUT {
                type_: INPUT_MOUSE,
                u: INPUTUNION {
                    mouse: MOUSEINPUT {
                        dx: nx,
                        dy: ny,
                        mouse_data: 0,
                        dw_flags: abs,
                        time: 0,
                        dw_extra_info: 0,
                    },
                },
            }],
            "mouse_down" | "mouse_up" => {
                let (down_f, up_f) = if button == 2 {
                    (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP)
                } else {
                    (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP)
                };
                let flag = if kind == "mouse_down" { down_f } else { up_f };
                vec![INPUT {
                    type_: INPUT_MOUSE,
                    u: INPUTUNION {
                        mouse: MOUSEINPUT {
                            dx: nx,
                            dy: ny,
                            mouse_data: 0,
                            dw_flags: flag,
                            time: 0,
                            dw_extra_info: 0,
                        },
                    },
                }]
            }
            "mouse_wheel" => {
                let delta = (p_delta(key) as c_long) * WHEEL_DELTA;
                vec![INPUT {
                    type_: INPUT_MOUSE,
                    u: INPUTUNION {
                        mouse: MOUSEINPUT {
                            dx: nx,
                            dy: ny,
                            mouse_data: delta as c_ulong,
                            dw_flags: MOUSEEVENTF_WHEEL,
                            time: 0,
                            dw_extra_info: 0,
                        },
                    },
                }]
            }
            "key_down" | "key_up" | "key_press" => {
                let (vk, need_shift) = match vk_of(key) {
                    Some(v) => (v, false),
                    None => {
                        // 可打印字符：VkKeyScanW 低字节=VK，高字节=shift 状态
                        let ch = key.chars().next().ok_or("空按键")? as u16;
                        let r = VkKeyScanW(ch);
                        if r == -1 {
                            return Err(format!("VkKeyScan 无法映射字符 U+{:04X}", ch));
                        }
                        ((r & 0xff) as u16, (r >> 8) & 1 == 1)
                    }
                };
                let mut v = Vec::new();
                if need_shift {
                    v.push(key_input(0x10, true)); // VK_LSHIFT
                }
                let down = kind != "key_up";
                v.push(key_input(vk, down));
                if kind == "key_press" {
                    v.push(key_input(vk, false));
                }
                if need_shift {
                    v.push(key_input(0x10, false));
                }
                v
            }
            _ => return Err(format!("未知 kind {}", kind)),
        };
        let n = SendInput(
            inputs.len() as c_uint,
            inputs.as_ptr(),
            std::mem::size_of::<INPUT>() as c_int,
        );
        if n != inputs.len() as c_uint {
            return Err(format!("SendInput 仅注入 {}/{}", n, inputs.len()));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
unsafe fn key_input(vk: u16, down: bool) -> win32::INPUT {
    use self::win32::*;
    INPUT {
        type_: INPUT_KEYBOARD,
        u: INPUTUNION {
            keyboard: KEYBDINPUT {
                w_vk: vk,
                w_scan: 0,
                dw_flags: if down { 0 } else { KEYEVENTF_KEYUP },
                time: 0,
                dw_extra_info: 0,
            },
        },
    }
}

// ===================== RGBA 采集（原生编码器 / RAW 通道数据源，§8.3.6） =====================
//
// 采集当前主屏为紧凑 RGBA8（w*h*4）。平台实现：
// - macOS：CoreGraphics CGDisplayCreateImage → CFData（原生位图为 BGRA8888，交换 B/R）；
// - Linux：X11 XGetImage（ZPixmap，常见 32bpp BGRX/BGRA，交换 B/R）；
// - Windows：GDI BitBlt + GetDIBits（BI_RGB 32bpp 自底向上 BGRA，交换 B/R）。
// 不可用（无权限/无显示/布局不符）返回 None——调用方诚实回退，不造假帧。

#[cfg(target_os = "macos")]
mod cgcap {
    use std::os::raw::c_void;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        pub fn CGMainDisplayID() -> u32;
        pub fn CGDisplayCreateImage(display: u32) -> *const c_void;
        pub fn CGImageRelease(image: *const c_void);
        pub fn CGImageGetWidth(image: *const c_void) -> usize;
        pub fn CGImageGetHeight(image: *const c_void) -> usize;
        pub fn CGImageGetBitsPerPixel(image: *const c_void) -> usize;
        pub fn CGImageGetBytesPerRow(image: *const c_void) -> usize;
        pub fn CGImageGetDataProvider(image: *const c_void) -> *const c_void;
        pub fn CGDataProviderCopyData(provider: *const c_void) -> *const c_void;
    }

    // CFData/CFRelease 属 CoreFoundation（与 CoreGraphics 分离的框架）。
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        pub fn CFDataGetLength(data: *const c_void) -> isize;
        pub fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
        pub fn CFRelease(obj: *const c_void);
    }
}

#[cfg(target_os = "macos")]
fn capture_rgba_macos() -> Option<(Vec<u8>, usize, usize)> {
    unsafe {
        let img = cgcap::CGDisplayCreateImage(cgcap::CGMainDisplayID());
        if img.is_null() {
            return None; // 缺屏幕录制权限等
        }
        let w = cgcap::CGImageGetWidth(img);
        let h = cgcap::CGImageGetHeight(img);
        let bpp = cgcap::CGImageGetBitsPerPixel(img);
        let row = cgcap::CGImageGetBytesPerRow(img);
        let provider = cgcap::CGImageGetDataProvider(img);
        let data = if provider.is_null() {
            std::ptr::null()
        } else {
            cgcap::CGDataProviderCopyData(provider)
        };
        let mut out = None;
        if !data.is_null() && bpp == 32 && w > 0 && h > 0 && row >= w * 4 {
            let len = cgcap::CFDataGetLength(data) as usize;
            let ptr = cgcap::CFDataGetBytePtr(data);
            if !ptr.is_null() && len >= row * h {
                let src = std::slice::from_raw_parts(ptr, row * h);
                let mut rgba = vec![0u8; w * h * 4];
                for y in 0..h {
                    let s = &src[y * row..y * row + w * 4];
                    let d = &mut rgba[y * w * 4..(y + 1) * w * 4];
                    for i in 0..w * 4 {
                        // BGRA8888（小端 alpha first）→ RGBA：交换 B/R 通道
                        d[i] = match i % 4 {
                            0 => s[i + 2],
                            2 => s[i - 2],
                            _ => s[i],
                        };
                    }
                }
                out = Some((rgba, w, h));
            }
        }
        if !data.is_null() {
            cgcap::CFRelease(data);
        }
        cgcap::CGImageRelease(img);
        out
    }
}

#[cfg(target_os = "linux")]
mod x11cap {
    use std::os::raw::{c_char, c_int, c_uint, c_ulong};

    #[link(name = "X11")]
    extern "C" {
        pub fn XOpenDisplay(name: *const c_char) -> *mut std::os::raw::c_void;
        pub fn XCloseDisplay(d: *mut std::os::raw::c_void) -> c_int;
        pub fn XDefaultScreen(d: *mut std::os::raw::c_void) -> c_int;
        pub fn XRootWindow(d: *mut std::os::raw::c_void, screen: c_int) -> c_ulong;
        pub fn XDisplayWidth(d: *mut std::os::raw::c_void, screen: c_int) -> c_int;
        pub fn XDisplayHeight(d: *mut std::os::raw::c_void, screen: c_int) -> c_int;
        pub fn XGetImage(
            d: *mut std::os::raw::c_void,
            drawable: c_ulong,
            x: c_int,
            y: c_int,
            w: c_uint,
            h: c_uint,
            plane_mask: c_ulong,
            format: c_int,
        ) -> *mut XImage;
        pub fn XDestroyImage(img: *mut XImage) -> c_int;
    }

    pub const Z_PIXMAP: c_int = 2;
    pub const ALL_PLANES: c_ulong = !0u64 as c_ulong;

    /// XImage 布局前缀（Xlib.h 公开 ABI，后续 funcs 字段由 Xlib 自行访问，此处只需读到的字段）。
    #[repr(C)]
    pub struct XImage {
        pub width: c_int,
        pub height: c_int,
        pub xoffset: c_int,
        pub format: c_int,
        pub data: *mut c_char,
        pub byte_order: c_int,
        pub bitmap_unit: c_int,
        pub bitmap_bit_order: c_int,
        pub bitmap_pad: c_int,
        pub depth: c_int,
        pub bytes_per_line: c_int,
        pub red_mask: c_ulong,
        pub green_mask: c_ulong,
        pub blue_mask: c_ulong,
        pub obdata: *mut c_char,
    }
}

#[cfg(target_os = "linux")]
fn capture_rgba_linux() -> Option<(Vec<u8>, usize, usize)> {
    unsafe {
        let d = x11cap::XOpenDisplay(std::ptr::null());
        if d.is_null() {
            return None; // 无 X 显示（Wayland/纯头端）
        }
        let screen = x11cap::XDefaultScreen(d);
        let root = x11cap::XRootWindow(d, screen);
        let w = x11cap::XDisplayWidth(d, screen);
        let h = x11cap::XDisplayHeight(d, screen);
        let mut out = None;
        if w > 0 && h > 0 {
            let img = x11cap::XGetImage(
                d,
                root,
                0,
                0,
                w as u32,
                h as u32,
                x11cap::ALL_PLANES,
                x11cap::Z_PIXMAP,
            );
            if !img.is_null() {
                let pad = (*img).bitmap_pad;
                let depth = (*img).depth;
                let row = (*img).bytes_per_line;
                let data = (*img).data;
                // TrueColor 32bpp（BGRX/BGRA）或 24bpp 紧凑（BGR）
                let bpl_target = match pad {
                    32 => w * 4,
                    24 => w * 3,
                    _ => 0,
                };
                if !data.is_null() && row >= bpl_target && (depth == 24 || depth == 32) {
                    let src = std::slice::from_raw_parts(data as *const u8, row as usize * h as usize);
                    let mut rgba = vec![0u8; w as usize * h as usize * 4];
                    for y in 0..h as usize {
                        let s = &src[y * row as usize..];
                        let drow = &mut rgba[y * w as usize * 4..(y + 1) * w as usize * 4];
                        for x in 0..w as usize {
                            let (b, g, r) = if pad == 32 {
                                (s[x * 4], s[x * 4 + 1], s[x * 4 + 2])
                            } else {
                                (s[x * 3], s[x * 3 + 1], s[x * 3 + 2])
                            };
                            drow[x * 4] = r;
                            drow[x * 4 + 1] = g;
                            drow[x * 4 + 2] = b;
                            drow[x * 4 + 3] = 0xFF;
                        }
                    }
                    out = Some((rgba, w as usize, h as usize));
                }
                x11cap::XDestroyImage(img);
            }
        }
        x11cap::XCloseDisplay(d);
        out
    }
}

#[cfg(target_os = "windows")]
mod gdicap {
    use std::os::raw::{c_int, c_uint, c_ushort};

    #[repr(C)]
    pub struct BITMAPINFOHEADER {
        pub bi_size: u32,
        pub bi_width: c_int,
        pub bi_height: c_int,
        pub bi_planes: c_ushort,
        pub bi_bit_count: c_ushort,
        pub bi_compression: u32,
        pub bi_size_image: u32,
        pub bi_x_pels_per_meter: c_int,
        pub bi_y_pels_per_meter: c_int,
        pub bi_clr_used: u32,
        pub bi_clr_important: u32,
    }

    #[repr(C)]
    pub struct BITMAPINFO {
        pub bmi_header: BITMAPINFOHEADER,
        pub bmi_colors: [u32; 1],
    }

    #[link(name = "gdi32")]
    extern "system" {
        pub fn CreateCompatibleDC(hdc: *mut std::os::raw::c_void) -> *mut std::os::raw::c_void;
        pub fn DeleteDC(hdc: *mut std::os::raw::c_void) -> c_int;
        pub fn CreateCompatibleBitmap(hdc: *mut std::os::raw::c_void, cx: c_int, cy: c_int)
            -> *mut std::os::raw::c_void;
        pub fn DeleteObject(o: *mut std::os::raw::c_void) -> c_int;
        pub fn SelectObject(hdc: *mut std::os::raw::c_void, h: *mut std::os::raw::c_void)
            -> *mut std::os::raw::c_void;
        pub fn BitBlt(
            dest: *mut std::os::raw::c_void,
            x: c_int,
            y: c_int,
            cx: c_int,
            cy: c_int,
            src: *mut std::os::raw::c_void,
            sx: c_int,
            sy: c_int,
            rop: u32,
        ) -> c_int;
        pub fn GetDIBits(
            hdc: *mut std::os::raw::c_void,
            bmp: *mut std::os::raw::c_void,
            start: c_uint,
            lines: c_uint,
            bits: *mut u8,
            info: *mut BITMAPINFO,
            usage: c_uint,
        ) -> c_int;
    }

    pub const SRCCOPY: u32 = 0x00CC_0020;
    pub const DIB_RGB_COLORS: c_uint = 0;
    pub const BI_RGB: u32 = 0;

    // 远端光标叠加：GDI BitBlt 不含鼠标指针，不叠加则主端看不到副端光标
    // 位置与点击落点，远程操作如同失灵。
    #[repr(C)]
    pub struct POINT {
        pub x: i32,
        pub y: i32,
    }
    #[repr(C)]
    pub struct CURSORINFO {
        pub cb_size: u32,
        pub flags: u32,
        pub hcursor: *mut std::os::raw::c_void,
        pub pt_screen_pos: POINT,
    }
    #[link(name = "user32")]
    extern "system" {
        pub fn GetCursorInfo(info: *mut CURSORINFO) -> c_int;
        pub fn DrawIconEx(
            hdc: *mut std::os::raw::c_void,
            x: c_int,
            y: c_int,
            icon: *mut std::os::raw::c_void,
            cx: c_int,
            cy: c_int,
            step: c_uint,
            brush: *mut std::os::raw::c_void,
            flags: c_uint,
        ) -> c_int;
    }
    pub const CURSOR_SHOWING: u32 = 0x1;
    pub const DI_NORMAL: c_uint = 0x3;
}

#[cfg(target_os = "windows")]
fn capture_rgba_windows() -> Option<(Vec<u8>, usize, usize)> {
    use self::gdicap::*;
    unsafe {
        let hdc_screen = win32::GetDC(std::ptr::null_mut());
        if hdc_screen.is_null() {
            return None;
        }
        let w = win32::GetSystemMetrics(0); // SM_CXSCREEN
        let h = win32::GetSystemMetrics(1); // SM_CYSCREEN
        let mut out = None;
        if w > 0 && h > 0 {
            let mem = CreateCompatibleDC(hdc_screen);
            let bmp = CreateCompatibleBitmap(hdc_screen, w, h);
            if !mem.is_null() && !bmp.is_null() {
                let old = SelectObject(mem, bmp);
                if BitBlt(mem, 0, 0, w, h, hdc_screen, 0, 0, SRCCOPY) != 0 {
                    // 不再把光标烘焙进帧。光标改为「主端本地指针 + 客户端平滑渲染 +
                    // 真实形状流式下发」（见 spawn_cursor_thread），避免 15fps 帧率下光标
                    // 轨迹卡顿（成熟远控产品的标准做法）。
                    let mut bi = BITMAPINFO {
                        bmi_header: BITMAPINFOHEADER {
                            bi_size: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                            bi_width: w,
                            bi_height: -h, // 负值 = 自顶向下
                            bi_planes: 1,
                            bi_bit_count: 32,
                            bi_compression: BI_RGB,
                            bi_size_image: 0,
                            bi_x_pels_per_meter: 0,
                            bi_y_pels_per_meter: 0,
                            bi_clr_used: 0,
                            bi_clr_important: 0,
                        },
                        bmi_colors: [0; 1],
                    };
                    let mut buf = vec![0u8; w as usize * h as usize * 4];
                    let lines = GetDIBits(
                        mem,
                        bmp,
                        0,
                        h as u32,
                        buf.as_mut_ptr(),
                        &mut bi,
                        DIB_RGB_COLORS,
                    );
                    if lines == h {
                        // BGRA（DIB 32bpp）→ RGBA：交换 B/R
                        for px in buf.chunks_exact_mut(4) {
                            px.swap(0, 2);
                        }
                        out = Some((buf, w as usize, h as usize));
                    }
                }
                SelectObject(mem, old);
                DeleteObject(bmp);
                DeleteDC(mem);
            }
        }
        win32::ReleaseDC(std::ptr::null_mut(), hdc_screen);
        out
    }
}

// ===================== 光标形状流式下发 =====================
// 光标位置由主端「本地指针 + 客户端平滑渲染」负责（无需副端位置通道，彻底消除 15fps
// 帧率下的轨迹卡顿）；副端仅在光标形状变化时（切箭头/I 形/手形等）低频下发形状，
// 主端据此绘制与远端一致的光标。形状变化频率极低，独立线程 ~200ms 轮询即可。

pub struct CursorShape {
    pub data: Vec<u8>, // RGBA8（已交换 B/R，可直接 putImageData）
    pub w: u32,
    pub h: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub screen_w: u32,
    pub screen_h: u32,
}

/// 采集当前光标形状（RGBA）。不可用/失败时返回 None（主端回退通用箭头）。
pub fn capture_cursor_shape() -> Option<CursorShape> {
    #[cfg(target_os = "windows")]
    {
        capture_cursor_shape_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (0u32, 0u32);
        None
    }
}

#[cfg(target_os = "windows")]
fn capture_cursor_shape_windows() -> Option<CursorShape> {
    use self::gdicap::*;
    unsafe {
        let mut ci = CURSORINFO {
            cb_size: std::mem::size_of::<CURSORINFO>() as u32,
            flags: 0,
            hcursor: std::ptr::null_mut(),
            pt_screen_pos: POINT { x: 0, y:0 },
        };
        if GetCursorInfo(&mut ci) == 0 || (ci.flags & CURSOR_SHOWING) == 0 || ci.hcursor.is_null() {
            return None;
        }
        // GetIconInfo 取热点与位图；返回的两个位图须调用方 DeleteObject 释放。
        #[repr(C)]
        struct ICONINFO {
            f_icon: c_int,
            x_hotspot: c_int,
            y_hotspot: c_int,
            hbm_mask: *mut std::os::raw::c_void,
            hbm_color: *mut std::os::raw::c_void,
        }
        let mut ii = ICONINFO {
            f_icon: 0, x_hotspot: 0, y_hotspot: 0,
            hbm_mask: std::ptr::null_mut(), hbm_color: std::ptr::null_mut(),
        };
        extern "system" {
            fn GetIconInfo(h: *mut std::os::raw::c_void, ii: *mut ICONINFO) -> c_int;
        }
        if GetIconInfo(ci.hcursor, &mut ii) == 0 {
            return None;
        }
        let (hbm, has_color) = if !ii.hbm_color.is_null() {
            (ii.hbm_color, true)
        } else if !ii.hbm_mask.is_null() {
            (ii.hbm_mask, false)
        } else {
            return None;
        };
        let screen_w = win32::GetSystemMetrics(0) as u32;
        let screen_h = win32::GetSystemMetrics(1) as u32;
        let res = get_bitmap_rgba(hbm, has_color, ii.x_hotspot as u32, ii.y_hotspot as u32, screen_w, screen_h);
        DeleteObject(ii.hbm_mask);
        if !ii.hbm_color.is_null() {
            DeleteObject(ii.hbm_color);
        }
        res
    }
}

#[cfg(target_os = "windows")]
unsafe fn get_bitmap_rgba(
    hbm: *mut std::os::raw::c_void, has_color: bool, hot_x: u32, hot_y: u32,
    screen_w: u32, screen_h: u32,
) -> Option<CursorShape> {
    use self::gdicap::*;
    #[repr(C)]
    struct BITMAP {
        bm_type: c_int, bm_width: c_int, bm_height: c_int, bm_width_bytes: c_int,
        bm_planes: c_ushort, bm_bits_pixel: c_ushort, bm_bits: *mut std::os::raw::c_void,
    }
    extern "system" {
        fn GetObjectW(h: *mut std::os::raw::c_void, c: c_int, lp: *mut std::os::raw::c_void) -> c_int;
    }
    let mut bm = std::mem::zeroed::<BITMAP>();
    if GetObjectW(hbm, std::mem::size_of::<BITMAP>() as c_int, &mut bm as *mut _ as *mut std::os::raw::c_void) == 0 {
        return None;
    }
    let w = bm.bm_width;
    let h = bm.bm_height;
    if w <= 0 || h <= 0 || w > 256 || h > 256 {
        return None;
    }
    let mem = CreateCompatibleDC(std::ptr::null_mut());
    if mem.is_null() {
        return None;
    }
    let old = SelectObject(mem, hbm);
    let mut bi = BITMAPINFO {
        bmi_header: BITMAPINFOHEADER {
            bi_size: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            bi_width: w, bi_height: -h, bi_planes: 1, bi_bit_count: 32,
            bi_compression: BI_RGB, bi_size_image: 0, bi_x_pels_per_meter: 0,
            bi_y_pels_per_meter: 0, bi_clr_used: 0, bi_clr_important: 0,
        },
        bmi_colors: [0; 1],
    };
    let mut buf = vec![0u8; w as usize * h as usize * 4];
    let lines = GetDIBits(mem, hbm, 0, h as u32, buf.as_mut_ptr(), &mut bi, DIB_RGB_COLORS);
    SelectObject(mem, old);
    DeleteDC(mem);
    if lines != h {
        return None;
    }
    if has_color {
        // 32bpp BGRA → RGBA；alpha 直接取自位图（现代光标为 ARGB）。
        for px in buf.chunks_exact_mut(4) {
            px.swap(0, 2);
        }
    } else {
        // 仅掩码（单色光标）：以 1=黑 0=透构造简易箭头回退——此处直接放弃，回退通用箭头。
        return None;
    }
    Some(CursorShape { data: buf, w: w as u32, h: h as u32, hot_x, hot_y, screen_w, screen_h })
}

/// 启动光标形状流线程：低频轮询，形状变化时经 rc_event(cursor_shape) 下发。
pub fn spawn_cursor_thread(
    writer: Writer, rng: Arc<Mutex<crate::Lcg>>, seq: Arc<Mutex<u64>>, session_id: String, gen: u64,
) {
    thread::spawn(move || {
        let mut last_hash: u64 = 0;
        while RC_GEN.load(Ordering::SeqCst) == gen && !RC_STOP.load(Ordering::SeqCst) {
            if let Some(shape) = capture_cursor_shape() {
                let hash = {
                    let mut h: u64 = 1469598103934665603; // FNV-1a
                    for b in shape.data.iter().chain(std::iter::once(&(shape.w as u8))) {
                        h ^= *b as u64;
                        h = h.wrapping_mul(1099511628211);
                    }
                    h
                };
                if hash != last_hash {
                    last_hash = hash;
                    send_rc_cursor_shape(&writer, &rng, &seq, &session_id, &shape);
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
    });
}

fn send_rc_cursor_shape(
    writer: &Writer, rng: &Arc<Mutex<crate::Lcg>>, seq: &Arc<Mutex<u64>>, session_id: &str, shape: &CursorShape,
) {
    let data_b64 = crate::base64_encode(&shape.data);
    let inner = format!(
        "{{\"w\":{},\"h\":{},\"hot_x\":{},\"hot_y\":{},\"screen_w\":{},\"screen_h\":{},\"data\":\"{}\"}}",
        shape.w, shape.h, shape.hot_x, shape.hot_y, shape.screen_w, shape.screen_h, data_b64
    );
    // 复用 rc_event 通道：kind=cursor_shape，message 内嵌形状 JSON（hub 透明中继到主端）。
    let payload = format!(
        "{{\"session_id\":{},\"kind\":\"cursor_shape\",\"message\":{},\"require_consent\":false,\"consented\":false}}",
        json_string(session_id), json_string(&inner)
    );
    let m = {
        let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
        let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
        crate::build_envelope(&mut rng_g, &mut seq_g, "rc_event", &payload)
    };
    let _ = send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), m.as_bytes());
}

/// 采集当前主屏为紧凑 RGBA8；平台不可用时返回 None（诚实回退，不造假帧）。
pub fn capture_rgba() -> Option<(Vec<u8>, usize, usize)> {
    #[cfg(target_os = "macos")]
    {
        capture_rgba_macos()
    }
    #[cfg(target_os = "linux")]
    {
        capture_rgba_linux()
    }
    #[cfg(target_os = "windows")]
    {
        capture_rgba_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

/// RGBA 采集可用性探测（协商期调用一次；做一次真实采集后丢弃）。
pub fn rgba_capture_ok() -> bool {
    capture_rgba().is_some()
}

/// 协商期探测：一次真实 RGBA 采集 → 依 capabilities.max_w/h 定目标分辨率（保比取偶）
/// 并写入 RC_TARGET；同时返回 RGBA 采集是否可用。
fn probe_rgba_set_target() -> bool {
    let caps = crate::rc_media::default_capabilities();
    match capture_rgba() {
        Some((_, w, h)) => {
            let fit = crate::rc_media::fit_dims(w as u32, h as u32, caps.max_w as u32, caps.max_h as u32);
            eprintln!(
                "[agent] RGBA 采集可用 {}x{} → 协商目标 {}x{}",
                w, h, fit.0, fit.1
            );
            *RC_TARGET.lock().unwrap_or_else(|p| p.into_inner()) = Some(fit);
            true
        }
        None => {
            *RC_TARGET.lock().unwrap_or_else(|p| p.into_inner()) = None;
            false
        }
    }
}

// ===================== 屏幕采集 =====================

/// JPEG 路径（§8.3.10 降采样）：优先 RGBA 采集（三平台同构，CoreGraphics/X11/GDI）
/// → 按协商目标分辨率降采样 → 内置 JPEG 编码；RGBA 采集不可用时回退平台 CLI
/// （screencapture/scrot/import，保持全分辨率兜底）。
/// 效果：5K 屏 JPEG 从 2.3MB/帧（全分辨率）降至 1080p ~200KB 级，且不再依赖 CLI。
pub(crate) fn capture_jpeg() -> Option<(Vec<u8>, usize, usize)> {
    if let Some((rgba, w, h)) = capture_rgba() {
        let (tw, th) = target_dims()
            .map(|(a, b)| (a as usize, b as usize))
            .unwrap_or((w, h));
        let (data, tw, th) = if (tw, th) != (w, h) && tw > 0 && th > 0 {
            (crate::rc_media::downscale_rgba(&rgba, w as u32, h as u32, tw as u32, th as u32), tw, th)
        } else {
            (rgba, w, h)
        };
        if let Some(jpeg) = crate::jpegenc::encode_rgba(
            &data,
            tw as u32,
            th as u32,
            RC_JPEG_Q.load(Ordering::SeqCst).clamp(10, 95) as u32,
        ) {
            return Some((jpeg, tw, th));
        }
        // 编码失败：落 CLI 兜底（不产出错误码流）
        eprintln!("[agent] 内置 JPEG 编码失败，回退平台 CLI 采集");
    }
    capture_jpeg_cli()
}

/// 平台 CLI 采集（旧路径，全分辨率兜底）。
fn capture_jpeg_cli() -> Option<(Vec<u8>, usize, usize)> {
    let path = format!("/tmp/yuduan_rc_{}.jpg", std::process::id());
    if cfg!(target_os = "macos") {
        let ok = Command::new("screencapture")
            .args(["-x", "-t", "jpg", &path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return None;
        }
    } else if cfg!(target_os = "linux") {
        let ok = Command::new("scrot").args(["-o", &path]).status().map(|s| s.success()).unwrap_or(false)
            || Command::new("import").args(["-window", "root", &path]).status().map(|s| s.success()).unwrap_or(false);
        if !ok {
            return None;
        }
    } else {
        return None;
    }
    let data = std::fs::read(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    if data.is_empty() {
        return None;
    }
    let (w, h) = jpeg_size(&data).unwrap_or((0, 0));
    Some((data, w, h))
}

/// 解析 JPEG SOF 尺寸（无第三方库，纯 std）。
fn jpeg_size(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return None;
    }
    let mut i = 2usize;
    while i + 9 < data.len() {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = data[i + 1];
        if marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01 {
            i += 2;
            continue;
        }
        if marker == 0xD9 {
            break;
        }
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        // SOF0/1/2/3/5/6/7/9/10/11
        if (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC {
            let h = u16::from_be_bytes([data[i + 5], data[i + 6]]) as usize;
            let w = u16::from_be_bytes([data[i + 7], data[i + 8]]) as usize;
            return Some((w, h));
        }
        i += 2 + len;
    }
    None
}

// ===================== 协议消息 =====================

/// JSON rc_frame 载荷（M4 MVP 中继兜底；二进制通道就绪后走 §8.3 二进制帧）。
fn rc_frame_payload(session_id: &str, seq: i64, w: usize, h: usize, data: &[u8]) -> String {
    format!(
        "{{\"session_id\":{},\"seq\":{},\"width\":{},\"height\":{},\"format\":\"jpeg\",\"data\":{},\"ts\":{}}}",
        json_string(session_id), seq, w, h, json_string(&base64_encode(data)), crate::now_secs()
    )
}

fn send_rc_ready(writer: &Writer, rng: &Arc<Mutex<crate::Lcg>>, seq: &Arc<Mutex<u64>>, session_id: &str, ok: bool, reason: &str) {
    let payload = format!(
        "{{\"session_id\":{},\"ok\":{},\"reason\":{}}}",
        json_string(session_id), ok, json_string(reason)
    );
    let msg = {
        let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
        let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
        crate::build_envelope(&mut rng_g, &mut seq_g, "rc_ready", &payload)
    };
    let _ = send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes());
}

/// 宣告远控媒体能力（§8.3）：编解码器 / 最大分辨率 / 帧率；主端据此协商二进制帧通道。
/// 载荷为扁平字段，与 protocol.md §8.3 及 Go proto.RCCapabilitiesPayload 一致：
/// {"session_id":…, "codecs":[…], "max_w":…, "max_h":…, "fps":…}
fn send_rc_capabilities(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    session_id: &str,
    caps_json: &str,
) {
    let payload = format!("{{\"session_id\":{},{}}}", json_string(session_id), caps_json);
    let msg = {
        let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
        let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
        crate::build_envelope(&mut rng_g, &mut seq_g, "rc_capabilities", &payload)
    };
    let _ = send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), msg.as_bytes());
}

fn send_rc_event(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    session_id: &str,
    kind: &str,
    msg: &str,
    require_consent: bool,
    consented: bool,
) {
    let payload = format!(
        "{{\"session_id\":{},\"kind\":{},\"message\":{},\"require_consent\":{},\"consented\":{}}}",
        json_string(session_id), json_string(kind), json_string(msg), require_consent, consented
    );
    let m = {
        let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
        let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
        crate::build_envelope(&mut rng_g, &mut seq_g, "rc_event", &payload)
    };
    let _ = send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), m.as_bytes());
}

fn show_remote_notice() {
    if cfg!(target_os = "macos") {
        let _ = Command::new("osascript")
            .args([
                "-e",
                "display notification \"管理员正在请求远程控制本机，您可拒绝\" with title \"御端远端提示\"",
            ])
            .status();
    }
    eprintln!("[agent] [远端提示] 管理员请求远程控制，员工可拒绝");
}

// ===================== base64 编解码 =====================
// 编码复用主模块实现（crate::base64_encode）；解码用 sha256 模块的 base64_decode。

// 平台无关的远控中继桥接（非 Windows 编译时返回 None/false，原样走本地路径）。
// Windows 下若助手活跃，则帧来源于用户会话助手、输入转发给助手注入。
fn relay_frame() -> Option<(Vec<u8>, usize, usize)> {
    #[cfg(target_os = "windows")]
    {
        if rc_helper::is_active() {
            return rc_helper::read_frame().map(|(d, w, h)| (d, w as usize, h as usize));
        }
    }
    None
}

#[allow(unused_variables)]
fn relay_send_input_json(p: &crate::Json) -> bool {
    #[cfg(target_os = "windows")]
    {
        if rc_helper::is_active() {
            let kind = p.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind == "cad" {
                return false; // 助手在用户态也送不到 Winlogon 安全桌面
            }
            let x = p.get("x").and_then(|v| v.as_i64()).unwrap_or(0);
            let y = p.get("y").and_then(|v| v.as_i64()).unwrap_or(0);
            let button = p.get("button").and_then(|v| v.as_i64()).unwrap_or(0);
            let key = p.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let json = format!(
                "{{\"kind\":{},\"x\":{},\"y\":{},\"button\":{},\"key\":{}}}",
                crate::json_string(kind), x, y, button, crate::json_string(key)
            );
            return rc_helper::send_input(&json);
        }
    }
    false
}

// ===================== 双进程远控：服务 ↔ 用户会话助手 回环中继（Windows） =====================
// 服务以 SCM 在 Session 0 运行，GDI GetDC(null)+BitBlt 只能抓 Session 0 隔离桌面（空/黑屏），
// SendInput 同理无效。故 Windows 远控采集/注入改在**活动用户会话**内执行：服务用 WTS 取活动
// 会话令牌，CreateProcessAsUserW 拉起自身 `--rc-helper <port> <session_id>` 子进程（运行于用户
// 会话），经 127.0.0.1 回环 TCP 中继帧与输入。无活动会话/锁屏时 rc_ready 带明确失败原因。
#[cfg(target_os = "windows")]
pub(crate) mod rc_helper {
    use std::ffi::OsStr;
    use std::io::{Read, Write};
    use std::mem;
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::raw::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::{capture_jpeg, inject_input_windows, rc_frame_interval_ms};

    const MSG_FRAME: u8 = 1; // 助手→服务：payload = w(u32 BE)+h(u32 BE)+jpeg
    const MSG_INPUT: u8 = 2; // 服务→助手：payload = JSON（rc_input 参数）

    struct Bridge {
        stream: TcpStream,
        h_process: *mut c_void,
        pid: u32,
    }
    // h_process 是 Windows HANDLE（原始指针），仅本进程内用于 TerminateProcess/CloseHandle，
    // 不跨线程共享；此处声明 Send 以满足 `static Mutex<Option<Bridge>>` 的 Sync 约束。
    unsafe impl Send for Bridge {}
    static RC_BRIDGE: Mutex<Option<Bridge>> = Mutex::new(None);

    pub(crate) fn is_active() -> bool {
        RC_BRIDGE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// 服务侧：检测活动会话并拉起用户会话助手。成功 Ok(())；失败 Err(reason)（供调用方 rc_ready 上报）。
    pub(crate) fn start_for_session() -> Result<(), String> {
        unsafe {
            let sid = super::win32::WTSGetActiveConsoleSessionId();
            if sid == 0 {
                return Err("no_active_console_session".into());
            }
            let mut token: super::win32::HANDLE = ptr::null_mut();
            if super::win32::WTSQueryUserToken(sid, &mut token) == 0 {
                return Err("cannot_acquire_user_token".into());
            }
            // 锁屏检测（Win8+ 支持 WTSIsLocked；不支持时降级为允许远控）。
            let mut buf: *mut u16 = ptr::null_mut();
            let mut bytes: u32 = 0;
            if super::win32::WTSQuerySessionInformationW(
                ptr::null_mut(),
                sid,
                super::win32::WTS_IS_LOCKED,
                &mut buf,
                &mut bytes,
            ) != 0
                && bytes >= 4
            {
                let bp = buf as *const u8;
                let v = u32::from(*bp)
                    | (u32::from(*bp.add(1)) << 8)
                    | (u32::from(*bp.add(2)) << 16)
                    | (u32::from(*bp.add(3)) << 24);
                super::win32::WTSFreeMemory(buf as super::win32::HANDLE);
                if v != 0 {
                    super::win32::CloseHandle(token);
                    return Err("session_locked".into());
                }
            } else if !buf.is_null() {
                super::win32::WTSFreeMemory(buf as super::win32::HANDLE);
            }
            // 复制为 primary token 并迁移到目标会话。
            let mut primary: super::win32::HANDLE = ptr::null_mut();
            if super::win32::DuplicateTokenEx(
                token,
                super::win32::TOKEN_ALL_ACCESS,
                ptr::null_mut(),
                super::win32::SECURITY_IMPERSONATION,
                super::win32::TOKEN_PRIMARY,
                &mut primary,
            ) == 0
            {
                super::win32::CloseHandle(token);
                return Err("token_duplicate_failed".into());
            }
            let mut sid_copy = sid;
            super::win32::SetTokenInformation(
                primary,
                super::win32::TOKEN_SESSION_ID,
                &mut sid_copy as *mut _ as super::win32::LPVOID,
                4,
            );
            // 监听回环端口（系统分配空闲端口，跨会话回环互通）。
            let listener = match TcpListener::bind("127.0.0.1:0") {
                Ok(l) => l,
                Err(e) => {
                    super::win32::CloseHandle(token);
                    super::win32::CloseHandle(primary);
                    eprintln!("[agent] 远控中继监听失败: {}", e);
                    return Err("relay_listen_failed".into());
                }
            };
            let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
            let exe = match std::env::current_exe() {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(_) => return Err("exe_path_failed".into()),
            };
            let cmd = format!("\"{}\" --rc-helper {} {}", exe, port, sid);
            let mut cmd_wide = wide(&cmd);
            let exe_wide = wide(&exe);
            let mut desktop = wide("winsta0\\default");
            let mut si: super::win32::STARTUPINFOW = mem::zeroed();
            si.cb = mem::size_of::<super::win32::STARTUPINFOW>() as u32;
            si.lp_desktop = desktop.as_mut_ptr();
            let mut pi: super::win32::PROCESS_INFORMATION = mem::zeroed();
            if super::win32::CreateProcessAsUserW(
                primary,
                exe_wide.as_ptr(),
                cmd_wide.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                super::win32::CREATE_UNICODE_ENVIRONMENT | super::win32::CREATE_NEW_CONSOLE,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut si,
                &mut pi,
            ) == 0
            {
                super::win32::CloseHandle(token);
                super::win32::CloseHandle(primary);
                return Err("launch_helper_failed".into());
            }
            super::win32::CloseHandle(token);
            super::win32::CloseHandle(pi.h_thread);
            // 接受助手连接（非阻塞重试，避免卡死在 accept）。
            let _ = listener.set_nonblocking(true);
            let stream = {
                let mut s = None;
                for _ in 0..100 {
                    if let Ok((st, _)) = listener.accept() {
                        s = Some(st);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                s
            };
            match stream {
                Some(st) => {
                    *RC_BRIDGE
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) = Some(Bridge {
                        stream: st,
                        h_process: pi.h_process,
                        pid: pi.dw_process_id,
                    });
                    eprintln!(
                        "[agent] 远控助手已拉起 sid={} pid={} port={}",
                        sid, pi.dw_process_id, port
                    );
                    Ok(())
                }
                None => {
                    super::win32::CloseHandle(pi.h_process);
                    Err("helper_connect_timeout".into())
                }
            }
        }
    }

    /// 服务帧循环：从中继读一帧 JPEG（Windows 服务侧改用，替代本进程 capture）。
    pub(crate) fn read_frame() -> Option<(Vec<u8>, u32, u32)> {
        let mut g = RC_BRIDGE.lock().unwrap_or_else(|p| p.into_inner());
        let bridge = g.as_mut()?;
        let mut head = [0u8; 5];
        if bridge.stream.read_exact(&mut head).is_err() {
            return None;
        }
        if head[0] != MSG_FRAME {
            return None;
        }
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        let mut payload = vec![0u8; len];
        if bridge.stream.read_exact(&mut payload).is_err() {
            return None;
        }
        if payload.len() < 8 {
            return None;
        }
        let w = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let h = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        Some((payload[8..].to_vec(), w, h))
    }

    /// 服务输入路径：把输入 JSON 转发给助手注入。
    pub(crate) fn send_input(json: &str) -> bool {
        let mut g = RC_BRIDGE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(b) = g.as_mut() {
            let mut buf = Vec::with_capacity(5 + json.len());
            buf.push(MSG_INPUT);
            buf.extend_from_slice(&(json.len() as u32).to_be_bytes());
            buf.extend_from_slice(json.as_bytes());
            b.stream.write_all(&buf).is_ok()
        } else {
            false
        }
    }

    /// 停止远控：关流 + 终止助手进程。
    pub(crate) fn stop() {
        let mut g = RC_BRIDGE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(b) = g.take() {
            let _ = b.stream.shutdown(Shutdown::Both);
            unsafe {
                if !b.h_process.is_null() {
                    super::win32::TerminateProcess(b.h_process, 0);
                    super::win32::CloseHandle(b.h_process);
                }
            }
            eprintln!("[agent] 远控助手已停止 pid={}", b.pid);
        }
    }

    /// 助手进程入口：连服务回环 TCP，用户会话内真实抓屏 + 注入。
    pub(crate) fn run(addr: &str) -> ! {
        let mut stream = match TcpStream::connect(addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[agent-helper] 连接服务失败: {}", e);
                std::process::exit(1);
            }
        };
        eprintln!("[agent-helper] 已连接服务 {}", addr);
        let mut writer = match stream.try_clone() {
            Ok(w) => w,
            Err(_) => std::process::exit(1),
        };
        // 帧采集线程：用户会话内真实采集并编码 JPEG，上行中继。
        std::thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                let interval = rc_frame_interval_ms() as u64;
                let next = last_tick + Duration::from_millis(interval);
                let now = Instant::now();
                if next > now {
                    std::thread::sleep(next - now);
                }
                last_tick = Instant::now();
                match capture_jpeg() {
                    Some((jpeg, w, h)) => {
                        let mut buf = Vec::with_capacity(5 + 8 + jpeg.len());
                        buf.push(MSG_FRAME);
                        buf.extend_from_slice(&((8 + jpeg.len()) as u32).to_be_bytes());
                        buf.extend_from_slice(&(w as u32).to_be_bytes());
                        buf.extend_from_slice(&(h as u32).to_be_bytes());
                        buf.extend_from_slice(&jpeg);
                        if writer.write_all(&buf).is_err() {
                            break;
                        }
                    }
                    None => {
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            }
        });
        // 输入接收线程：服务转发来的输入在此注入用户会话。
        let mut head = [0u8; 5];
        loop {
            if stream.read_exact(&mut head).is_err() {
                break;
            }
            let t = head[0];
            let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
            let mut payload = vec![0u8; len];
            if stream.read_exact(&mut payload).is_err() {
                break;
            }
            if t != MSG_INPUT {
                continue;
            }
            let s = String::from_utf8_lossy(&payload);
            if let Ok(j) = crate::parse_json(s.as_bytes()) {
                let kind = j.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                if kind == "cad" {
                    continue; // 安全注意序列在用户态不可合成
                }
                let x = j.get("x").and_then(|v| v.as_i64()).unwrap_or(0) as f64;
                let y = j.get("y").and_then(|v| v.as_i64()).unwrap_or(0) as f64;
                let button = j.get("button").and_then(|v| v.as_i64()).unwrap_or(0) as u32;
                let key = j.get("key").and_then(|v| v.as_str()).unwrap_or("");
                if let Err(e) = inject_input_windows(kind, x, y, button, key) {
                    eprintln!("[agent-helper] 输入注入失败 kind={} err={}", kind, e);
                }
            }
        }
        std::process::exit(0);
    }
}

// 供测试引用避免 unused 警告
#[allow(dead_code)]
fn _use_decode() {
    let _ = base64_decode("AAAA");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_size_parses_sof() {
        // 构造一个最小 JPEG：SOI + SOF0(长度8, 精度8, 高=100, 宽=200) + EOI
        let mut jpg = vec![0xFF, 0xD8];
        jpg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x08, 0x08]);
        jpg.extend_from_slice(&(100u16).to_be_bytes());
        jpg.extend_from_slice(&(200u16).to_be_bytes());
        jpg.push(0x03); // 分量数
        jpg.extend_from_slice(&[0x01, 0x22, 0x00]);
        jpg.extend_from_slice(&[0xFF, 0xD9]);
        assert_eq!(jpeg_size(&jpg), Some((200, 100)));
    }

    #[test]
    fn base64_roundtrip() {
        let raw = vec![1u8, 2, 3, 4, 5];
        let enc = base64_encode(&raw);
        assert_eq!(base64_decode(&enc).unwrap(), raw);
    }

    #[test]
    fn keysym_map_covers_special_keys() {
        assert_eq!(keysym_of("enter"), Some(0xff0d)); // XK_Return
        assert_eq!(keysym_of("Return"), Some(0xff0d)); // 大小写不敏感
        assert_eq!(keysym_of("space"), Some(0x020));
        assert_eq!(keysym_of("backspace"), Some(0xff08));
        assert_eq!(keysym_of("escape"), Some(0xff1b));
        assert_eq!(keysym_of("left"), Some(0xff51));
        assert_eq!(keysym_of("f1"), Some(0xffbe));
        assert_eq!(keysym_of("pageup"), Some(0xff55));
        assert_eq!(keysym_of(" nonexistent-key "), None);
    }

    #[test]
    fn vk_map_covers_special_keys() {
        assert_eq!(vk_of("enter"), Some(0x0D)); // VK_RETURN
        assert_eq!(vk_of("Escape"), Some(0x1B));
        assert_eq!(vk_of("space"), Some(0x20));
        assert_eq!(vk_of("backspace"), Some(0x08));
        assert_eq!(vk_of("left"), Some(0x25));
        assert_eq!(vk_of("f1"), Some(0x70));
        assert_eq!(vk_of("pageup"), Some(0x21)); // VK_PRIOR
        assert_eq!(vk_of("nope"), None);
    }

    #[test]
    fn vk_map_covers_modifier_keys() {
        // Mac 快捷键透传：Cmd/Meta→Win，Ctrl/Alt/Shift 直映（缺失会打进首字母乱码）
        assert_eq!(vk_of("Meta"), Some(0x5B)); // VK_LWIN
        assert_eq!(vk_of("Command"), Some(0x5B));
        assert_eq!(vk_of("Control"), Some(0x11)); // VK_CONTROL
        assert_eq!(vk_of("Alt"), Some(0x12)); // VK_MENU
        assert_eq!(vk_of("Shift"), Some(0x10)); // VK_SHIFT
        assert_eq!(vk_of("CapsLock"), Some(0x14)); // VK_CAPITAL
        assert_eq!(vk_of("Insert"), Some(0x2D)); // VK_INSERT
    }

    #[test]
    fn clamp_runtime_codec_respects_probed_capabilities() {
        // 探测能力驱动：JPEG 恒可用；RAW 需 RGBA 采集源；原生需 RGBA + 原生库。
        assert_eq!(clamp_runtime_codec(crate::rc_media::CODEC_JPEG, false, false), crate::rc_media::CODEC_JPEG);
        assert_eq!(clamp_runtime_codec(crate::rc_media::CODEC_JPEG, true, true), crate::rc_media::CODEC_JPEG);
        assert_eq!(clamp_runtime_codec(crate::rc_media::CODEC_RAW_RGBA, false, false), crate::rc_media::CODEC_JPEG);
        assert_eq!(clamp_runtime_codec(crate::rc_media::CODEC_RAW_RGBA, true, false), crate::rc_media::CODEC_RAW_RGBA);
        assert_eq!(clamp_runtime_codec(crate::rc_media::CODEC_H264, true, false), crate::rc_media::CODEC_JPEG);
        assert_eq!(clamp_runtime_codec(crate::rc_media::CODEC_H264, false, true), crate::rc_media::CODEC_JPEG);
        assert_eq!(clamp_runtime_codec(crate::rc_media::CODEC_H264, true, true), crate::rc_media::CODEC_H264);
        assert_eq!(clamp_runtime_codec(crate::rc_media::CODEC_H265, true, true), crate::rc_media::CODEC_H265);
    }

    #[test]
    fn native_encoder_probe_false_without_lib() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        std::env::remove_var("YUDUAN_ENCODER_LIB");
        assert!(!native_encoder_ok(crate::rc_media::CODEC_H264));
        assert!(!native_encoder_ok(crate::rc_media::CODEC_JPEG)); // JPEG 非原生 codec
    }

    #[test]
    fn rc_offer_payload_parses_candidates() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        // 与 handle_rc_offer 取值表达式一致
        let j = crate::parse_json(
            "{\"session_id\":\"s-1\",\"candidates\":[\"192.168.1.10:19001\",\"10.0.0.2:19001\"]}".as_bytes(),
        )
        .unwrap();
        match j.get("candidates") {
            Some(crate::Json::Arr(a)) => {
                let v: Vec<&str> = a.iter().filter_map(|x| x.as_str()).collect();
                assert_eq!(v, vec!["192.168.1.10:19001", "10.0.0.2:19001"]);
            }
            _ => panic!("candidates 应为数组"),
        }
    }

    #[test]
    fn screen_header_builds_decodable_frame() {
        let hdr = screen_header(crate::rc_media::CODEC_JPEG, 320, 240, 9, 1500);
        assert_eq!(hdr.stream, crate::rc_media::STREAM_SCREEN);
        assert_eq!(hdr.codec, crate::rc_media::CODEC_JPEG);
        assert_ne!(hdr.flags & crate::rc_media::FLAG_KEYFRAME, 0);
        assert_eq!((hdr.width, hdr.height), (320, 240));
        assert_eq!(hdr.seq, 9);
        let jpeg = [0xFFu8, 0xD8, 0xFF, 0xD9];
        let frame = encode_frame(&hdr, &jpeg);
        let (got, pl) = crate::rc_media::decode_frame(&frame).unwrap();
        assert_eq!(got, hdr);
        assert_eq!(pl, &jpeg);
    }

    #[test]
    fn rc_select_payload_parses_with_defaults() {
        // 缺省字段 → jpeg / relay / 空地址（与 handle_rc_select 取值表达式一致）
        let j = crate::parse_json("{\"session_id\":\"s-1\"}".as_bytes()).unwrap();
        assert_eq!(j.get("codec").and_then(|v| v.as_i64()).unwrap_or(1) as u8, crate::rc_media::CODEC_JPEG);
        assert_eq!(j.get("transport").and_then(|v| v.as_str()).unwrap_or("relay"), "relay");
        assert_eq!(j.get("media_addr").and_then(|v| v.as_str()).unwrap_or(""), "");
        // 完整字段
        let j2 = crate::parse_json(
            "{\"codec\":1,\"transport\":\"p2p\",\"media_addr\":\"127.0.0.1:19500\"}".as_bytes(),
        )
        .unwrap();
        assert_eq!(j2.get("codec").and_then(|v| v.as_i64()).unwrap_or(0) as u8, crate::rc_media::CODEC_JPEG);
        assert_eq!(j2.get("transport").and_then(|v| v.as_str()).unwrap_or("relay"), "p2p");
        assert_eq!(j2.get("media_addr").and_then(|v| v.as_str()).unwrap_or(""), "127.0.0.1:19500");
    }

    #[test]
    fn rc_frame_payload_is_valid_json_with_base64() {
        let data = [0xFFu8, 0xD8, 0xFF, 0xD9];
        let payload = rc_frame_payload("s-42", 3, 640, 480, &data);
        let j = crate::parse_json(payload.as_bytes()).expect("rc_frame 载荷应为合法 JSON");
        assert_eq!(j.get("session_id").and_then(|v| v.as_str()), Some("s-42"));
        assert_eq!(j.get("seq").and_then(|v| v.as_i64()), Some(3));
        assert_eq!(j.get("width").and_then(|v| v.as_i64()), Some(640));
        assert_eq!(j.get("height").and_then(|v| v.as_i64()), Some(480));
        assert_eq!(j.get("format").and_then(|v| v.as_str()), Some("jpeg"));
        let b64 = j.get("data").and_then(|v| v.as_str()).unwrap();
        assert_eq!(base64_decode(b64).unwrap(), data);
    }

    #[test]
    fn rc_frame_interval_obeys_env_and_default() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        // 默认帧率来自 capabilities.fps（15 → 66ms/帧），环境变量可覆盖，非法值回退默认。
        std::env::remove_var("YUDUAN_RC_FPS");
        let d = rc_frame_interval_ms();
        assert_eq!(d, 1000 / 15, "默认应取 capabilities.fps");
        std::env::set_var("YUDUAN_RC_FPS", "10");
        assert_eq!(rc_frame_interval_ms(), 100);
        std::env::set_var("YUDUAN_RC_FPS", "0");
        assert_eq!(rc_frame_interval_ms(), d, "非法值应回退默认");
        std::env::set_var("YUDUAN_RC_FPS", "abc");
        assert_eq!(rc_frame_interval_ms(), d, "非数字应回退默认");
        std::env::remove_var("YUDUAN_RC_FPS");
        // 上限保护：极大 fps 不至于除零/忙轮询
        std::env::set_var("YUDUAN_RC_FPS", "1000000");
        assert_eq!(rc_frame_interval_ms(), 1);
        std::env::remove_var("YUDUAN_RC_FPS");
    }

    #[test]
    fn rc_qos_override_drives_interval_and_clamps() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        // §8.3.9 带宽自适应闭环：rc_qos 反馈优先级高于环境变量与默认值；
        // 越界（负数/超大/非数字）不应用；0 = 恢复默认（清覆盖）。
        std::env::remove_var("YUDUAN_RC_FPS");
        RC_FPS_QOS.store(0, Ordering::SeqCst);
        let d = rc_frame_interval_ms();

        // 合法反馈：4fps → 250ms/帧（优先级高于 env）
        std::env::set_var("YUDUAN_RC_FPS", "10");
        let p: crate::Json = crate::parse_json(br#"{"session_id":"s","fps":4,"reason":"decode_slow"}"#)
            .expect("合法 qos 载荷应可解析");
        handle_rc_qos(&p);
        assert_eq!(RC_FPS_QOS.load(Ordering::SeqCst), 4);
        assert_eq!(rc_frame_interval_ms(), 250, "QoS 覆盖应优先于 env/默认");

        // 越界反馈：不应用（保留 4）
        for bad in [br#"{"fps":-3}"#.as_slice(), br#"{"fps":500}"#, br#"{"fps":"abc"}"#, br#"{}"#] {
            let p: crate::Json = crate::parse_json(bad).expect("越界载荷本身应可解析");
            handle_rc_qos(&p);
            assert_eq!(RC_FPS_QOS.load(Ordering::SeqCst), 4, "越界反馈不应改变当前值");
        }

        // fps=0：恢复默认（清覆盖后回到 env=10）
        let p: crate::Json = crate::parse_json(br#"{"fps":0}"#).expect("fps=0 应可解析");
        handle_rc_qos(&p);
        assert_eq!(RC_FPS_QOS.load(Ordering::SeqCst), 0);
        assert_eq!(rc_frame_interval_ms(), 100, "清覆盖后应回到 env 值");

        std::env::remove_var("YUDUAN_RC_FPS");
        let _ = d;
    }

    #[test]
    fn rc_loss_cap_and_bitrate_policy() {
        // §8.3.15 丢包档位 + 码率阶梯（纯函数 + 原子量，不碰 env）。
        // 档位边界：≤2% 不限，≤5% → 15，≤10% → 8，>10% → 4
        assert_eq!(loss_cap_fps(0), None);
        assert_eq!(loss_cap_fps(2), None);
        assert_eq!(loss_cap_fps(3), Some(15));
        assert_eq!(loss_cap_fps(5), Some(15));
        assert_eq!(loss_cap_fps(6), Some(8));
        assert_eq!(loss_cap_fps(10), Some(8));
        assert_eq!(loss_cap_fps(11), Some(4));

        // 码率阶梯：丢包触发降档（基准 prev → 实测 → 默认 4000），下限 300
        assert_eq!(next_target_kbps(0, 0, 8, 0), (3200, 0));
        assert_eq!(next_target_kbps(0, 1000, 8, 0), (800, 0));
        assert_eq!(next_target_kbps(3200, 0, 3, 0), (2560, 0));
        assert_eq!(next_target_kbps(350, 0, 50, 0), (300, 0), "降档下限 300");
        // 无丢包：计数增长；连续 3 次后升档 ×1.25（上限 4000），计数清零
        assert_eq!(next_target_kbps(800, 0, 0, 0), (800, 1));
        assert_eq!(next_target_kbps(800, 0, 0, 2), (800, 3));
        assert_eq!(next_target_kbps(800, 0, 0, 3), (1000, 0));
        assert_eq!(next_target_kbps(3900, 0, 0, 3), (4000, 0), "升档上限 4000");
        assert_eq!(next_target_kbps(4000, 0, 0, 3), (4000, 4), "已达上限不再动");
        assert_eq!(next_target_kbps(0, 0, 0, 5), (0, 6), "未设目标不主动抬高");

        // JPEG 质量闭环：超预算降 10（下限 30）、低于半预算升 5（上限 92）、budget=0 不动
        assert_eq!(next_jpeg_q(80, 10_000, 5_000), 70);
        assert_eq!(next_jpeg_q(35, 10_000, 5_000), 30, "质量下限 30");
        assert_eq!(next_jpeg_q(80, 1_000, 5_000), 85);
        assert_eq!(next_jpeg_q(90, 1_000, 5_000), 92, "质量上限 92");
        assert_eq!(next_jpeg_q(80, 4_000, 5_000), 80, "预算内不变");
        assert_eq!(next_jpeg_q(80, 1_000, 0), 80, "未设目标不调节");
    }

    #[test]
    fn rc_qos_loss_and_kbps_apply() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        // §8.3.15：rc_qos.loss_pct/kbps 到达 → 丢包档位原子量 + 码率目标阶梯生效；
        // 越界载荷忽略；interval 与 RTT 档位取 min。
        RC_FPS_QOS.store(0, Ordering::SeqCst);
        RC_RTT_MS.store(0, Ordering::SeqCst);
        RC_LOSS_PCT.store(0, Ordering::SeqCst);
        RC_LOSS_CLEAR.store(0, Ordering::SeqCst);
        RC_KBPS_TARGET.store(0, Ordering::SeqCst);
        std::env::remove_var("YUDUAN_RC_FPS");

        // 丢包 8% + 实测 1000 kbps：帧率上限 8fps + 码率目标 1000*4/5=800
        let p: crate::Json =
            crate::parse_json(br#"{"session_id":"s","loss_pct":8,"kbps":1000}"#).expect("载荷应可解析");
        handle_rc_qos(&p);
        assert_eq!(RC_LOSS_PCT.load(Ordering::SeqCst), 8);
        assert_eq!(RC_KBPS_TARGET.load(Ordering::SeqCst), 800);
        assert_eq!(rc_frame_interval_ms(), 125, "丢包 8% 应夹到 8fps（125ms）");

        // 越界丢包（负数/>100）：不应用
        for bad in [br#"{"loss_pct":-1}"#.as_slice(), br#"{"loss_pct":101}"#, br#"{"loss_pct":"x"}"#] {
            let p: crate::Json = crate::parse_json(bad).expect("越界载荷本身应可解析");
            handle_rc_qos(&p);
            assert_eq!(RC_LOSS_PCT.load(Ordering::SeqCst), 8, "越界丢包不应改变当前值");
        }

        // 连续 4 次无丢包报告：码率 800 → 1000（恢复升档）
        let ok: crate::Json = crate::parse_json(br#"{"loss_pct":0}"#).expect("载荷应可解析");
        for _ in 0..4 {
            handle_rc_qos(&ok);
        }
        assert_eq!(RC_KBPS_TARGET.load(Ordering::SeqCst), 1000);

        // 收尾复位（防影响并行测试的其他用例）
        RC_LOSS_PCT.store(0, Ordering::SeqCst);
        RC_LOSS_CLEAR.store(0, Ordering::SeqCst);
        RC_KBPS_TARGET.store(0, Ordering::SeqCst);
        RC_KBPS_APPLIED.store(0, Ordering::SeqCst);
        RC_JPEG_Q.store(80, Ordering::SeqCst);
    }

    #[test]
    fn rc_rtt_cap_applies_over_target_fps() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        // §8.3.11 传输级自适应：RTT 档位上限与目标 fps 取 min；rc_qos.rtt_ms 越界忽略。
        RC_FPS_QOS.store(0, Ordering::SeqCst);
        RC_RTT_MS.store(0, Ordering::SeqCst);
        std::env::set_var("YUDUAN_RC_FPS", "30");

        // 档位边界：≤80 不限，≤200 → 15，≤400 → 8，>400 → 4
        assert_eq!(rtt_cap_fps(0), None);
        assert_eq!(rtt_cap_fps(80), None);
        assert_eq!(rtt_cap_fps(81), Some(15));
        assert_eq!(rtt_cap_fps(200), Some(15));
        assert_eq!(rtt_cap_fps(201), Some(8));
        assert_eq!(rtt_cap_fps(400), Some(8));
        assert_eq!(rtt_cap_fps(401), Some(4));
        assert_eq!(rtt_cap_fps(5000), Some(4));

        // rc_qos 携带 rtt_ms=300 → 目标 30fps 被夹到 8fps（125ms 间隔）
        let p: crate::Json = crate::parse_json(br#"{"session_id":"s","fps":0,"rtt_ms":300}"#).expect("应可解析");
        handle_rc_qos(&p);
        assert_eq!(RC_RTT_MS.load(Ordering::SeqCst), 300);
        assert_eq!(rc_frame_interval_ms(), 125, "RTT 300ms 应夹 8fps");

        // rtt 越界（60001/负数）忽略，不影响当前值
        for bad in [br#"{"rtt_ms":60001}"#.as_slice(), br#"{"rtt_ms":-1}"#] {
            let p: crate::Json = crate::parse_json(bad).expect("应可解析");
            handle_rc_qos(&p);
            assert_eq!(RC_RTT_MS.load(Ordering::SeqCst), 300, "越界 rtt 不应改变当前值");
        }

        // RTT 恢复良好（60ms）→ 回到目标 30fps（33ms）
        let p: crate::Json = crate::parse_json(br#"{"rtt_ms":60}"#).expect("应可解析");
        handle_rc_qos(&p);
        assert_eq!(rc_frame_interval_ms(), 33, "RTT 良好应解除上限");

        // 主端 fps 反馈与 RTT 上限同时生效：取 min（反馈 2fps → 500ms）
        let p: crate::Json = crate::parse_json(br#"{"fps":2}"#).expect("应可解析");
        handle_rc_qos(&p);
        assert_eq!(rc_frame_interval_ms(), 500, "min(反馈 2fps, RTT 上限 15fps) = 2fps");

        std::env::remove_var("YUDUAN_RC_FPS");
        RC_FPS_QOS.store(0, Ordering::SeqCst);
        RC_RTT_MS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn rc_capabilities_payload_is_flat_per_protocol() {
        // 载荷必须扁平（§8.3 / Go proto.RCCapabilitiesPayload）：session_id + codecs/max_w/max_h/fps
        let caps = crate::rc_media::Capabilities {
            codecs: vec![crate::rc_media::CODEC_RAW_RGBA, crate::rc_media::CODEC_JPEG],
            max_w: 1920,
            max_h: 1080,
            fps: 15,
        };
        let payload = format!("{{\"session_id\":{},{}}}", json_string("s-7"), caps.to_payload_fields());
        let j = crate::parse_json(payload.as_bytes()).expect("rc_capabilities 载荷应为合法 JSON");
        assert_eq!(j.get("session_id").and_then(|v| v.as_str()), Some("s-7"));
        // 扁平字段可直接取到（不得嵌套在 capabilities 下）
        assert!(j.get("capabilities").is_none(), "载荷不应嵌套 capabilities");
        assert_eq!(j.get("max_w").and_then(|v| v.as_i64()), Some(1920));
        assert_eq!(j.get("max_h").and_then(|v| v.as_i64()), Some(1080));
        assert_eq!(j.get("fps").and_then(|v| v.as_i64()), Some(15));
        match j.get("codecs") {
            Some(crate::Json::Arr(a)) => assert_eq!(a.len(), 2),
            _ => panic!("codecs 应为数组"),
        }
    }
}
