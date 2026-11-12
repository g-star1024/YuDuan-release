// 波次 2：远控会话内协作（副端 / 被控端实现）。
//
// 覆盖：W2-1 会话内双向文件传输（push 主端→终端 / pull 终端→主端，默认关闭）、
//       W2-2 会话内消息（管理员→远端员工可见提示）、
//       W2-3 水印 / 远端黑屏防窥视（采集后处理，不造假帧）、
//       W2-6 Ctrl+Alt+Del 直达（Windows 安全屏幕；macOS/Linux 无 SAS 语义，诚实回告）。
//
// 边界（铁律）：全部能力仅在既有远控会话内生效，不新增监听端口、不出公网（铁律 1/3）；
// 三平台同构实现，能力不足时以 rc_event 诚实回告，绝不伪造成功（铁律 6）。
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub(crate) type Writer = Arc<Mutex<Box<dyn Write + Send>>>;

// ===================== W2-3 画面状态（黑屏 / 水印） =====================

static RC_BLANK: AtomicBool = AtomicBool::new(false);
static RC_WATERMARK: AtomicBool = AtomicBool::new(false);
static RC_WM_TEXT: Mutex<Option<String>> = Mutex::new(None);
/// 最近一次采集的尺寸（黑屏帧复用，保证主端画面尺寸不跳变）。
static LAST_DIMS: Mutex<(usize, usize)> = Mutex::new((0, 0));

/// 会话开始时复位画面状态（避免上一次会话的黑屏残留到新会话）。
pub fn reset_display() {
    RC_BLANK.store(false, Ordering::SeqCst);
    RC_WATERMARK.store(false, Ordering::SeqCst);
    if let Ok(mut g) = RC_WM_TEXT.lock() {
        *g = None;
    }
}

/// 主端下发 rc_display：设置黑屏/水印状态，返回 (blank, watermark, 实际生效文本)。
pub fn set_display(blank: bool, watermark: bool, text: &str) -> (bool, bool, String) {
    RC_BLANK.store(blank, Ordering::SeqCst);
    RC_WATERMARK.store(watermark, Ordering::SeqCst);
    let wm = if text.is_empty() {
        format!("御端远控 {}", now_string())
    } else {
        text.to_string()
    };
    if let Ok(mut g) = RC_WM_TEXT.lock() {
        *g = Some(wm.clone());
    }
    (blank, watermark, wm)
}

/// 是否需要在采集后做画面处理（黑屏或水印任一开启）。
pub fn display_active() -> bool {
    RC_BLANK.load(Ordering::SeqCst) || RC_WATERMARK.load(Ordering::SeqCst)
}

pub fn blank_active() -> bool {
    RC_BLANK.load(Ordering::SeqCst)
}

/// 记录最近一次真实采集尺寸（黑屏帧沿用）。
pub fn note_dims(w: usize, h: usize) {
    if let Ok(mut g) = LAST_DIMS.lock() {
        *g = (w, h);
    }
}

/// 取最近采集尺寸（无则回退 1280×720，保证主端有画面而非空帧）。
pub fn last_dims() -> (usize, usize) {
    match LAST_DIMS.lock() {
        Ok(g) if g.0 > 0 && g.1 > 0 => *g,
        _ => (1280, 720),
    }
}

/// 生成黑屏帧（纯黑 RGBA，尺寸沿用最近采集尺寸）。
pub fn blank_frame() -> (Vec<u8>, usize, usize) {
    let (w, h) = last_dims();
    (vec![0u8; w * h * 4], w, h)
}

/// 对采集到的 RGBA 帧应用画面处理：黑屏→置黑；水印→叠加水印文本。
/// 输入必须是紧凑 RGBA8（宽×高×4）。
pub fn apply_display(mut rgba: Vec<u8>, w: usize, h: usize) -> Vec<u8> {
    if rgba.len() != w * h * 4 {
        return rgba;
    }
    if RC_BLANK.load(Ordering::SeqCst) {
        // 防窥视：整帧置黑（不解除控制、不中断会话，主端仍可继续键鼠操作）。
        for px in rgba.chunks_exact_mut(4) {
            px[0] = 0;
            px[1] = 0;
            px[2] = 0;
            px[3] = 255;
        }
        return rgba;
    }
    if RC_WATERMARK.load(Ordering::SeqCst) {
        let text = match RC_WM_TEXT.lock() {
            Ok(g) => g.clone().unwrap_or_else(|| format!("御端远控 {}", now_string())),
            Err(_) => format!("御端远控 {}", now_string()),
        };
        draw_watermark(&mut rgba, w, h, &text);
    }
    rgba
}

// ---- 5×7 点阵字体（无第三方依赖，纯 std） ----
// 每行 5 bit（bit4=最左列）。覆盖水印所需字符：数字、大写字母、空格与常见分隔符。
fn glyph(ch: char) -> Option<[u8; 7]> {
    let g: [u8; 7] = match ch {
        '0' => [0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110],
        '1' => [0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
        '2' => [0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111],
        '3' => [0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110],
        '4' => [0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010],
        '5' => [0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110],
        '6' => [0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110],
        '7' => [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000],
        '8' => [0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110],
        '9' => [0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100],
        'A' => [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'B' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110],
        'C' => [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
        'D' => [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110],
        'E' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
        'F' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000],
        'G' => [0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110],
        'H' => [0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'I' => [0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
        'J' => [0b00001, 0b00001, 0b00001, 0b00001, 0b10001, 0b10001, 0b01110],
        'K' => [0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001],
        'L' => [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111],
        'M' => [0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001],
        'N' => [0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001],
        'O' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'P' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
        'Q' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101],
        'R' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
        'S' => [0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110],
        'T' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
        'U' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'V' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100],
        'W' => [0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001],
        'X' => [0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001],
        'Y' => [0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100],
        'Z' => [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111],
        ' ' => [0, 0, 0, 0, 0, 0, 0],
        ':' => [0, 0b01100, 0b01100, 0, 0b01100, 0b01100, 0],
        '-' => [0, 0, 0, 0b11111, 0, 0, 0],
        '.' => [0, 0, 0, 0, 0, 0, 0b01100],
        '/' => [0b00001, 0b00010, 0b00010, 0b00100, 0b01000, 0b01000, 0b10000],
        '@' => [0b01110, 0b10001, 0b10111, 0b10101, 0b10111, 0b10000, 0b01110],
        '_' => [0, 0, 0, 0, 0, 0, 0b11111],
        '#' => [0b01010, 0b01010, 0b11111, 0b01010, 0b11111, 0b01010, 0b01010],
        _ => return None,
    };
    Some(g)
}

/// 水印：三处（左上 / 画面中心 / 右下）叠加半透明文本，先画暗描边再画亮字，
/// 保证在深浅不同底色的屏幕上均可读（截图外泄可追溯到操作员工号与时间）。
fn draw_watermark(rgba: &mut [u8], w: usize, h: usize, text: &str) {
    let scale = 2usize;
    let cw = 6usize * scale; // 字宽 5 + 间隔 1
    let chh = 8usize * scale;
    let tw = text.chars().count() * cw;
    let margin = 24usize;
    let mut spots: Vec<(usize, usize)> = Vec::new();
    spots.push((margin, margin));
    if w > tw + margin && h > chh + margin {
        spots.push((w - tw - margin, h - chh - margin));
        spots.push(((w - tw) / 2, (h - chh) / 2));
    }
    for (ox, oy) in spots {
        for (i, ch) in text.chars().enumerate() {
            let g = match glyph(ch.to_ascii_uppercase()) {
                Some(g) => g,
                None => continue,
            };
            let gx = ox + i * cw;
            let gy = oy;
            for r in 0..7usize {
                for c in 0..5usize {
                    if (g[r] >> (4 - c)) & 1 == 0 {
                        continue;
                    }
                    for dy in 0..scale {
                        for dx in 0..scale {
                            // 暗描边（右下偏移 1px）——浅色底上仍可辨
                            shade(rgba, w, h, gx + c * scale + dx + 1, gy + r * scale + dy + 1, -90);
                            // 亮字
                            shade(rgba, w, h, gx + c * scale + dx, gy + r * scale + dy, 70);
                        }
                    }
                }
            }
        }
    }
}

/// 单像素亮度调整（delta 正负），越界忽略。
fn shade(rgba: &mut [u8], w: usize, h: usize, x: usize, y: usize, delta: i32) {
    if x >= w || y >= h {
        return;
    }
    let i = (y * w + x) * 4;
    if i + 3 >= rgba.len() {
        return;
    }
    for k in 0..3 {
        let v = rgba[i + k] as i32 + delta;
        rgba[i + k] = v.clamp(0, 255) as u8;
    }
    rgba[i + 3] = 255;
}

// ===================== W2-2 会话内消息（管理员 → 远端员工） =====================

/// 主端发来会话内消息：在被控端以系统通知提示（远端员工知情），并回告已送达。
/// 说明：远端→主端的回复需要副端常驻托盘 UI 提供输入源，本波次未实现，
///      协议与中枢中继双向均已打通，待托盘 UI 落地后接入（见 dev-status 待用户决策）。
pub fn handle_chat(writer: &Writer, rng: &Arc<Mutex<crate::Lcg>>, seq: &Arc<Mutex<u64>>, text: &str, from: &str) {
    let shown = show_chat_notice(text);
    let msg = if shown {
        "会话消息已在被控端提示"
    } else {
        "会话消息已记录（本机无可用通知通道，已写入运行日志）"
    };
    eprintln!("[agent] [会话消息] {}：{}", from, text);
    let payload = format!(
        "{{\"session_id\":{},\"kind\":{},\"message\":{}}}",
        crate::json_string(&current_session()),
        crate::json_string("chat_delivered"),
        crate::json_string(msg)
    );
    send_envelope(writer, rng, seq, "rc_event", &payload);
}

/// 系统通知（best-effort，不阻塞、不失败即放弃）：macOS osascript / Linux notify-send /
/// Windows PowerShell Toast（失败则仅记日志）。
fn show_chat_notice(text: &str) -> bool {
    let safe = text.replace('"', "'").replace('\n', " ").chars().take(120).collect::<String>();
    let ok = if cfg!(target_os = "macos") {
        std::process::Command::new("osascript")
            .args([
                "-e",
                &format!(
                    "display notification \"{}\" with title \"御端 · 管理员消息\"",
                    safe
                ),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else if cfg!(target_os = "linux") {
        std::process::Command::new("notify-send")
            .args(["御端 · 管理员消息", &safe])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else if cfg!(target_os = "windows") {
        // Windows：PowerShell BurntToast 不可假设存在 → 用 msg 不可靠；
        // 采用 Shell 弹出一次性消息框（独立进程，阻塞的是子进程不是 agent）。
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Add-Type -AssemblyName System.Windows.Forms;[System.Windows.Forms.MessageBox]::Show('{}','御端 · 管理员消息')",
                    safe.replace('\'', "")
                ),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        false
    };
    ok
}

// ===================== W2-6 Ctrl+Alt+Del 直达 =====================

/// Ctrl+Alt+Del（安全注意序列 SAS）不能由普通进程的 SendInput 合成——
/// Windows 只在 Winlogon 安全桌面接受该序列，用户态模拟必被忽略（非代码缺陷）。
/// 采用官方可达路径：拉起「Windows 安全」屏幕（shell:::{2559a1f2-...}），
/// 等价于用户按 Ctrl+Alt+Del 后看到的界面。
/// macOS / Linux 无 SAS 语义：不做伪造注入，诚实回告不支持。
pub fn handle_cad(writer: &Writer, rng: &Arc<Mutex<crate::Lcg>>, seq: &Arc<Mutex<u64>>) {
    if cfg!(target_os = "windows") {
        let ok = std::process::Command::new("explorer.exe")
            .args(["shell:::{2559a1f2-21d7-11d4-bdaf-00c04f60b9f0}"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let payload = format!(
            "{{\"session_id\":{},\"kind\":{},\"message\":{}}}",
            crate::json_string(&current_session()),
            crate::json_string("cad"),
            crate::json_string(if ok {
                "已拉起 Windows 安全屏幕"
            } else {
                "拉起 Windows 安全屏幕失败（可能被策略拦截）"
            })
        );
        send_envelope(writer, rng, seq, "rc_event", &payload);
        return;
    }
    let payload = format!(
        "{{\"session_id\":{},\"kind\":{},\"message\":{}}}",
        crate::json_string(&current_session()),
        crate::json_string("cad_unsupported"),
        crate::json_string("当前平台无 Ctrl+Alt+Del 安全序列语义，已忽略该指令")
    );
    send_envelope(writer, rng, seq, "rc_event", &payload);
}

// ===================== W2-1 会话内文件传输 =====================

/// 单文件传输上限（50MB）：防止会话内大文件拖垮控制面长连接。
const MAX_TRANSFER_BYTES: u64 = 50 * 1024 * 1024;
/// 默认分片大小（64KB，base64 后约 87KB，仍在 WS 文本帧合理区间）。
const DEFAULT_CHUNK: usize = 64 * 1024;

struct Transfer {
    direction: String, // "push" | "pull"
    name: String,
    path: String, // push=落盘绝对路径；pull=源绝对路径
    size: u64,
    expect_sha: String,
    received: u64,
    buf: Vec<u8>,
    next_seq: i64,
    chunk: usize,
}

fn transfers() -> &'static Mutex<HashMap<String, Transfer>> {
    static T: OnceLock<Mutex<HashMap<String, Transfer>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 传输落盘目录：优先 ~/Downloads，其次系统临时目录下的 yuduan-transfer。
fn transfer_dir() -> std::path::PathBuf {
    let base = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from));
    if let Some(home) = base {
        let dl = home.join("Downloads");
        if dl.is_dir() {
            return dl.join("YuDuan");
        }
        return home.join("YuDuan");
    }
    std::env::temp_dir().join("yuduan-transfer")
}

/// 文件名安全校验：拒绝路径分隔符与相对路径穿越，只允许扁平文件名。
fn safe_name(name: &str) -> Option<String> {
    let n = name.trim();
    if n.is_empty() || n.contains('/') || n.contains('\\') || n.contains("..") || n.starts_with('.') {
        return None;
    }
    // 过滤控制字符，避免写入异常文件名
    let cleaned: String = n.chars().filter(|c| !c.is_control()).collect();
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned)
}

/// pull 允许根目录（合规默认关闭）：未配置 YUDUAN_RC_PULL_ROOT 时拒绝一切拉取。
fn pull_root() -> Option<std::path::PathBuf> {
    let r = std::env::var_os("YUDUAN_RC_PULL_ROOT")?;
    let p = std::path::PathBuf::from(r);
    p.canonicalize().ok()
}

/// 主端发起传输提议（rc_file_offer）。push=主端下发文件到本机；pull=从本机拉取文件。
pub fn handle_file_offer(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    p: &crate::Json,
) {
    let sid = p.get("session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tid = p.get("transfer_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let direction = p.get("direction").and_then(|v| v.as_str()).unwrap_or("push").to_string();
    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let size = p.get("size").and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u64;
    let sha = p.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let path = p.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if tid.is_empty() {
        return;
    }

    if direction == "pull" {
        // 合规：拉取属「从终端采集数据」，默认关闭（铁律 5 最小必要），
        // 须显式配置允许根目录且目标路径落在其内。
        let root = match pull_root() {
            Some(r) => r,
            None => {
                send_file_done(writer, rng, seq, &sid, &tid, false, "本机未启用文件拉取（未配置 YUDUAN_RC_PULL_ROOT）", 0, "");
                return;
            }
        };
        let target = match std::path::PathBuf::from(&path).canonicalize() {
            Ok(t) => t,
            Err(_) => {
                send_file_done(writer, rng, seq, &sid, &tid, false, "文件不存在或不可读", 0, "");
                return;
            }
        };
        if !target.starts_with(&root) {
            send_file_done(writer, rng, seq, &sid, &tid, false, "目标路径不在允许根目录内，已拒绝", 0, "");
            return;
        }
        let meta = match std::fs::metadata(&target) {
            Ok(m) => m,
            Err(_) => {
                send_file_done(writer, rng, seq, &sid, &tid, false, "无法读取文件元信息", 0, "");
                return;
            }
        };
        if !meta.is_file() {
            send_file_done(writer, rng, seq, &sid, &tid, false, "目标不是普通文件", 0, "");
            return;
        }
        if meta.len() > MAX_TRANSFER_BYTES {
            send_file_done(writer, rng, seq, &sid, &tid, false, "文件超过 50MB 上限", 0, "");
            return;
        }
        let data = match std::fs::read(&target) {
            Ok(d) => d,
            Err(_) => {
                send_file_done(writer, rng, seq, &sid, &tid, false, "读取文件失败", 0, "");
                return;
            }
        };
        let actual_sha = crate::sha256::hex_encode(&crate::sha256::sha256(&data));
        let fname = target
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| name.clone());
        // 登记并等待主端 rc_file_accept 后开始分片（主端可据此拒绝过大文件）
        let total = data.len();
        if let Ok(mut g) = transfers().lock() {
            g.insert(
                tid.clone(),
                Transfer {
                    direction: "pull".into(),
                    name: fname.clone(),
                    path: target.to_string_lossy().to_string(),
                    size: total as u64,
                    expect_sha: actual_sha.clone(),
                    received: 0,
                    buf: data.clone(),
                    next_seq: 0,
                    chunk: DEFAULT_CHUNK,
                },
            );
        }
        // 应答：chunk_size 位携带文件总字节数，供主端判断是否接受（同 Go 协议注释）
        send_file_accept(writer, rng, seq, &sid, &tid, true, "", total);
        return;
    }

    // push：主端下发文件到本机
    let clean = match safe_name(&name) {
        Some(n) => n,
        None => {
            send_file_done(writer, rng, seq, &sid, &tid, false, "文件名非法（含路径分隔符或相对路径）", 0, "");
            return;
        }
    };
    if size > MAX_TRANSFER_BYTES {
        send_file_done(writer, rng, seq, &sid, &tid, false, "文件超过 50MB 上限", 0, "");
        return;
    }
    let dir = transfer_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        send_file_done(writer, rng, seq, &sid, &tid, false, &format!("创建接收目录失败: {}", e), 0, "");
        return;
    }
    let dest = dir.join(&clean);
    if let Ok(mut g) = transfers().lock() {
        g.insert(
            tid.clone(),
            Transfer {
                direction: "push".into(),
                name: clean.clone(),
                path: dest.to_string_lossy().to_string(),
                size,
                expect_sha: sha,
                received: 0,
                buf: Vec::new(),
                next_seq: 0,
                chunk: DEFAULT_CHUNK,
            },
        );
    }
    eprintln!("[agent] 接收文件提议 tid={} name={} size={}B → {}", tid, clean, size, dest.display());
    send_file_accept(writer, rng, seq, &sid, &tid, true, "", DEFAULT_CHUNK);
}

/// 主端应答（rc_file_accept）：pull 方向由本机开始分片上传。
pub fn handle_file_accept(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    p: &crate::Json,
) {
    let sid = p.get("session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tid = p.get("transfer_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let accept = p.get("accept").and_then(|v| v.as_bool()).unwrap_or(false);
    let chunk = p.get("chunk_size").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
    if !accept {
        if let Ok(mut g) = transfers().lock() {
            g.remove(&tid);
        }
        eprintln!("[agent] 主端拒绝传输 tid={}", tid);
        return;
    }
    // 仅 pull 方向由本机发送分片；push 方向等主端分片到达。
    let job: Option<(Vec<u8>, usize, String)> = {
        let mut g = match transfers().lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        match g.get_mut(&tid) {
            Some(t) if t.direction == "pull" => {
                if chunk > 0 {
                    t.chunk = chunk.clamp(1024, 1024 * 1024);
                }
                Some((t.buf.clone(), t.chunk, t.expect_sha.clone()))
            }
            Some(t) => {
                if chunk > 0 {
                    t.chunk = chunk.clamp(1024, 1024 * 1024);
                }
                None
            }
            None => None,
        }
    };
    if let Some((data, cs, sha)) = job {
        send_chunks(writer, rng, seq, &sid, &tid, &data, cs);
        send_file_done(writer, rng, seq, &sid, &tid, true, "", data.len() as u64, &sha);
        if let Ok(mut g) = transfers().lock() {
            g.remove(&tid);
        }
    }
}

/// 收到分片（rc_file_chunk）：push 方向累积，收满即落盘并校验。
pub fn handle_file_chunk(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    p: &crate::Json,
) {
    let sid = p.get("session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tid = p.get("transfer_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let seq_no = p.get("seq").and_then(|v| v.as_i64()).unwrap_or(-1);
    let data_b64 = p.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let bytes = match crate::sha256::base64_decode(&data_b64) {
        Some(b) => b,
        None => {
            send_file_done(writer, rng, seq, &sid, &tid, false, "分片 base64 解码失败", 0, "");
            return;
        }
    };
    let done: Option<(String, Vec<u8>, String, u64)> = {
        let mut g = match transfers().lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let t = match g.get_mut(&tid) {
            Some(t) => t,
            None => return,
        };
        if seq_no >= 0 && t.next_seq > 0 && seq_no != t.next_seq {
            // 乱序/重放分片：直接判失败（顺序传输，不做重排缓冲）
            let m = format!("分片序号不连续（期望 {} 收到 {}）", t.next_seq, seq_no);
            return drop_send_done(writer, rng, seq, &sid, &tid, &m);
        }
        t.next_seq = seq_no + 1;
        t.buf.extend_from_slice(&bytes);
        t.received += bytes.len() as u64;
        if t.received >= t.size {
            Some((t.path.clone(), std::mem::take(&mut t.buf), t.expect_sha.clone(), t.received))
        } else {
            None
        }
    };
    if let Some((path, buf, expect, total)) = done {
        let actual = crate::sha256::hex_encode(&crate::sha256::sha256(&buf));
        if !expect.is_empty() && !expect.eq_ignore_ascii_case(&actual) {
            let m = format!("校验失败 期望 {} 实得 {}", expect, actual);
            send_file_done(writer, rng, seq, &sid, &tid, false, &m, total, &actual);
        } else if let Err(e) = std::fs::write(&path, &buf) {
            send_file_done(writer, rng, seq, &sid, &tid, false, &format!("写入失败: {}", e), total, &actual);
        } else {
            eprintln!("[agent] 文件接收完成 tid={} → {}（{}B sha256={}）", tid, path, total, actual);
            send_file_done(writer, rng, seq, &sid, &tid, true, "", total, &actual);
        }
        if let Ok(mut g) = transfers().lock() {
            g.remove(&tid);
        }
    }
}

fn drop_send_done(writer: &Writer, rng: &Arc<Mutex<crate::Lcg>>, seq: &Arc<Mutex<u64>>, sid: &str, tid: &str, m: &str) {
    send_file_done(writer, rng, seq, sid, tid, false, m, 0, "");
    if let Ok(mut g) = transfers().lock() {
        g.remove(tid);
    }
}

/// 会话结束或未完成的传输清理（防止残留占用内存）。
pub fn cleanup_transfers() {
    if let Ok(mut g) = transfers().lock() {
        if !g.is_empty() {
            eprintln!("[agent] 清理未完成的会话内传输 {} 项", g.len());
        }
        g.clear();
    }
}

fn send_chunks(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    sid: &str,
    tid: &str,
    data: &[u8],
    cs: usize,
) {
    let mut i = 0i64;
    for part in data.chunks(cs.max(1024)) {
        let payload = format!(
            "{{\"session_id\":{},\"transfer_id\":{},\"seq\":{},\"data\":{}}}",
            crate::json_string(sid),
            crate::json_string(tid),
            i,
            crate::json_string(&crate::base64_encode(part))
        );
        send_envelope(writer, rng, seq, "rc_file_chunk", &payload);
        i += 1;
    }
}

fn send_file_accept(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    sid: &str,
    tid: &str,
    accept: bool,
    reason: &str,
    total_or_chunk: usize,
) {
    // 复用同一字段位：pull 提议应答时传文件总字节数；push 应答时传期望分片大小。
    let payload = format!(
        "{{\"session_id\":{},\"transfer_id\":{},\"accept\":{},\"reason\":{},\"chunk_size\":{}}}",
        crate::json_string(sid),
        crate::json_string(tid),
        accept,
        crate::json_string(reason),
        total_or_chunk
    );
    send_envelope(writer, rng, seq, "rc_file_accept", &payload);
}

fn send_file_done(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    sid: &str,
    tid: &str,
    ok: bool,
    err: &str,
    bytes: u64,
    sha: &str,
) {
    let payload = format!(
        "{{\"session_id\":{},\"transfer_id\":{},\"ok\":{},\"error\":{},\"bytes\":{},\"sha256\":{}}}",
        crate::json_string(sid),
        crate::json_string(tid),
        ok,
        crate::json_string(err),
        bytes,
        crate::json_string(sha)
    );
    send_envelope(writer, rng, seq, "rc_file_done", &payload);
}

// ===================== 公共小工具 =====================

fn send_envelope(
    writer: &Writer,
    rng: &Arc<Mutex<crate::Lcg>>,
    seq: &Arc<Mutex<u64>>,
    typ: &str,
    payload: &str,
) {
    let m = {
        let mut rng_g = rng.lock().unwrap_or_else(|p| p.into_inner());
        let mut seq_g = seq.lock().unwrap_or_else(|p| p.into_inner());
        crate::build_envelope(&mut rng_g, &mut seq_g, typ, payload)
    };
    let _ = crate::send_ws_text(&mut *writer.lock().unwrap_or_else(|p| p.into_inner()), m.as_bytes());
}

fn current_session() -> String {
    crate::rc::current_session_id()
}

fn now_string() -> String {
    // 无时间格式化依赖：取 Unix 秒 + 简易本地日期（UTC）
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    let hms = secs % 86400;
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, hms / 3600, (hms % 3600) / 60)
}

/// 天数 → 公历年月日（Howard Hinnant 算法，纯整数，无依赖）。
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyph_covers_watermark_chars() {
        for c in "ADMIN 2026-10-28 00:30".chars() {
            assert!(glyph(c.to_ascii_uppercase()).is_some(), "缺字形: {}", c);
        }
        assert!(glyph('~').is_none());
    }

    #[test]
    fn blank_frame_is_all_black() {
        note_dims(64, 32);
        let (buf, w, h) = blank_frame();
        assert_eq!((w, h), (64, 32));
        assert_eq!(buf.len(), 64 * 32 * 4);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn apply_display_blank_zeroes_rgb() {
        note_dims(4, 2);
        let mut rgba = vec![200u8; 4 * 2 * 4];
        for px in rgba.chunks_exact_mut(4) {
            px[3] = 255;
        }
        set_display(true, false, "");
        let out = apply_display(rgba, 4, 2);
        for px in out.chunks_exact(4) {
            assert_eq!(&px[0..3], &[0, 0, 0]);
            assert_eq!(px[3], 255);
        }
        reset_display();
    }

    #[test]
    fn apply_display_watermark_changes_pixels() {
        note_dims(320, 120);
        let base = vec![128u8; 320 * 120 * 4];
        set_display(false, true, "ADMIN 2026");
        let out = apply_display(base.clone(), 320, 120);
        let diff = out.iter().zip(base.iter()).filter(|(a, b)| a != b).count();
        assert!(diff > 500, "水印应改变足量像素，实际 {}", diff);
        reset_display();
    }

    #[test]
    fn safe_name_rejects_traversal() {
        assert_eq!(safe_name("a.txt"), Some("a.txt".to_string()));
        assert_eq!(safe_name("../etc/passwd"), None);
        assert_eq!(safe_name("dir/a.txt"), None);
        assert_eq!(safe_name(""), None);
    }

    #[test]
    fn civil_date_conversion() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20727), (2026, 10, 1));
        assert_eq!(civil_from_days(20754), (2026, 10, 28));
    }

    #[test]
    fn shade_clamps_at_bounds() {
        let mut buf = vec![0u8; 4 * 4 * 4];
        shade(&mut buf, 4, 4, 100, 100, 300); // 越界：不应 panic
        shade(&mut buf, 4, 4, 1, 1, -300);
        assert_eq!(buf[(1 * 4 + 1) * 4], 0);
    }
}
