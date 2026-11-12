// 御端（YuDuan）副端 —— Windows 服务控制管理器（SCM）集成（std-only + Win32 FFI）
//
// 为什么需要这一层
// ─────────────────────────────────────────────────────────────
// 产品需求：副端「注册激活 → 关闭窗口 → 后台常驻 → 开机自启 → 断联后自动拉起（守卫）」。
// Windows 上唯一稳妥的落点是系统服务：
//   开机自启       = SCM 启动类型 SERVICE_AUTO_START
//   断联/崩溃拉起  = SCM 失败恢复策略（sc.exe failure ... actions=restart/5000）
//
// 但「系统服务」有一个硬前提，也是历史踩坑所在：进程被 SCM 拉起后，必须在 30s 内调用
// StartServiceCtrlDispatcherW 完成握手；否则 SCM 记 1053「服务未及时响应」，
// 失败恢复策略视为未生效，服务实际处于「拉起但失控」状态。
// 此前副端只是普通控制台进程，被 sc.exe 创建的服务指向它，缺少这一握手。
// 本模块用裸 Win32 FFI 补齐（不引入 windows-service crate，保持零第三方依赖铁律）。
//
// 非 Windows 平台由 main.rs 提供同名桩，保证三平台同一份源码可编译。

use std::os::raw::{c_int, c_uint, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

// —— SCM 常量（advapi32 文档常量，非推导值） ——
const SC_MANAGER_ALL_ACCESS: c_uint = 0xF003F; // SC_MANAGER_ALL_ACCESS
const SERVICE_ALL_ACCESS: c_uint = 0xF01FF;
const SERVICE_WIN32_OWN_PROCESS: c_uint = 0x00000010;
const SERVICE_AUTO_START: c_uint = 2;
// v0.4.45（N10）：ChangeServiceConfigW 的「该字段不变」哨兵值（MSDN）。
const SERVICE_NO_CHANGE: c_uint = 0xFFFF_FFFF;
const SERVICE_ERROR_NORMAL: c_uint = 1;
const SERVICE_STOPPED: c_uint = 1;
const SERVICE_START_PENDING: c_uint = 2;
const SERVICE_STOP_PENDING: c_uint = 3;
const SERVICE_RUNNING: c_uint = 4;
// v0.4.44（第 24 轮报告 V3 回归 · 真根因）：SERVICE_ACCEPT_* 常量此前写错——
//   SERVICE_ACCEPT_STOP      官方值 0x00000001（此前误写 0x00000002 = PAUSE_CONTINUE）
//   SERVICE_ACCEPT_SHUTDOWN  官方值 0x00000004（此前误写 0x00000080 = SESSIONCHANGE）
// 错值导致 report(RUNNING) 上报的 dwControlsAccepted=0x82（PAUSE|SESSION），STOP 位
// 从未开放 → SCM 直接拒收 STOP 报 1052「control is not valid」——这正是 v0.4.40/v0.4.41
// 两轮「优雅停止」修复实机均无效的共同根因（210 用户自定义控制码不受 accept 位约束，
// 故热切换一直正常，掩盖了该错误）。值依据 MSDN SERVICE_STATUS.dwControlsAccepted。
const SERVICE_ACCEPT_STOP: c_uint = 0x00000001;
const SERVICE_ACCEPT_SHUTDOWN: c_uint = 0x00000004;
// v0.4.44（V3 第三层 · CI 探针实证）：SERVICE_CONTROL_* 常量此前也写错——
//   SERVICE_CONTROL_STOP      官方值 0x00000001（此前误写 0 = 无效控制码）
//   SERVICE_CONTROL_SHUTDOWN  官方值 0x00000005（此前误写 0x00000008 = NETBINDREMOVE）
// CI 探针（svc-trace.log）实锤：accept 位修复后 sc stop exit=0、SCM 成功投递
// control=1，但 handle_ex 的 match 按 0 匹配 → 不命中 → 服务永不停止。依据 MSDN
// HandlerEx 文档（SERVICE_CONTROL_STOP 0x1 / PAUSE 0x2 / CONTINUE 0x3 /
// INTERROGATE 0x4 / SHUTDOWN 0x5）。210 用户自定义控制码此前写对，故热切换一直
// 正常，掩盖了此处错误。
const SERVICE_CONTROL_STOP: c_uint = 0x00000001;
const SERVICE_CONTROL_SHUTDOWN: c_uint = 0x00000005;
const SERVICE_CONFIG_FAILURE_ACTIONS: c_uint = 2;
const SC_ACTION_RESTART: c_uint = 1; // SERVICE_FAILURE_ACTION.type：重启服务（sc.exe failure ... restart）
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: c_uint = 1063;
const ERROR_SERVICE_EXISTS: c_uint = 1073;
const ERROR_SERVICE_DOES_NOT_EXIST: c_uint = 1060;
// v0.4.17（第九轮实测报告缺陷B）：ERROR_SERVICE_MARKED_DELETE——DeleteService 后
// SCM 侧句柄未全部释放时服务名处于「标记删除」，紧随的同名 CreateServiceW 必失败。
const ERROR_SERVICE_MARKED_DELETE: c_uint = 1072;
const ERROR_ACCESS_DENIED: c_uint = 5;
// v0.4.40：自定义服务控制码（128~255）与所需访问权限。控制码不受
// dwControlsAccepted 的 SERVICE_ACCEPT_* 位约束，SCM 会直接投递给 HandlerEx。
const SERVICE_USER_DEFINED_CONTROL: c_uint = 0x0100;
const YUDUAN_CTRL_RELOAD_HUB: c_uint = 210;

type ServiceMainFn = unsafe extern "system" fn(argc: c_uint, argv: *mut *mut u16) -> c_uint;
type HandlerExFn =
    unsafe extern "system" fn(control: c_uint, event: c_uint, data: *mut c_void, ctx: *mut c_void);

#[repr(C)]
struct ServiceStatus {
    dw_service_type: c_uint,
    dw_current_state: c_uint,
    dw_controls_accepted: c_uint,
    dw_win32_exit_code: c_uint,
    dw_service_specific_exit_code: c_uint,
    dw_check_point: c_uint,
    dw_wait_hint: c_uint,
}

#[repr(C)]
struct ServiceTableEntryW {
    lp_service_name: *mut u16,
    lp_service_proc: Option<ServiceMainFn>,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct ServiceFailureAction {
    action_type: c_uint, // SC_ACTION_TYPE（SC_ACTION_RESTART=1）
    dw_delay: c_uint,    // 重启前等待毫秒数
}

#[repr(C)]
struct ServiceFailureActions {
    dw_reset_period: c_uint,
    lp_reboot_msg: *mut u16,
    lp_command: *mut u16,
    // v0.4.11（实测报告问题 3）：Win32 SERVICE_FAILURE_ACTIONSW 在 lpCommand 与
    // lpsaActions 之间有 cActions（动作计数）字段，此前漏写导致 SCM 读到垃圾计数，
    // ChangeServiceConfig2W 报 win32 1734、失败恢复策略始终未生效。补上后对齐官方布局。
    c_actions: c_uint, // lpsaActions 指向的 SC_ACTION 数量
    lpsa_actions: *mut ServiceFailureAction,
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenSCManagerW(machine: *mut u16, database: *mut u16, access: c_uint) -> *mut c_void;
    fn OpenServiceW(scm: *mut c_void, name: *mut u16, access: c_uint) -> *mut c_void;
    // v0.4.45（N10）：就地复用已存在服务（改 binPath/显示名/自启/错误控制），重装零删除。
    fn ChangeServiceConfigW(
        svc: *mut c_void,
        service_type: c_uint,
        start_type: c_uint,
        error_control: c_uint,
        binary_path: *mut u16,
        load_group: *mut u16,
        tag_id: *mut c_uint,
        dependencies: *mut u16,
        start_name: *mut u16,
        password: *mut u16,
        display_name: *mut u16,
    ) -> c_int;
    fn CreateServiceW(
        scm: *mut c_void,
        service_name: *mut u16,
        display_name: *mut u16,
        desired_access: c_uint,
        service_type: c_uint,
        start_type: c_uint,
        error_control: c_uint,
        binary_path_name: *mut u16,
        load_order_group: *mut u16,
        tag_id: *mut c_uint,
        dependencies: *mut u16,
        service_start_name: *mut u16,
        password: *mut u16,
    ) -> *mut c_void;
    fn ChangeServiceConfig2W(svc: *mut c_void, level: c_uint, info: *mut c_void) -> c_int;
    fn DeleteService(svc: *mut c_void) -> c_int;
    fn ControlService(svc: *mut c_void, control: c_uint, status: *mut ServiceStatus) -> c_int;
    fn QueryServiceStatus(svc: *mut c_void, status: *mut ServiceStatus) -> c_int;
    fn QueryServiceStatusEx(
        svc: *mut c_void,
        info_level: c_uint,
        buffer: *mut c_void,
        buf_size: c_uint,
        needed: *mut c_uint,
    ) -> c_int;
    fn StartServiceW(svc: *mut c_void, argc: u32, argv: *const *const u16) -> c_int;
    fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> c_int;
    fn RegisterServiceCtrlHandlerExW(
        name: *mut u16,
        handler: Option<HandlerExFn>,
        ctx: *mut c_void,
    ) -> *mut c_void;
    fn SetServiceStatus(handle: *mut c_void, status: *const ServiceStatus) -> c_int;
    // v0.4.23：查询服务配置（lpBinaryPathName）——就地升级判定用
    fn QueryServiceConfigW(
        svc: *mut c_void,
        buf: *mut QueryServiceConfigW,
        buf_size: u32,
        needed: *mut u32,
    ) -> c_int;
}

/// QUERY_SERVICE_CONFIGW（只关心 lpBinaryPathName；其余字段按布局占位）。
#[repr(C)]
struct QueryServiceConfigW {
    dw_service_type: u32,
    dw_start_type: u32,
    dw_error_control: u32,
    lp_binary_path_name: *mut u16,
    lp_load_order_group: *mut u16,
    dw_tag_id: u32,
    lp_dependencies: *mut u16,
    lp_service_start_name: *mut u16,
    lp_display_name: *mut u16,
}

const SERVICE_QUERY_CONFIG: c_uint = 0x0001;
const ERROR_INSUFFICIENT_BUFFER: c_uint = 122;

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> c_uint;
    fn CloseHandle(handle: *mut c_void) -> c_int;
}

// —— 跨线程全局态 ——
/// SCM 停止/关机信号。service 控制处理器写，agent 主循环读。
static STOP: AtomicBool = AtomicBool::new(false);
/// v0.4.40：是否曾上报 SERVICE_STOPPED。一旦上报，忽略后续任何非 STOPPED 的
/// 状态上报，防止 service_main 尾部把 STOPPED→STOP_PENDING 倒退（控制处理器
/// 现在会立即上报 STOPPED，不等主循环返回）。
static STOPPED_REPORTED: AtomicBool = AtomicBool::new(false);
/// 本进程是否以服务模式运行（用于日志与远控行为区分，例如服务模式不弹窗）。
static IN_SERVICE: AtomicBool = AtomicBool::new(false);
/// RegisterServiceCtrlHandlerExW 返回的句柄（控制处理器与主函数共用）。
/// 以 usize 保存（原始指针非 Send/Sync，静态原子量/互斥量要求 Send+Sync）。
static SERVICE_HANDLE: Mutex<Option<usize>> = Mutex::new(None);
/// agent 主循环闭包（service 主函数取出后执行）。
static SERVICE_MAIN: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);
/// 服务名宽字符串的 (ptr as usize, capacity) —— 泄漏到进程生命周期，SCM 从表项读取时必须有效。
static SVC_NAME: Mutex<Option<(usize, usize)>> = Mutex::new(None);

/// 字符串 → 宽字符（含结尾 NUL）。返回 (指针, capacity)，调用方负责 `Vec::from_raw_parts` 回收。
fn wide_parts(s: &str) -> (*mut u16, usize) {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    let (p, _len, c) = v.into_raw_parts();
    (p, c)
}

unsafe fn drop_wide(p: *mut u16, cap: usize) {
    drop(Vec::from_raw_parts(p, 0, cap));
}

unsafe fn last_error() -> c_uint {
    GetLastError()
}

/// v0.4.44 CI 诊断探针（V3 断言专用）：服务内部关键事件落盘取证。
/// 路径固定 C:\ProgramData\yuduan-svc-trace.log——服务以 LocalSystem 运行可写、
/// CI 断言步（admin）可读，失败时随 ci-logs-win 分支带回。best-effort，绝不 panic。
/// 定位 HandlerEx 不可达问题后可移除。
fn svc_trace(msg: &str) {
    use std::io::Write;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("C:\\ProgramData\\yuduan-svc-trace.log")
    {
        let _ = writeln!(f, "[{ts}] pid={pid} {msg}", pid = std::process::id());
    }
}

/// 向 SCM 报告状态。`state` 为 SERVICE_*；checkpoint/wait_hint 用于启动进度。
fn report(state: c_uint, checkpoint: c_uint, wait_hint: c_uint) {
    // v0.4.40：状态单调保护——控制处理器已立即上报 STOPPED 后，忽略 service_main
    // 尾部任何「倒退」到 STOP_PENDING / RUNNING 的重复上报。
    if STOPPED_REPORTED.load(Ordering::SeqCst) && state != SERVICE_STOPPED {
        return;
    }
    let h = match *SERVICE_HANDLE.lock().unwrap_or_else(|p| p.into_inner()) {
        Some(h) if h != 0 => h as *mut c_void,
        _ => return,
    };
    let st = ServiceStatus {
        dw_service_type: SERVICE_WIN32_OWN_PROCESS,
        dw_current_state: state,
        dw_controls_accepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: checkpoint,
        dw_wait_hint: wait_hint,
    };
    if state == SERVICE_STOPPED {
        STOPPED_REPORTED.store(true, Ordering::SeqCst);
    }
    let ok = unsafe { SetServiceStatus(h, &st) };
    svc_trace(&format!("report state={state} ok={ok}"));
}

/// 控制处理器：STOP/SHUTDOWN → 立即上报 STOPPED + 置停止标志 + 打断在线会话；
/// --set-hub 的自定义控制码 → 请求立即重载中枢端点（打断在线会话）。
///
/// v0.4.40 P2-5：旧实现只上报 STOP_PENDING，最终 STOPPED 要等 service_main 的
/// 主循环返回；而主循环可能阻塞在 session() 的 read_frame()（在线、无入站帧时
/// 永不返回），导致服务卡在 STOP_PENDING、后续 sc stop/sc delete 报 1052 / 1072、
/// PID 始终不变。现在在处理器里立即上报 STOPPED（不依赖主循环返回），并调用
/// crate::interrupt_active_session() 强制断开底层 socket / openssl 子进程，
/// 让主循环尽快返回、进程干净退出。SERVICE_ACCEPT_STOP 仍在 RUNNING 声明。
unsafe extern "system" fn handle_ex(control: c_uint, _event: c_uint, _data: *mut c_void, _ctx: *mut c_void) {
    svc_trace(&format!("handle_ex control={control} received"));
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            // v0.4.44 探针版：先置标志+打断会话、最后 report——即使 SetServiceStatus
            // 意外阻塞，工作线程也已见到 STOP 标志退出、进程退出时 SCM 自动标 STOPPED。
            svc_trace(&format!(
                "STOP branch enter ctrl={control} (stop={SERVICE_CONTROL_STOP} shutdown={SERVICE_CONTROL_SHUTDOWN})"
            ));
            STOP.store(true, Ordering::SeqCst);
            svc_trace("STOP: flag set");
            crate::interrupt_active_session();
            svc_trace("STOP: interrupt_active_session done");
            report(SERVICE_STOPPED, 0, 0);
            svc_trace("STOP: STOPPED reported");
        }
        YUDUAN_CTRL_RELOAD_HUB => {
            // --set-hub 已写好 agent-hub.json，通知服务立即重解析端点并打断在线会话。
            crate::request_hub_reload();
        }
        _ => {}
    }
}

/// 服务主函数（SCM 通过 SERVICE_TABLE_ENTRY 调用，不可闭包捕获，故全局取闭包）。
unsafe extern "system" fn service_main(_argc: c_uint, _argv: *mut *mut u16) -> c_uint {
    IN_SERVICE.store(true, Ordering::SeqCst);
    svc_trace(&format!(
        "service_main enter ctrl_stop={SERVICE_CONTROL_STOP} ctrl_shutdown={SERVICE_CONTROL_SHUTDOWN} accept_stop={SERVICE_ACCEPT_STOP}"
    ));

    let name = match *SVC_NAME.lock().unwrap_or_else(|p| p.into_inner()) {
        Some((p, _)) => p as *mut u16,
        None => ptr::null_mut(),
    };
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name, Some(handle_ex), ptr::null_mut()) };
    if handle.is_null() {
        svc_trace(&format!(
            "[agent] RegisterServiceCtrlHandlerExW 失败: win32 {}",
            unsafe { last_error() }
        ));
        eprintln!(
            "[agent] RegisterServiceCtrlHandlerExW 失败: win32 {}",
            unsafe { last_error() }
        );
        return 1;
    }
    svc_trace("handler registered");
    {
        let mut g = SERVICE_HANDLE.lock().unwrap_or_else(|p| p.into_inner());
        *g = Some(handle as usize);
    }

    report(SERVICE_START_PENDING, 1, 5_000);
    report(SERVICE_RUNNING, 0, 0);
    svc_trace("RUNNING reported, spawning worker");

    // v0.4.41（测试报告 N2 / P2-5 根因修复）：服务主逻辑 MUST 在独立线程运行，
    // service_main 立即返回，交还 StartServiceCtrlDispatcherW 的派发线程——否则该线程
    // 被 run_agent_loop 阻塞，HandlerEx（STOP/SHUTDOWN/--set-hub 重载控制码）永远等不到
    // 被 SCM 派发，sc stop 的 STOP 石沉大海，服务卡在 RUNNING、PID 不变（v0.4.40 实测
    // 10s 仍 Running）。STOP 时由 HandlerEx 立即 report(SERVICE_STOPPED) +
    // interrupt_active_session() 打断在线会话，工作线程退出后进程随之退出。
    let f = SERVICE_MAIN.lock().unwrap_or_else(|p| p.into_inner()).take();
    match f {
        Some(f) => {
            match std::thread::Builder::new()
                .name("agent-svc-main".into())
                .spawn(move || {
                    f();
                })
            {
                Ok(_) => svc_trace("worker spawned OK"),
                Err(e) => svc_trace(&format!("worker spawn FAILED: {e}")),
            }
        }
        None => eprintln!("[agent] 服务主函数缺失，无法运行副端逻辑"),
    }

    // service_main 返回即交还派发线程；控制码由 HandlerEx 在 dispatcher 线程处理，
    // 此处不再 report STOPPED（交由 HandlerEx 的 STOP 分支，避免重复/竞争上报）。
    svc_trace("service_main returning (dispatcher thread free)");
    0
}

/// 清理失败路径的全局态（成功路径由 service_main 自然完成，此处仅兜底）。
fn cleanup_statics() {
    if let Some(f) = SERVICE_MAIN.lock().unwrap_or_else(|p| p.into_inner()).take() {
        drop(f);
    }
    if let Some((p, c)) = SVC_NAME.lock().unwrap_or_else(|p| p.into_inner()).take() {
        unsafe { drop_wide(p as *mut u16, c) };
    }
    let mut g = SERVICE_HANDLE.lock().unwrap_or_else(|p| p.into_inner());
    *g = None;
    STOP.store(false, Ordering::SeqCst);
    STOPPED_REPORTED.store(false, Ordering::SeqCst);
    IN_SERVICE.store(false, Ordering::SeqCst);
}

/// 以服务进程身份运行 agent 主逻辑。
///
/// 返回 `true` = 本进程确由 SCM 拉起、已按服务模式完整跑到停止（调用方应直接退出）；
/// 返回 `false` = 不是服务进程（SCM 报 `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT=1063`），
/// 调用方按前台/开发态路径继续运行。
pub fn run_service(service_name: &str, f: Box<dyn FnOnce() + Send>) -> bool {
    let (name_ptr, name_cap) = wide_parts(service_name);
    {
        let mut g = SVC_NAME.lock().unwrap_or_else(|p| p.into_inner());
        *g = Some((name_ptr as usize, name_cap));
    }
    {
        let mut g = SERVICE_MAIN.lock().unwrap_or_else(|p| p.into_inner());
        *g = Some(f);
    }
    // 表项在栈上即可：StartServiceCtrlDispatcherW 阻塞至服务停止，栈帧始终有效。
    let table = [
        ServiceTableEntryW {
            lp_service_name: name_ptr,
            lp_service_proc: Some(service_main),
        },
        ServiceTableEntryW {
            lp_service_name: ptr::null_mut(),
            lp_service_proc: None,
        },
    ];

    let dispatched = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if dispatched != 0 {
        return true;
    }
    let err = unsafe { last_error() };
    if err != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
        eprintln!(
            "[agent] StartServiceCtrlDispatcherW 失败: win32 {}（非「未由服务管理器启动」类错误）",
            err
        );
    }
    cleanup_statics();
    false
}

/// SCM 是否已请求停止（SCM 停止服务 / 系统关机）。
pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// 本进程是否以 Windows 服务模式运行（区别于前台/开发态）。
pub fn is_service_mode() -> bool {
    IN_SERVICE.load(Ordering::SeqCst)
}

/// 可被停止信号 / 中枢重载信号打断的 sleep：最长 250ms 粒度轮询一次。
/// 避免「收到停止指令后仍睡满 9s」导致 SCM 等不到 STOPPED；也避免 --set-hub
/// 必须等满退避才用新端点重连。
pub fn sleep(d: Duration) {
    let end = Instant::now() + d;
    loop {
        if STOP.load(Ordering::SeqCst) || crate::RELOAD_HUB.load(Ordering::SeqCst) {
            return;
        }
        let now = Instant::now();
        if now >= end {
            return;
        }
        let remaining = (end - now).as_millis() as u64;
        thread::sleep(Duration::from_millis(remaining.min(250)));
    }
}

/// 安装服务：开机自启 + 失败自动重启（守卫）。
///
/// `bin_path` 建议带引号（路径含空格时必需），例：`"C:\Program Files\YuDuan\yuduan-agent.exe"`。
/// 失败恢复策略 = 首次/二次/三次失败均 5 秒后自动重启，`reset=86400`（对齐 sc.exe failure 语义），
/// 这就是「监测到副端断联后主动拉起」的 Windows 实现：进程崩溃/被杀/异常退出，SCM 都会拉起。
pub fn install(service_name: &str, display_name: &str, bin_path: &str) -> Result<(), String> {
    let (nm, nm_cap) = wide_parts(service_name);
    let (dn, dn_cap) = wide_parts(display_name);
    let (bp, bp_cap) = wide_parts(bin_path);

    let scm = unsafe { OpenSCManagerW(ptr::null_mut(), ptr::null_mut(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        let e = unsafe { last_error() };
        unsafe { drop_wide(nm, nm_cap); drop_wide(dn, dn_cap); drop_wide(bp, bp_cap) };
        return Err(format!("无法打开服务控制管理器: win32 {}（请以管理员身份运行）", e));
    }

    let mut svc = unsafe {
        CreateServiceW(
            scm,
            nm,
            dn,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            bp,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let mut svc_err = if svc.is_null() { unsafe { last_error() } } else { 0 };
    // v0.4.17（第九轮实测报告缺陷B）：升级流程「删旧服务→建同名服务」背靠背执行，
    // DeleteService 成功 ≠ 名字立即可用（SCM 句柄未全释放 → 标记删除 → 1072），
    // 此前一次失败即整装失败，升级实际变成卸载。现对 1072 轮询重试。
    // v0.4.19（第十轮实测报告问题1）：真实升级链实测 10s 重试窗口不足——
    // v0.4.16→v0.4.17 首次升级中「标记删除」窗口超过 10s，重试耗尽后仍失败（重跑才成功）。
    // 按报告建议把窗口提到 500ms × 60 = 30s；仅 1072 时才轮询，正常安装不受影响。
    // v0.4.20（第十一轮实测问题1）：30s 在真实就地升级中仍不足（首次仍 exit 1），
    // 提到 500ms × 120 = 60s；run_setup 另有失败自动整体重试兜底。
    if svc.is_null() && svc_err == ERROR_SERVICE_MARKED_DELETE {
        for i in 0..120u32 {
            if i % 4 == 3 {
                println!(
                    "[agent] 服务名处于「标记删除」待清理状态，等待 SCM 释放句柄…（{}s / 60s）",
                    (i + 1) / 2
                );
            }
            thread::sleep(Duration::from_millis(500));
            svc = unsafe {
                CreateServiceW(
                    scm,
                    nm,
                    dn,
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    bp,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if !svc.is_null() {
                svc_err = 0;
                println!("[agent] 服务名已释放，服务创建成功（此前为标记删除等待）");
                break;
            }
            svc_err = unsafe { last_error() };
            if svc_err != ERROR_SERVICE_MARKED_DELETE {
                break;
            }
        }
    }

    if svc.is_null() && svc_err == ERROR_SERVICE_EXISTS {
        // v0.4.45（N10，第二十五轮实测报告）：服务已存在 → **就地复用**而非报错——
        // OpenService + ChangeServiceConfig 更新 binPath/显示名/自启/错误控制，随后
        // 走统一的失败恢复策略配置。重装/异目录升级从此**零 DeleteService**：SCM
        // 「标记删除」释放窗口（实测 60s+，M1 卸载 77s / M3 重装 78s 的根因）整体绕开。
        svc = unsafe { OpenServiceW(scm, nm, SERVICE_ALL_ACCESS) };
        if svc.is_null() {
            svc_err = unsafe { last_error() };
        } else {
            let ok_cfg = unsafe {
                ChangeServiceConfigW(
                    svc,
                    SERVICE_WIN32_OWN_PROCESS, // 服务类型固定重设（OWN_PROCESS）
                    SERVICE_AUTO_START,        // 自启策略固定重设
                    SERVICE_ERROR_NORMAL,      // 错误控制固定重设
                    bp,                        // binPath 更新（异目录升级关键）
                    ptr::null_mut(),           // 加载顺序组不变
                    ptr::null_mut(),           // tag 不变
                    ptr::null_mut(),           // 依赖不变
                    ptr::null_mut(),           // 启动账户不变（LocalSystem）
                    ptr::null_mut(),           // 口令不变
                    dn,                        // 显示名更新
                )
            };
            if ok_cfg == 0 {
                let e = unsafe { last_error() };
                unsafe { CloseHandle(svc) };
                unsafe { CloseHandle(scm) };
                unsafe { drop_wide(nm, nm_cap); drop_wide(dn, dn_cap); drop_wide(bp, bp_cap) };
                return Err(format!("服务 {} 已存在，就地更新配置失败: win32 {}", service_name, e));
            }
            println!("[agent] 服务已存在：就地复用并更新配置（binPath/显示名/自启），未删除服务对象（零标记删除等待）");
        }
    }

    if svc.is_null() {
        let e = svc_err;
        let msg = if e == ERROR_SERVICE_EXISTS {
            format!(
                "服务 {} 已存在；如需重装请先执行 `yuduan-agent.exe --uninstall`",
                service_name
            )
        } else if e == ERROR_SERVICE_MARKED_DELETE {
            // v0.4.22（第十三轮实测报告建议③）：旧文案「重跑即可恢复」在残留进程
            // 拖住标记删除时并不成立（实测重跑仍 1072）。改为指明根因动作：
            // 先结束全部同映像进程（含用户会话远控助手）再重跑。
            let image = std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
                .unwrap_or_else(|| "yuduan-agent.exe".into());
            format!(
                "创建服务失败: win32 1072（服务 {} 处于「标记删除」待清理状态，仍有旧进程占用）。\
请先结束所有 {} 进程（任务管理器，或 taskkill /F /IM {}；注意排除本安装器窗口），\
再重跑安装器即可恢复",
                service_name, image, image
            )
        } else if e == ERROR_ACCESS_DENIED {
            format!("创建服务失败: win32 5（拒绝访问，请以管理员身份运行）")
        } else {
            format!("创建服务失败: win32 {}（请以管理员身份运行）", e)
        };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap); drop_wide(dn, dn_cap); drop_wide(bp, bp_cap) };
        return Err(msg);
    }

    // 守卫：失败恢复策略
    let actions = [
        ServiceFailureAction {
            action_type: SC_ACTION_RESTART,
            dw_delay: 5000,
        };
        3
    ];
    let fa = ServiceFailureActions {
        dw_reset_period: 86400,
        lp_reboot_msg: ptr::null_mut(),
        lp_command: ptr::null_mut(),
        c_actions: 3, // actions 数组长度（v0.4.11 补齐，此前缺失报 win32 1734）
        lpsa_actions: actions.as_ptr() as *mut ServiceFailureAction,
    };
    let ok = unsafe {
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa as *const ServiceFailureActions as *mut c_void)
    };
    if ok == 0 {
        println!(
            "[agent] 设置失败恢复策略失败: win32 {}（SCM 默认策略仍可能重启，但重启间隔不受控）",
            unsafe { last_error() }
        );
    } else {
        println!("[agent] 已设置失败恢复策略：失败后 5 秒自动重启（断联/崩溃守卫）");
    }

    unsafe { CloseHandle(svc) }; // 关闭句柄（服务已注册，勿调用 DeleteService 否则会立即卸载）
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap); drop_wide(dn, dn_cap); drop_wide(bp, bp_cap) };
    Ok(())
}

/// 卸载服务：尽力停止 → 超时按 PID 强杀兜底 → 删除。
///
/// v0.4.7（实测报告问题 6）：旧版副端服务可能 NOT_STOPPABLE（不响应 STOP 控制码），
/// 原实现等 15s 后不杀进程也不报错，继续装新服务会在复制文件时被旧进程锁定，
/// 实机表现为安装器长时间无输出「挂起」。现改为：等待期间输出进度、超时后
/// QueryServiceStatusEx 取服务进程 PID → taskkill /F 强杀 → 仍不停则显式报错退出。
pub fn uninstall(service_name: &str) -> Result<(), String> {
    let (nm, nm_cap) = wide_parts(service_name);
    let scm = unsafe { OpenSCManagerW(ptr::null_mut(), ptr::null_mut(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        let e = unsafe { last_error() };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务控制管理器: win32 {}", e));
    }
    let svc = unsafe { OpenServiceW(scm, nm, SERVICE_ALL_ACCESS) };
    if svc.is_null() {
        let e = unsafe { last_error() };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap) };
        if e == ERROR_SERVICE_DOES_NOT_EXIST {
            return Err(format!("服务 {} 不存在，无需卸载", service_name));
        }
        return Err(format!("无法打开服务 {}: win32 {}", service_name, e));
    }

    // 尽力停止（忽略失败：可能本就未运行；NOT_STOPPABLE 旧服务不响应 STOP）
    let mut st = ServiceStatus {
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
    };
    unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut st) };
    let mut stopped = false;
    for i in 0..30u32 {
        if unsafe { QueryServiceStatus(svc, &mut st) } != 0 && st.dw_current_state == SERVICE_STOPPED {
            stopped = true;
            break;
        }
        if i % 4 == 3 {
            println!("[agent] 等待旧服务停止…（{}s / 15s）", (i + 1) / 2);
        }
        thread::sleep(Duration::from_millis(500));
    }

    // 超时兜底：按服务进程 PID 强杀（不能按映像名杀——安装器自身也是 yuduan-agent.exe）
    if !stopped {
        let pid = query_service_pid(svc);
        if let Some(pid) = pid.filter(|p| *p as u32 != std::process::id()) {
            println!(
                "[agent] 旧服务 15s 未响应停止控制（可能为 NOT_STOPPABLE 旧版本），按 PID {} 强杀兜底",
                pid
            );
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .output();
            for _ in 0..20u32 {
                if unsafe { QueryServiceStatus(svc, &mut st) } != 0
                    && st.dw_current_state == SERVICE_STOPPED
                {
                    stopped = true;
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
    }

    if !stopped {
        unsafe { CloseHandle(svc) };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!(
            "旧服务 {} 进程 25s 内无法停止（可能被安全软件占用或为 NOT_STOPPABLE 旧版本）。\
请手动 `taskkill /F /IM yuduan-agent.exe`（注意区分安装器自身进程）或重启机器后重跑安装。",
            service_name
        ));
    }

    // v0.4.22（第十三轮实测）：服务已停 ≠ 进程全退。用户会话的 rc-helper 助手
    // （Session 2）由服务以 CreateProcessAsUserW 拉起、独立于 SCM 生命周期，
    // 残留时会拖住「标记删除」释放窗口（实测 60s 轮询不够，旧进程全退后才成功）。
    // 删除服务前强杀全部同映像残留（排除安装器自身）。
    kill_residual_processes();

    let ok = unsafe { DeleteService(svc) };
    unsafe { CloseHandle(svc) };
    // v0.4.17（第九轮实测报告缺陷B）：DeleteService 返回成功 ≠ 名字立即可用——
    // SCM 侧句柄未全部释放时服务名处于「标记删除」状态，紧随的同名 CreateService
    // 会报 1072（现场实测：升级变卸载）。此处轮询等待名字真正消失（OpenServiceW
    // 返回 1060）再返回。v0.4.20（第十一轮实测问题1）：10s 实测不足，提到 30s；
    // 自身句柄已审计无泄漏（svc/probe/scm 全路径关闭），慢在 SCM 侧释放。
    // v0.4.22（第十三轮实测）：残留同映像进程（rc-helper）会拖住释放窗口、60s 也不够；
    // 上一步已强杀全部残留（kill_residual_processes），此处窗口再提到 60s 兜底。
    if ok != 0 {
        // v0.4.34（测试报告 N7）：SCM「标记删除」释放窗口做成可调，超时时明确提示
        // 「重跑安装器即可恢复」——避免挂载满默认上限却无结论。
        // v0.4.45（N10，第二十五轮实测）：默认等待 60s→**8s**——DeleteService 成功
        // 即卸载语义达成（服务不再可启动/不再占用文件），名称释放只是 SCM 异步回收的
        // 可观测尾巴（实测该机释放恒 >60s）。重装/升级场景由 install() 的就地复用模式
        // 绕开（服务已存在时零删除，无需等待释放）——纯卸载 M1 从 77s 降到 ~10s 内。
        // 运维仍可用 YUDUAN_SVC_DEL_WAIT_SECS 调整（1-600s）。
        let wait_secs: u64 = std::env::var("YUDUAN_SVC_DEL_WAIT_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|v| *v >= 1 && *v <= 600)
            .unwrap_or(8);
        let max_iter = wait_secs * 2; // 每迭代 500ms
        let mut released = false;
        for i in 0..max_iter {
            let probe = unsafe { OpenServiceW(scm, nm, SERVICE_ALL_ACCESS) };
            if probe.is_null() {
                let pe = unsafe { last_error() };
                if pe == ERROR_SERVICE_DOES_NOT_EXIST {
                    released = true;
                    break;
                }
            } else {
                unsafe { CloseHandle(probe) };
            }
            if i % 4 == 3 {
                println!(
                    "[agent] 等待服务名从「标记删除」中释放…（{}s / {}s）",
                    (i + 1) / 2,
                    wait_secs
                );
            }
            thread::sleep(Duration::from_millis(500));
        }
        if !released {
            println!(
                "[agent] 服务已删除，但 SCM 仍未释放「标记删除」名称（超过 {}s）。\
这是 Windows 异步回收，不影响本次卸载结果；如需立即重装，重跑安装器即可（自动重试会处理）。",
                wait_secs
            );
        }
    }
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    if ok == 0 {
        Err(format!("删除服务失败: win32 {}", unsafe { last_error() }))
    } else {
        Ok(())
    }
}

/// 生成「强杀全部同映像残留副端进程（排除调用者自身 PID）」的 taskkill 参数。
///
/// v0.4.22（第十三轮实测）：旧服务停止后，用户会话的 rc-helper 助手（Session 2）
/// 与其他残留同映像进程仍可能存活——实测它们会拖住 SCM 的「标记删除」释放窗口，
/// 60s 轮询都不够（报告：待旧进程全部退出后重跑安装器才成功）。删除服务前先
/// taskkill 全部同映像残留（排除安装器自身），对齐报告建议①。
/// 用映像名+过滤器而不是逐 PID 枚举：std-only 下无需进程快照 API，
/// taskkill 原生 `PID ne <self>` 过滤即可精确排除自身。
pub(crate) fn residual_kill_args() -> (String, Vec<String>) {
    let self_pid = std::process::id();
    let image = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "yuduan-agent.exe".into());
    (
        image.clone(),
        vec![
            "/F".to_string(),
            "/IM".to_string(),
            image,
            "/FI".to_string(),
            format!("PID ne {}", self_pid),
        ],
    )
}

/// 执行残留进程清理（尽力而为：taskkill 失败不影响主流程，后续等待/文案兜底）。
/// v0.4.23 改 pub(crate)：就地升级（替换二进制）路径在停服务后也需清残留再覆盖 exe。
pub(crate) fn kill_residual_processes() {
    let (image, args) = residual_kill_args();
    match std::process::Command::new("taskkill").args(&args).output() {
        Ok(o) if o.status.success() => {
            println!("[agent] 已清理残留 {} 进程（含用户会话远控助手）", image);
        }
        _ => {
            // 无残留进程时 taskkill 返回非 0，属正常；不打扰输出
        }
    }
    // 给 SCM 感知进程退出、释放服务对象句柄的时间（实测数百毫秒级即可）
    thread::sleep(Duration::from_millis(800));
}

/// 查询服务宿主进程 PID（SC_STATUS_PROCESS_INFO；失败返回 None）。
fn query_service_pid(svc: *mut c_void) -> Option<u32> {
    const SC_STATUS_PROCESS_INFO: c_uint = 0;
    #[repr(C)]
    struct ServiceStatusProcess {
        dw_service_type: c_uint,
        dw_current_state: c_uint,
        dw_controls_accepted: c_uint,
        dw_win32_exit_code: c_uint,
        dw_service_specific_exit_code: c_uint,
        dw_check_point: c_uint,
        dw_wait_hint: c_uint,
        dw_process_id: c_uint,
        dw_service_flags: c_uint,
    }
    let mut ssp = ServiceStatusProcess {
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
        dw_process_id: 0,
        dw_service_flags: 0,
    };
    let mut needed: c_uint = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            &mut ssp as *mut ServiceStatusProcess as *mut c_void,
            std::mem::size_of::<ServiceStatusProcess>() as c_uint,
            &mut needed,
        )
    };
    if ok == 0 || ssp.dw_process_id == 0 {
        return None;
    }
    Some(ssp.dw_process_id)
}

/// 查询服务状态（人类可读）。v0.4.40 可观测性：
/// 先读状态文件（端点 / 来源 / 最近连接 / 最近错误 / 连接态 / uptime，普通用户
/// 无需管理员即可读），再叠加 SCM 状态与 PID。SCM 查询改用最小权限
/// （CONNECT+QUERY_STATUS），普通用户也能拿到状态；即便失败也把文件内容带回
/// Err 文本，由调用方（--status）降级展示，绝不整条命令空手而归。
pub fn status(service_name: &str) -> Result<String, String> {
    // 状态文件优先：--status 是独立短命进程、无 IPC，文件是唯一可观测通道。
    let file_info = crate::config::format_agent_status();

    const SC_MANAGER_CONNECT: c_uint = 0x0001;
    const SERVICE_QUERY_STATUS: c_uint = 0x0004;
    let (nm, nm_cap) = wide_parts(service_name);
    let scm = unsafe { OpenSCManagerW(ptr::null_mut(), ptr::null_mut(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        let e = unsafe { last_error() };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!(
            "{}\n[SCM] 无法打开服务控制管理器: win32 {}（请以管理员身份运行；以上端点/错误信息来自状态文件）",
            file_info, e
        ));
    }
    let svc = unsafe { OpenServiceW(scm, nm, SERVICE_QUERY_STATUS) };
    if svc.is_null() {
        let e = unsafe { last_error() };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!(
            "{}\n[SCM] 无法打开服务 {}: win32 {}（可能未安装；请以管理员身份核实）",
            file_info, service_name, e
        ));
    }
    let mut st = ServiceStatus {
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
    };
    let ok = unsafe { QueryServiceStatus(svc, &mut st) };
    // PID 需在关闭 svc 句柄前查询；失败错误码也要在关句柄前取（关句柄会覆盖 LastError）。
    let pid = if ok != 0 { query_service_pid(svc) } else { None };
    let query_err = if ok == 0 { unsafe { last_error() } } else { 0 };
    unsafe { CloseHandle(svc) };
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    if ok == 0 {
        return Err(format!(
            "{}\n[SCM] 查询服务状态失败: win32 {}（请以管理员身份运行）",
            file_info, query_err
        ));
    }
    let state = match st.dw_current_state {
        SERVICE_STOPPED => "已停止 (STOPPED)".to_string(),
        SERVICE_START_PENDING => "启动中 (START_PENDING)".to_string(),
        SERVICE_STOP_PENDING => "停止中 (STOP_PENDING)".to_string(),
        SERVICE_RUNNING => "运行中 (RUNNING)".to_string(),
        n => format!("未知状态 ({})", n),
    };
    let mut scm_line = format!("[SCM] 服务 {}：{}", service_name, state);
    if let Some(p) = pid {
        scm_line.push_str(&format!("，PID {}", p));
    }
    Ok(format!("{}\n{}", file_info, scm_line))
}

/// v0.4.40：--set-hub 写入 agent-hub.json 后调用，向运行中的服务发自定义控制码
/// （210，位于 128~255 用户自定义区间）。自定义控制码不受 dwControlsAccepted 的
/// SERVICE_ACCEPT_* 位约束，SCM 直接投递给 HandlerEx → 置 RELOAD_HUB + 强制断开
/// 当前在线 WS 会话，立即用新端点重连——无需重启服务进程，绕过 1052 停止失败。
///
/// 失败（服务未运行 / 权限不足 / 旧版服务不识别该控制码）返回 Err，但不影响已
/// 落盘的端点文件：主循环每轮重连都会重读文件，最迟下次自然重连生效（轮询兜底）。
pub fn notify_hub_changed(service_name: &str) -> Result<(), String> {
    let (nm, nm_cap) = wide_parts(service_name);
    let scm = unsafe { OpenSCManagerW(ptr::null_mut(), ptr::null_mut(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        let e = unsafe { last_error() };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务控制管理器: win32 {}（请以管理员身份运行）", e));
    }
    // 用户自定义控制码要求句柄具备 SERVICE_USER_DEFINED_CONTROL 访问权限。
    let svc = unsafe { OpenServiceW(scm, nm, SERVICE_USER_DEFINED_CONTROL) };
    if svc.is_null() {
        let e = unsafe { last_error() };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务 {}: win32 {}", service_name, e));
    }
    let mut st = ServiceStatus {
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
    };
    let ok = unsafe { ControlService(svc, YUDUAN_CTRL_RELOAD_HUB, &mut st) };
    let ctrl_err = if ok == 0 { unsafe { last_error() } } else { 0 };
    unsafe { CloseHandle(svc) };
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    if ok == 0 {
        return Err(format!(
            "通知服务重载中枢失败: win32 {}（服务可能未运行 / 需管理员 / 旧版服务不支持）",
            ctrl_err
        ));
    }
    Ok(())
}

/// 服务是否已安装（一键安装流程的幂等判断：未装 → 走安装，已装 → 查状态）。
/// 注意：必须用 CONNECT+QUERY_STATUS 最小权限——普通用户（双击场景，未提权）
/// 对 SC_MANAGER_ALL_ACCESS 直接拒绝，会误判「未安装」而反复触发重装（v0.2.5 实机踩坑）。
pub fn is_installed(service_name: &str) -> bool {
    const SC_MANAGER_CONNECT: c_uint = 0x0001;
    const SERVICE_QUERY_STATUS: c_uint = 0x0004;
    let (nm, nm_cap) = wide_parts(service_name);
    let scm = unsafe { OpenSCManagerW(ptr::null_mut(), ptr::null_mut(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return false;
    }
    let svc = unsafe { OpenServiceW(scm, nm, SERVICE_QUERY_STATUS) };
    let installed = !svc.is_null();
    if !svc.is_null() {
        unsafe { CloseHandle(svc) };
    }
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    installed
}

/// 启动服务（安装/重置完成后由一键流程调用）。
pub fn start(service_name: &str) -> Result<(), String> {
    let (nm, nm_cap) = wide_parts(service_name);
    let scm = unsafe { OpenSCManagerW(ptr::null_mut(), ptr::null_mut(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务控制管理器: win32 {}", unsafe { last_error() }));
    }
    let svc = unsafe { OpenServiceW(scm, nm, SERVICE_ALL_ACCESS) };
    if svc.is_null() {
        let e = unsafe { last_error() };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务 {}: win32 {}", service_name, e));
    }
    let ok = unsafe { StartServiceW(svc, 0, ptr::null()) };
    if ok == 0 {
        let e = unsafe { last_error() };
        unsafe { CloseHandle(svc) };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap) };
        // ERROR_SERVICE_ALREADY_RUNNING=1056 视为成功（幂等）
        if e == 1056 {
            return Ok(());
        }
        return Err(format!("启动服务失败: win32 {}", e));
    }
    // 轮询至 RUNNING（最多 15s）
    let mut st = ServiceStatus {
        dw_service_type: 0, dw_current_state: 0, dw_controls_accepted: 0,
        dw_win32_exit_code: 0, dw_service_specific_exit_code: 0, dw_check_point: 0, dw_wait_hint: 0,
    };
    let mut running = false;
    for _ in 0..30 {
        if unsafe { QueryServiceStatus(svc, &mut st) } != 0 {
            if st.dw_current_state == SERVICE_RUNNING {
                running = true;
                break;
            }
            if st.dw_current_state == SERVICE_STOPPED {
                break;
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    unsafe { CloseHandle(svc) };
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    if running {
        Ok(())
    } else {
        Err("服务已启动请求发出，但 15s 内未进入 RUNNING（查看 Windows 事件查看器定位原因）".into())
    }
}

/// 查询服务当前配置的二进制路径（QUERY_SERVICE_CONFIG.lpBinaryPathName，原样含引号/参数）。
///
/// v0.4.23（第十四轮实测报告问题2建议②）：就地升级判定用——服务已存在且指向同一
/// 安装目标时，升级走「停服务 → 替换二进制 → 启动」，**全程不删除服务对象**，
/// 彻底绕开 SCM「标记删除」1072 窗口（实测该窗口在残留进程拖住时 60s 都不够）。
pub fn query_bin_path(service_name: &str) -> Result<String, String> {
    let (nm, nm_cap) = wide_parts(service_name);
    let scm = unsafe { OpenSCManagerW(ptr::null_mut(), ptr::null_mut(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务控制管理器: win32 {}", unsafe { last_error() }));
    }
    let svc = unsafe { OpenServiceW(scm, nm, SERVICE_QUERY_CONFIG) };
    if svc.is_null() {
        let e = unsafe { last_error() };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务 {}: win32 {}", service_name, e));
    }
    let result = unsafe {
        let mut needed: u32 = 0;
        if QueryServiceConfigW(svc, ptr::null_mut(), 0, &mut needed) == 0
            && last_error() != ERROR_INSUFFICIENT_BUFFER
        {
            Err(format!("QueryServiceConfigW(探测大小) 失败: win32 {}", last_error()))
        } else {
            // needed 字节；按 u16 对齐再留 1 个 NUL 余量
            let units = (needed as usize / 2).max(1) + 1;
            let mut buf: Vec<u16> = vec![0; units];
            if QueryServiceConfigW(svc, buf.as_mut_ptr() as *mut QueryServiceConfigW, needed, &mut needed) == 0
            {
                Err(format!("QueryServiceConfigW 失败: win32 {}", last_error()))
            } else {
                let cfg = &*(buf.as_ptr() as *const QueryServiceConfigW);
                let mut len = 0usize;
                while *cfg.lp_binary_path_name.add(len) != 0 {
                    len += 1;
                }
                Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
                    cfg.lp_binary_path_name,
                    len,
                )))
            }
        }
    };
    unsafe { CloseHandle(svc) };
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    result
}

/// 停止服务并等待 STOPPED（15s 超时 → 按服务进程 PID 强杀兜底 10s）。
///
/// v0.4.23：「替换二进制」升级路径专用——只停**不删**（`uninstall` 会 DeleteService
/// 并引入 1072 标记删除窗口）。停止语义与 uninstall 内部一致，此处独立成函数避免
/// 两条路径行为漂移。
pub fn stop(service_name: &str) -> Result<(), String> {
    let (nm, nm_cap) = wide_parts(service_name);
    let scm = unsafe { OpenSCManagerW(ptr::null_mut(), ptr::null_mut(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务控制管理器: win32 {}", unsafe { last_error() }));
    }
    let svc = unsafe { OpenServiceW(scm, nm, SERVICE_ALL_ACCESS) };
    if svc.is_null() {
        let e = unsafe { last_error() };
        unsafe { CloseHandle(scm) };
        unsafe { drop_wide(nm, nm_cap) };
        return Err(format!("无法打开服务 {}: win32 {}", service_name, e));
    }
    let mut st = ServiceStatus {
        dw_service_type: 0, dw_current_state: 0, dw_controls_accepted: 0,
        dw_win32_exit_code: 0, dw_service_specific_exit_code: 0, dw_check_point: 0, dw_wait_hint: 0,
    };
    unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut st) };
    let mut stopped = false;
    for i in 0..30u32 {
        if unsafe { QueryServiceStatus(svc, &mut st) } != 0 && st.dw_current_state == SERVICE_STOPPED {
            stopped = true;
            break;
        }
        if i % 4 == 3 {
            println!("[agent] 等待服务停止…（{}s / 15s）", (i + 1) / 2);
        }
        thread::sleep(Duration::from_millis(500));
    }
    if !stopped {
        let pid = query_service_pid(svc);
        if let Some(pid) = pid.filter(|p| *p as u32 != std::process::id()) {
            println!("[agent] 服务 15s 未响应停止控制，按 PID {} 强杀兜底", pid);
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .output();
            for _ in 0..20u32 {
                if unsafe { QueryServiceStatus(svc, &mut st) } != 0
                    && st.dw_current_state == SERVICE_STOPPED
                {
                    stopped = true;
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
    unsafe { CloseHandle(svc) };
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    if stopped {
        Ok(())
    } else {
        Err(format!(
            "服务 {} 25s 内无法停止（可能被安全软件占用）。请手工 `taskkill /F /IM yuduan-agent.exe`\
（注意区分安装器自身进程）或重启机器后重跑安装。",
            service_name
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // v0.4.44（V3 回归根因防再犯）：SCM accept 位是魔数，必须与 winsvc.h 一致。
    // 此前 STOP 误写 0x2（实为 PAUSE_CONTINUE）、SHUTDOWN 误写 0x80（实为
    // SESSIONCHANGE），导致 sc stop 被拒 1052 两轮未愈。锁死官方值防回归。
    #[test]
    fn service_accept_bits_match_winsvc_h() {
        assert_eq!(SERVICE_ACCEPT_STOP, 0x0000_0001, "SERVICE_ACCEPT_STOP 必须为 0x1");
        assert_eq!(SERVICE_ACCEPT_SHUTDOWN, 0x0000_0004, "SERVICE_ACCEPT_SHUTDOWN 必须为 0x4");
        // RUNNING 时上报的 accept 掩码 = STOP | SHUTDOWN = 0x5（report() 的取值来源）
        assert_eq!(
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            0x0000_0005,
            "RUNNING 上报掩码必须含 STOP(0x1)+SHUTDOWN(0x4)"
        );
        // v0.4.44 V3 第三层：控制码常量必须与 MSDN HandlerEx 一致（CI 探针实证
        // SCM 投递 STOP=1，match 按 0 匹配导致永不停止）
        assert_eq!(SERVICE_CONTROL_STOP, 0x0000_0001, "SERVICE_CONTROL_STOP 必须为 0x1");
        assert_eq!(
            SERVICE_CONTROL_SHUTDOWN, 0x0000_0005,
            "SERVICE_CONTROL_SHUTDOWN 必须为 0x5"
        );
    }

    #[test]
    fn residual_kill_args_excludes_self_pid() {
        // v0.4.22 回归：过滤器必须排除调用者自身 PID——否则升级前清理会把安装器自己杀掉
        let (image, args) = residual_kill_args();
        assert_eq!(args[0], "/F");
        assert_eq!(args[1], "/IM");
        assert_eq!(args[2], image, "/IM 的映像名应与返回的 image 一致");
        assert!(!image.is_empty());
        assert_eq!(args[3], "/FI");
        assert_eq!(
            args[4],
            format!("PID ne {}", std::process::id()),
            "必须用 PID ne 过滤器排除安装器自身"
        );
    }
}
