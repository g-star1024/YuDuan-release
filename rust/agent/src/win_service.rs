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
const SERVICE_ERROR_NORMAL: c_uint = 1;
const SERVICE_STOPPED: c_uint = 1;
const SERVICE_START_PENDING: c_uint = 2;
const SERVICE_STOP_PENDING: c_uint = 3;
const SERVICE_RUNNING: c_uint = 4;
const SERVICE_ACCEPT_STOP: c_uint = 0x00000002;
const SERVICE_ACCEPT_SHUTDOWN: c_uint = 0x00000080;
const SERVICE_CONTROL_STOP: c_uint = 0;
const SERVICE_CONTROL_SHUTDOWN: c_uint = 8;
const SERVICE_CONFIG_FAILURE_ACTIONS: c_uint = 2;
const SC_ACTION_RESTART: c_uint = 1; // SERVICE_FAILURE_ACTION.type：重启服务（sc.exe failure ... restart）
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: c_uint = 1063;
const ERROR_SERVICE_EXISTS: c_uint = 1073;
const ERROR_SERVICE_DOES_NOT_EXIST: c_uint = 1060;

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
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> c_uint;
    fn CloseHandle(handle: *mut c_void) -> c_int;
}

// —— 跨线程全局态 ——
/// SCM 停止/关机信号。service 控制处理器写，agent 主循环读。
static STOP: AtomicBool = AtomicBool::new(false);
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

/// 向 SCM 报告状态。`state` 为 SERVICE_*；checkpoint/wait_hint 用于启动进度。
fn report(state: c_uint, checkpoint: c_uint, wait_hint: c_uint) {
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
    unsafe { SetServiceStatus(h, &st) };
}

/// 控制处理器：收到 STOP/SHUTDOWN → 上报 STOP_PENDING 并置停止标志，agent 主循环据此干净退出。
unsafe extern "system" fn handle_ex(control: c_uint, _event: c_uint, _data: *mut c_void, _ctx: *mut c_void) {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 1, 10_000);
            STOP.store(true, Ordering::SeqCst);
        }
        _ => {}
    }
}

/// 服务主函数（SCM 通过 SERVICE_TABLE_ENTRY 调用，不可闭包捕获，故全局取闭包）。
unsafe extern "system" fn service_main(_argc: c_uint, _argv: *mut *mut u16) -> c_uint {
    IN_SERVICE.store(true, Ordering::SeqCst);

    let name = match *SVC_NAME.lock().unwrap_or_else(|p| p.into_inner()) {
        Some((p, _)) => p as *mut u16,
        None => ptr::null_mut(),
    };
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name, Some(handle_ex), ptr::null_mut()) };
    if handle.is_null() {
        eprintln!(
            "[agent] RegisterServiceCtrlHandlerExW 失败: win32 {}",
            unsafe { last_error() }
        );
        return 1;
    }
    {
        let mut g = SERVICE_HANDLE.lock().unwrap_or_else(|p| p.into_inner());
        *g = Some(handle as usize);
    }

    report(SERVICE_START_PENDING, 1, 5_000);
    report(SERVICE_RUNNING, 0, 0);

    // 执行 agent 主循环（内部轮询 stop_requested()）
    let f = SERVICE_MAIN.lock().unwrap_or_else(|p| p.into_inner()).take();
    match f {
        Some(f) => f(),
        None => eprintln!("[agent] 服务主函数缺失，无法运行副端逻辑"),
    }

    report(SERVICE_STOP_PENDING, 2, 5_000);
    report(SERVICE_STOPPED, 0, 0);
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

/// 可被停止信号打断的 sleep：最长 250ms 粒度轮询一次。
/// 避免「收到停止指令后仍睡满 9s」导致 SCM 等不到 STOPPED。
pub fn sleep(d: Duration) {
    let end = Instant::now() + d;
    loop {
        if STOP.load(Ordering::SeqCst) {
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

    let svc = unsafe {
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

    if svc.is_null() {
        let e = unsafe { last_error() };
        let msg = if e == ERROR_SERVICE_EXISTS {
            format!(
                "服务 {} 已存在；如需重装请先执行 `yuduan-agent.exe --uninstall`",
                service_name
            )
        } else {
            format!("创建服务失败: win32 {}（可能需要管理员权限）", e)
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
        eprintln!(
            "[agent] 设置失败恢复策略失败: win32 {}（SCM 默认策略仍可能重启，但重启间隔不受控）",
            unsafe { last_error() }
        );
    } else {
        eprintln!("[agent] 已设置失败恢复策略：失败后 5 秒自动重启（断联/崩溃守卫）");
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
            eprintln!("[agent] 等待旧服务停止…（{}s / 15s）", (i + 1) / 2);
        }
        thread::sleep(Duration::from_millis(500));
    }

    // 超时兜底：按服务进程 PID 强杀（不能按映像名杀——安装器自身也是 yuduan-agent.exe）
    if !stopped {
        let pid = query_service_pid(svc);
        if let Some(pid) = pid.filter(|p| *p as u32 != std::process::id()) {
            eprintln!(
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

    let ok = unsafe { DeleteService(svc) };
    unsafe { CloseHandle(svc) };
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    if ok == 0 {
        Err(format!("删除服务失败: win32 {}", unsafe { last_error() }))
    } else {
        Ok(())
    }
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

/// 查询服务状态（人类可读）。
pub fn status(service_name: &str) -> Result<String, String> {
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
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
    };
    let ok = unsafe { QueryServiceStatus(svc, &mut st) };
    unsafe { CloseHandle(svc) };
    unsafe { CloseHandle(scm) };
    unsafe { drop_wide(nm, nm_cap) };
    if ok == 0 {
        return Err(format!("查询服务状态失败: win32 {}", unsafe { last_error() }));
    }
    let state = match st.dw_current_state {
        SERVICE_STOPPED => "已停止 (STOPPED)",
        SERVICE_START_PENDING => "启动中 (START_PENDING)",
        SERVICE_STOP_PENDING => "停止中 (STOP_PENDING)",
        SERVICE_RUNNING => "运行中 (RUNNING)",
        n => &format!("未知状态 ({})", n),
    };
    Ok(format!("服务 {}：{}", service_name, state))
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
