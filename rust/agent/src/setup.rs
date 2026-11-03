// 御端（YuDuan）副端 —— 一键自安装（Windows，std-only + Win32 FFI）
//
// 产品要求（2026-10-29 用户拍板）：小白双击 exe 即完成一切——不需要任何脚本。
//
// 流程（run_setup）：
//   1. 停止并删除旧服务（幂等，无旧服务则跳过）
//   2. 清理 User+Machine 两级作用域的 YUDUAN_* 历史残留（含占位域名等脏配置）
//      并广播 WM_SETTINGCHANGE（对齐 setx 行为，让 services.exe 感知变化）
//   3. 删除落盘引导配置 agent-config.json（重装后自动重新 claim 最新密钥）
//   4. 复制自身到稳定安装目录 %ProgramFiles%\YuDuan\（服务指向它，不怕用户挪动下载目录）
//   5. 注册系统服务（开机自启 + 失败 5s 自动重启守卫）
//   6. 启动服务并确认 RUNNING
//
// 提权：双击 exe 默认无管理员权限，ensure_installed 检测后用 ShellExecuteExW
// verb="runas" 重新拉起自身 --setup（UAC 弹窗），父进程随即退出。

use std::os::raw::c_void;

/// 部署托管的 YUDUAN_* 环境变量：一键安装时在 User+Machine 两级作用域全部清除。
/// 只清部署链路写入的项；YUDUAN_DB_DSN/TLS_* 等服务器高级项不在副端范围。
pub const DEPLOY_ENV_NAMES: &[&str] = &[
    "YUDUAN_HUB",
    "YUDUAN_HMAC_SECRET",
    "YUDUAN_OPENSSL",
    "YUDUAN_ENCODER_LIB",
];

// —— Win32 常量 ——
const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
const SW_SHOWNORMAL: i32 = 1;
const WM_SETTINGCHANGE: u32 = 0x001A;
const HWND_BROADCAST: usize = 0xFFFF;
const SMTO_ABORTIFHUNG: u32 = 0x0002;

#[repr(C)]
struct ShellExecuteInfoW {
    cb_size: u32,
    f_mask: u32,
    hwnd: *mut c_void,
    lp_verb: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    lp_directory: *const u16,
    n_show: i32,
    h_inst_app: *mut c_void,
    lp_id_list: *mut c_void,
    lp_class: *const u16,
    hkey_class: *mut c_void,
    dw_hot_key: u32,
    h_icon: *mut c_void, // union { hIcon; hMonitor; }
    h_process: *mut c_void,
}

#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteExW(info: *mut ShellExecuteInfoW) -> i32;
    fn IsUserAnAdmin() -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn SendMessageTimeoutW(
        hwnd: usize,
        msg: u32,
        wparam: usize,
        lparam: *const u16,
        flags: u32,
        timeout: u32,
        result: *mut usize,
    ) -> usize;
}

fn wide_c(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// 当前进程是否持有管理员令牌。
pub fn is_user_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

/// 以管理员身份重新拉起自身（UAC 弹窗）。成功返回后父进程应尽快退出。
pub fn relaunch_elevated(args: &str) -> Result<(), String> {
    let self_path = std::env::current_exe()
        .map_err(|e| format!("无法定位自身路径: {}", e))?
        .to_string_lossy()
        .to_string();
    let verb = wide_c("runas");
    let file = wide_c(&self_path);
    let params = wide_c(args);
    let mut info = ShellExecuteInfoW {
        cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
        f_mask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: std::ptr::null_mut(),
        lp_verb: verb.as_ptr(),
        lp_file: file.as_ptr(),
        lp_parameters: params.as_ptr(),
        lp_directory: std::ptr::null(),
        n_show: SW_SHOWNORMAL,
        h_inst_app: std::ptr::null_mut(),
        lp_id_list: std::ptr::null_mut(),
        lp_class: std::ptr::null(),
        hkey_class: std::ptr::null_mut(),
        dw_hot_key: 0,
        h_icon: std::ptr::null_mut(),
        h_process: std::ptr::null_mut(),
    };
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        return Err(format!(
            "UAC 提权被取消或失败（错误码 {}）。请右键 exe 选择「以管理员身份运行」重试。",
            info.h_inst_app as usize
        ));
    }
    Ok(())
}

/// 一键安装入口：未提权 → 自动 UAC 重拉自身 --setup；已提权 → 直接执行。
/// 返回 `Ok(true)` = 本进程已完成安装；`Ok(false)` = 已转交提权子进程（父进程应退出）。
pub fn ensure_installed(service_name: &str, display_name: &str) -> Result<bool, String> {
    if !is_user_admin() {
        relaunch_elevated("--setup")?;
        return Ok(false);
    }
    run_setup(service_name, display_name)?;
    Ok(true)
}

/// 完整安装流程（调用方必须已是管理员）。
pub fn run_setup(service_name: &str, display_name: &str) -> Result<(), String> {
    println!("==========================================");
    println!("  御端副端 · 一键安装（清旧配置 → 装服务 → 启动）");
    println!("==========================================");

    // 1. 停止并删除旧服务（幂等）
    match crate::win_service::uninstall(service_name) {
        Ok(()) => println!("[1/6] 已移除旧服务 {}", service_name),
        Err(e) if e.contains("不存在") => println!("[1/6] 无旧服务，跳过"),
        Err(e) => return Err(format!("移除旧服务失败: {}", e)),
    }

    // 2. 清理两级作用域 YUDUAN_* 历史残留
    let cleaned = clean_deployment_env();
    println!(
        "[2/6] 已清理历史环境变量残留（User+Machine 两级，命中 {} 项）",
        cleaned
    );

    // 3. 删除落盘引导配置（重装后自动重新领取最新密钥）
    if let Some(f) = crate::config::config_file() {
        match std::fs::remove_file(&f) {
            Ok(()) => println!("[3/6] 已清除落盘配置 {:?}，启动后自动重新领取密钥", f),
            Err(_) => println!("[3/6] 落盘配置不存在或不可删除，跳过"),
        }
    } else {
        println!("[3/6] 无落盘配置，跳过");
    }

    // 4. 复制自身到稳定安装目录（服务固定指向它，不受下载目录挪动/清理影响）
    let dst = install_to_program_files()?;
    println!("[4/6] 安装文件 -> {}", dst.display());

    // 5. 注册服务：开机自启 + 失败 5s 自动重启（守卫）
    crate::win_service::install(
        service_name,
        display_name,
        &format!("\"{}\"", dst.display()),
    )?;
    println!("[5/6] 服务注册成功（开机自启 + 崩溃/被杀 5s 自动重启）");

    // 6. 启动并确认
    crate::win_service::start(service_name)?;
    println!("[6/6] 服务已启动");
    if let Ok(s) = crate::win_service::status(service_name) {
        println!("  状态: {}", s);
    }

    println!("------------------------------------------");
    println!("安装完成。副端将广播自动发现中枢并领取密钥。");
    println!("管理命令：--status 查状态 / --uninstall 卸载 / --setup 重装 / --quiet 免交互");
    println!("本窗口可以直接关闭。");
    println!("------------------------------------------");
    wait_enter();
    Ok(())
}

/// 清理两级作用域的部署环境变量，返回实际删除的条目数。
fn clean_deployment_env() -> usize {
    let mut n = 0;
    for name in DEPLOY_ENV_NAMES {
        for key in ["HKCU\\Environment", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"] {
            let out = std::process::Command::new("reg")
                .args(["delete", key, "/v", name, "/f"])
                .output();
            if let Ok(o) = out {
                // reg delete 对不存在的值返回非 0；只有明确成功才计数
                if o.status.success() {
                    n += 1;
                }
            }
        }
    }
    broadcast_env_change();
    n
}

/// 广播 WM_SETTINGCHANGE（对齐 setx.exe 行为），让正在运行的 services.exe/
/// explorer.exe 立即感知环境变量变化，服务重启后读到干净值。
fn broadcast_env_change() {
    let param = wide_c("Environment");
    let mut result: usize = 0;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            param.as_ptr(),
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        );
    }
}

/// 安装目标：%ProgramFiles%\YuDuan\yuduan-agent.exe。
/// 若当前 exe 已在该目录（用户双击的是已装副本）直接返回其路径，跳过复制。
///
/// v0.4.11（实测报告问题 2）：旧版安装器曾把二进制设为只读属性（自我保护），
/// 升级时 `std::fs::copy` 报 os error 5「拒绝访问」，旧文案误导为「进程占用」，
/// 现场被带偏去查进程锁定（实机 T6 首装失败即此因，attrib -r 后才装上）。
/// 复制前：目标存在且只读 → 自动清除只读属性再复制；失败文案按根因三分：
/// 只读未清干净 / 权限不足 / 进程占用，便于现场一眼定位。
fn install_to_program_files() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("无法定位自身路径: {}", e))?;
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let dir = std::path::Path::new(&pf).join("YuDuan");
    let dst = dir.join("yuduan-agent.exe");
    if exe == dst {
        return Ok(dst);
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建安装目录 {:?} 失败: {}", dir, e))?;
    // 旧版残留只读属性：先清除（升级路径自愈，现场无需再手工 attrib -r）
    if let Ok(md) = std::fs::metadata(&dst) {
        if md.permissions().readonly() {
            let mut perm = md.permissions();
            perm.set_readonly(false);
            match std::fs::set_permissions(&dst, perm) {
                Ok(()) => println!("[setup] 已清除旧版二进制只读属性（升级自愈，无需手工 attrib -r）"),
                Err(e) => {
                    return Err(format!(
                        "目标 {:?} 为只读且自动清除失败: {}（请以管理员身份运行，或手工执行 attrib -r \"{}\"）",
                        dst, e, dst.display()
                    ))
                }
            }
        }
    }
    std::fs::copy(&exe, &dst).map_err(|e| {
        let hint = match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                // Windows 上 os error 5 可能是只读残留/权限不足/进程占用，逐项提示
                let ro = std::fs::metadata(&dst).map(|m| m.permissions().readonly()).unwrap_or(false);
                if ro {
                    "目标仍为只读属性（清除断言失败，请手工 attrib -r 后重试）"
                } else {
                    "权限不足（请以管理员身份运行）或文件被占用（先执行 --uninstall 或重启后重试）"
                }
            }
            _ => "检查磁盘空间与路径后重试",
        };
        format!("复制 {} -> {:?} 失败: {}（{}）", exe.display(), dst, e, hint)
    })?;
    Ok(dst)
}

/// 交互窗口收尾：等待回车，防止双击打开的控制台窗口闪退（用户看不到结果）。
/// v0.4.8（实测报告问题 3）：自动化/脚本链执行 --setup 时 stdin 是打开但无数据的
/// 管道/重定向，`read_line` 永远等不到回车 → 进程在服务装好、注册成功后仍挂起
/// >6 分钟，阻塞部署链（v0.4.7 实测复现）。两条免等出口：
///   1) 显式 --quiet / -q（批量部署推荐）；
///   2) stdin 非控制台（GetConsoleMode 失败 = 管道/重定向/服务上下文）自动跳过。
/// v0.4.10（实测报告问题 3 连续两轮复现）：提权 PowerShell 脚本链执行时 stdin 是
/// **真控制台**，GetConsoleMode 成功 → v0.4.8 的非交互探测放行不了，仍会挂起。
/// 追加第三条出口：**15s 倒计时超时**——控制台交互但无人敲回车（脚本驱动）时自动放行，
/// 双击场景用户仍可在倒计时内看到完整输出。
fn wait_enter() {
    if std::env::args().any(|a| a == "--quiet" || a == "-q") {
        return;
    }
    if !stdin_is_interactive() {
        return;
    }
    print!("按回车键关闭窗口（15 秒后自动退出）...");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    if !wait_enter_or_timeout(15) {
        // 超时放行前补一个换行，避免下一行输出贴在倒计时行尾
        println!();
    }
}

/// 等待回车或超时。返回 true = 用户按了回车，false = 超时。
fn wait_enter_or_timeout(secs: u64) -> bool {
    use std::io::Write as _;
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        let _ = tx.send(());
    });
    for left in (1..=secs).rev() {
        print!("\r{} 秒后自动退出...  ", left);
        let _ = std::io::stdout().flush();
        match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(_) => return true,
            Err(_) => {}
        }
    }
    false
}

/// stdin 是否连接到交互式控制台。
/// Windows：GetStdHandle(STD_INPUT_HANDLE) 后 GetConsoleMode 成功 = 控制台；
/// 失败（管道/重定向/已关闭）或句柄无效 = 非交互。
#[cfg(windows)]
pub fn stdin_is_interactive() -> bool {
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // (DWORD)-10
    const INVALID_HANDLE_VALUE: usize = usize::MAX;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn GetConsoleMode(hconsole: *mut c_void, mode: *mut u32) -> i32;
    }
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        if h.is_null() || h as usize == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut mode: u32 = 0;
        GetConsoleMode(h, &mut mode) != 0
    }
}

#[cfg(not(windows))]
pub fn stdin_is_interactive() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_env_names_cover_all_deployment_write_points() {
        // install-agent.ps1 setx 写入的项必须全部在清理清单内（防新增漏登记）
        for expected in ["YUDUAN_HUB", "YUDUAN_HMAC_SECRET", "YUDUAN_OPENSSL", "YUDUAN_ENCODER_LIB"] {
            assert!(DEPLOY_ENV_NAMES.contains(&expected), "缺 {}", expected);
        }
    }

    #[test]
    fn wide_c_is_nul_terminated() {
        let v = wide_c("ab");
        assert_eq!(&v[..2], &[b'a' as u16, b'b' as u16]);
        assert_eq!(v.last(), Some(&0u16));
    }
}
