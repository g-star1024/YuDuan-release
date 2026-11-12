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
///
/// F-07：`YUDUAN_DISCOVERY_PORT` 刻意**不**纳入本清单。它是副端服务进程启动期读取的
/// 机器级（setx /M）带外端口约定，由部署侧按实例注入、需跨重装保留；本清单在
/// clean_deployment_env() 里被 reg delete 且**不回写**，若纳入则双击/--setup 重装后
/// 服务读不到自定义端口、回落默认 18242，F-07 自定义端口在一条主路径上即失效。
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
///
/// v0.4.23（第十四轮实测报告问题2建议②）：升级优先走**就地替换**路径——
/// 服务已存在且指向同一安装目标时：「停服务 → 杀残留 → 覆盖 exe → 启动」，
/// 全程不 DeleteService/CreateService，彻底绕开 SCM「标记删除」1072 窗口
/// （实测残留进程拖住时 60s 重试都不够）。仅首装 / 安装目录变更 / 服务缺失
/// 才走原有「删旧建新」全量路径（保留 1072 自动重试兜底）。
pub fn run_setup(service_name: &str, display_name: &str) -> Result<(), String> {
    // v0.4.20（第十一轮实测报告问题2）：非管理员运行必须显式报错退出，不进入
    // 「删了旧服务却建不上新服务」的半装状态（升级变卸载的次生风险）。
    if !is_user_admin() {
        return Err(
            "一键安装需要管理员权限（当前进程未提权）。请右键「以管理员身份运行」，或在 UAC 弹窗中点「是」。"
                .into(),
        );
    }
    println!("==========================================");
    println!("  御端副端 · 一键安装（清旧配置 → 装服务 → 启动）");
    println!("==========================================");

    // —— v0.4.23 就地升级判定 ——
    let target = target_exe_path();
    let inplace = crate::win_service::is_installed(service_name)
        && crate::win_service::query_bin_path(service_name)
            .map(|bp| same_bin_target(&bp, &target))
            .unwrap_or(false);
    if inplace {
        println!("[1/6] 检出既有服务且指向同一安装目录：就地升级（替换二进制 + 重启，不删服务、无 1072 风险）");
        crate::win_service::stop(service_name)?;
        println!("[2/6] 旧服务已停止");
        crate::win_service::kill_residual_processes();
        let cleaned = clean_deployment_env();
        println!("[3/6] 已清理残留副端进程（含远控助手）与历史环境变量（{} 项）", cleaned);
        let dst = install_to_program_files()?;
        println!("[4/6] 安装文件已替换 -> {}", dst.display());
        // --setup 语义保持：清落盘引导配置（agent-config.json = HMAC 密钥）→
        // 启动后自动重新 claim 最新密钥。
        // v0.4.31 §9.2：**保留设备身份**——这里只删 config::config_file()，
        // 绝不删独立的 agent-devicekey.json（devicekey::devicekey_file()）。
        // 取舍：HMAC 引导密钥随中枢轮换需重新 claim，生命周期短；设备 Ed25519
        // 身份是长期凭证，若重装/升级连带删除，中枢台账里同一台机器会冒出新
        // 公钥、旧记录成孤儿。故设备密钥刻意不随 --setup / 密钥轮换自愈清除。
        // v0.4.40：**同样保留 agent-hub.json**（--set-hub 写入的运维中枢端点）。
        // 这里删的仅是 agent-config.json（DPAPI 加密的 HMAC 密钥）；中枢端点在
        // 独立文件里，绝不能被 --setup / 就地升级清掉——否则每次重装都会把远端
        // / 隧道中枢配置抹掉、退回 UDP 发现，正是本次要根治的缺陷。
        if let Some(f) = crate::config::config_file() {
            match std::fs::remove_file(&f) {
                Ok(()) => println!("[5/6] 已清除落盘配置，启动后自动重新领取密钥"),
                Err(_) => println!("[5/6] 落盘配置不存在或不可删除，跳过"),
            }
        } else {
            println!("[5/6] 无落盘配置，跳过");
        }
        crate::win_service::start(service_name)?;
        println!("[6/6] 服务已启动（新版本生效；服务对象未删除，升级零 1072 风险）");
        if let Ok(s) = crate::win_service::status(service_name) {
            println!("  状态: {}", s);
        }
        println!("------------------------------------------");
        println!("升级完成。副端将重新广播发现中枢并领取密钥。");
        println!("管理命令：--status 查状态 / --uninstall 卸载 / --setup 重装 / --quiet 免交互");
        println!("（窗口 15 秒后自动关闭，也可按回车键立即关闭）");
        println!("------------------------------------------");
        wait_enter();
        return Ok(());
    }

    // —— 全量路径（首装 / 服务缺失 / 安装目录变更）——
    // v0.4.45（N10，第二十五轮实测报告）：不再「删旧建新」。服务存在时（含异目录
    // 升级）仅停服务，由 install() 的就地复用模式（OpenService + ChangeServiceConfig
    // 更新 binPath/显示名）接管——全程零 DeleteService，SCM「标记删除」释放窗口
    // （实测 60s+，M1 卸载 77s / M3 重装 78s 的根因）整体消失。仅服务不存在时跳过停止。
    // 1. 停止旧服务（幂等；已停止时瞬时返回）
    if crate::win_service::is_installed(service_name) {
        crate::win_service::stop(service_name)?;
        crate::win_service::kill_residual_processes();
        println!(
            "[1/6] 已停止旧服务 {}（就地复用模式：不删除服务对象，零标记删除等待）",
            service_name
        );
    } else {
        println!("[1/6] 无旧服务，跳过停止");
    }

    // 2. 清理两级作用域 YUDUAN_* 历史残留
    let cleaned = clean_deployment_env();
    println!(
        "[2/6] 已清理历史环境变量残留（User+Machine 两级，命中 {} 项）",
        cleaned
    );

    // 3. 删除落盘引导配置（agent-config.json = HMAC 密钥；重装后重新 claim）。
    //    v0.4.31 §9.2：同就地升级路径，**保留设备身份**——只删引导配置，
    //    绝不删独立的 agent-devicekey.json（取舍理由见上方就地升级路径注释）。
    //    v0.4.40：**同样保留 agent-hub.json**——只删 agent-config.json 这一个
    //    文件，运维用 --set-hub 设置的远端中枢端点完整保留，重装不丢配置。
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
    // v0.4.20（第十一轮实测报告问题1）：真实就地升级中「标记删除」窗口可能超过
    // 安装器内部 60s 轮询（SCM 侧句柄释放慢，实测两轮超过 30s），首次 CreateService
    // 仍会撞 1072。失败不再只提示——按报告建议自动做一轮「清残留 → 重建」整体重试。
    let bin_arg = format!("\"{}\"", dst.display());
    if let Err(e) = crate::win_service::install(service_name, display_name, &bin_arg) {
        if e.contains("1072") || e.contains("标记删除") {
            println!("[5/6] 首次创建服务撞上「标记删除」窗口，自动重试（清残留 → 重建）…");
            // 幂等：服务已不存在时 uninstall 返回「不存在」，忽略即可
            let _ = crate::win_service::uninstall(service_name);
            crate::win_service::install(service_name, display_name, &bin_arg)?;
        } else {
            return Err(e);
        }
    }
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
    println!("（窗口 15 秒后自动关闭，也可按回车键立即关闭）");
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

/// 升级目标 exe 路径（不执行复制）：%ProgramFiles%\YuDuan\yuduan-agent.exe。
/// v0.4.23：就地升级判定（query_bin_path 比对）与实际复制共用同一目标定义。
fn target_exe_path() -> std::path::PathBuf {
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    std::path::Path::new(&pf).join("YuDuan").join("yuduan-agent.exe")
}

/// 判断服务当前 binpath 是否指向本次安装目标 exe（同一文件才算就地升级）。
/// 大小写不敏感（Windows 路径）；容忍 `\\?\` 前缀、引号包裹与尾部附加启动参数。
/// 返回 false = 走全量「删旧建新」路径（保守正确：宁多重建也不误判就地覆盖）。
fn same_bin_target(binpath: &str, target_exe: &std::path::Path) -> bool {
    let t = target_exe.to_string_lossy().to_lowercase();
    let s = binpath.trim();
    // 引号语义：ImagePath 常为 `"C:\...\exe" args`——有配对闭引号时取引号内纯路径
    let core = if let Some(rest) = s.strip_prefix('"') {
        match rest.find('"') {
            Some(i) => &rest[..i],
            None => rest,
        }
    } else {
        s
    };
    let b = core.to_lowercase();
    let b = b.trim_start_matches(r"\\?\").trim_end();
    b == t || b.starts_with(&(t.clone() + " "))
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
    let dst = target_exe_path();
    if exe == dst {
        return Ok(dst);
    }
    let dir = dst.parent().expect("目标 exe 必有父目录").to_path_buf();
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
        // v0.4.34（测试报告 N6）：超时放行。wait_enter_or_timeout 内部 spawn 的
        // stdin 读取线程仍阻塞在 read_line，会拖住整个进程/窗口导致「承诺自动退出却不退出」。
        // 必须显式退出整个进程（含该阻塞线程），否则无人值守/远程部署时窗口常驻会挂住会话。
        // 安装/升级工作已全部完成，exit(0) 安全。
        println!();
        std::process::exit(0);
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
    fn discovery_port_env_is_not_cleared_on_reinstall() {
        // F-07：YUDUAN_DISCOVERY_PORT 是服务启动期读取的机器级带外配置，需跨重装保留；
        // 若被误加入清理白名单，双击/--setup 重装会抹掉它、回落默认 18242，F-07 失效。
        assert!(
            !DEPLOY_ENV_NAMES.contains(&"YUDUAN_DISCOVERY_PORT"),
            "YUDUAN_DISCOVERY_PORT 不得加入 DEPLOY_ENV_NAMES（重装清理会抹掉自定义端口）"
        );
    }

    #[test]
    fn wide_c_is_nul_terminated() {
        let v = wide_c("ab");
        assert_eq!(&v[..2], &[b'a' as u16, b'b' as u16]);
        assert_eq!(v.last(), Some(&0u16));
    }

    #[test]
    fn same_bin_target_matches_inplace_variants_only() {
        // v0.4.23 回归：就地升级判定——同目标（含引号/参数/\\?\ 前缀/大小写）命中，
        // 异目录/异文件名一律走全量路径（保守正确）
        let t = std::path::Path::new(r"C:\Program Files\YuDuan\yuduan-agent.exe");
        assert!(same_bin_target(r#""C:\Program Files\YuDuan\yuduan-agent.exe""#, t), "带引号原样");
        assert!(same_bin_target(r"C:\Program Files\YuDuan\yuduan-agent.exe", t), "无引号");
        assert!(same_bin_target(r"c:\program files\yuduan\YUDUAN-AGENT.EXE", t), "大小写不敏感");
        assert!(same_bin_target(
            r#""C:\Program Files\YuDuan\yuduan-agent.exe" --service"#,
            t
        ), "尾部启动参数");
        assert!(same_bin_target(r"\\?\C:\Program Files\YuDuan\yuduan-agent.exe", t), r"\\?\ 前缀");
        assert!(!same_bin_target(r#""D:\yuduan\yuduan-agent.exe""#, t), "异盘目录→全量路径");
        assert!(!same_bin_target(r#""C:\Program Files\YuDuan\old-agent.exe""#, t), "同目录异名→全量路径");
        assert!(!same_bin_target("", t), "空串→全量路径");
    }
}
