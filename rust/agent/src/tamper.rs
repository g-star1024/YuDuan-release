// 御端 Rust 副端 —— 防篡改（生产化加固，std-only）。
//
// 三项检查：
//  1) 自校验（self-integrity）：计算自身可执行文件 SHA-256，与可信期望值
//     （YUDUAN_AGENT_EXPECTED_SHA256，生产由 KMS/配置下发）比对；不符即判定被篡改。
//  2) 反调试（anti-debug）：Linux 读 /proc/self/status TracerPid；macOS/Windows 走平台 API。
//     默认关闭，YUDUAN_AGENT_ANTI_DEBUG=1 启用（避免开发态误伤）。
//  3) 代码签名（codesign）：macOS 走系统 codesign -v（最佳努力，仅告警）。
//
// 行为：仅当 YUDUAN_AGENT_ENFORCE_TAMPER=1 时，关键失败项才阻断启动（exit 2）；
// 否则仅收集报告并日志输出，保证开发态不误伤。

use std::io::Read;

/// 单次检查结论。
pub struct TamperReport {
    pub check: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// 返回当前可执行文件的路径（std 跨平台）。
pub fn executable_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// 计算自身可执行文件 SHA-256（hex）。读取失败返回 None。
pub fn self_sha256() -> Option<String> {
    let path = executable_path()?;
    let mut f = std::fs::File::open(&path).ok()?;
    let mut hasher = crate::sha256::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(crate::sha256::hex_encode(&hasher.finalize()))
}

/// 读取可信期望值（环境）。未设置返回 None（开发态不强制）。
pub fn expected_sha256() -> Option<String> {
    let v = std::env::var("YUDUAN_AGENT_EXPECTED_SHA256").ok()?;
    let v = v.trim().to_ascii_lowercase();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// 是否强制阻断：YUDUAN_AGENT_ENFORCE_TAMPER=1。
pub fn enforce() -> bool {
    std::env::var("YUDUAN_AGENT_ENFORCE_TAMPER").map(|v| v == "1").unwrap_or(false)
}

/// 是否启用反调试：YUDUAN_AGENT_ANTI_DEBUG=1。
pub fn anti_debug_enabled() -> bool {
    std::env::var("YUDUAN_AGENT_ANTI_DEBUG").map(|v| v == "1").unwrap_or(false)
}

/// 自校验：比对自身哈希与期望值。
fn check_self_integrity() -> TamperReport {
    match (self_sha256(), expected_sha256()) {
        (None, _) => TamperReport {
            check: "self_integrity",
            ok: false,
            detail: "无法读取可执行文件计算哈希".into(),
        },
        (Some(actual), None) => TamperReport {
            check: "self_integrity",
            ok: true,
            detail: format!("未配置期望值（开发态）；actual={}", actual),
        },
        (Some(actual), Some(exp)) => {
            let ok = actual == exp;
            TamperReport {
                check: "self_integrity",
                ok,
                detail: if ok {
                    "哈希匹配期望值".into()
                } else {
                    format!("哈希不符！actual={} expected={}", actual, exp)
                },
            }
        }
    }
}

/// 反调试检查（仅 anti_debug_enabled 时执行；否则标记 skipped）。
fn check_debugger() -> TamperReport {
    if !anti_debug_enabled() {
        return TamperReport {
            check: "anti_debug",
            ok: true,
            detail: "未启用（YUDUAN_AGENT_ANTI_DEBUG=1 启用）".into(),
        };
    }
    let attached = debugger_attached();
    TamperReport {
        check: "anti_debug",
        ok: !attached,
        detail: if attached {
            "检测到调试器附加！".into()
        } else {
            "未检测到调试器".into()
        },
    }
}

/// 代码签名检查（仅 macOS；其它平台 skipped）。最佳努力：codesign 缺失 = 未知。
fn check_codesign() -> TamperReport {
    if !cfg!(target_os = "macos") {
        return TamperReport {
            check: "codesign",
            ok: true,
            detail: "仅 macOS 适用".into(),
        };
    }
    let path = match executable_path() {
        Some(p) => p,
        None => {
            return TamperReport {
                check: "codesign",
                ok: false,
                detail: "无法确定可执行路径".into(),
            }
        }
    };
    // 探测 codesign 是否可用
    let probe = std::process::Command::new("codesign")
        .arg("-v")
        .arg("--verbose=4")
        .arg(&path)
        .output();
    match probe {
        Ok(o) => {
            let ok = o.status.success();
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            TamperReport {
                check: "codesign",
                ok,
                detail: if ok {
                    "codesign 校验通过".into()
                } else {
                    format!("codesign 校验失败: {}", err)
                },
            }
        }
        Err(_) => TamperReport {
            check: "codesign",
            ok: true, // 工具缺失视为未知，不阻断（与 openssl 同策略）
            detail: "codesign 不可用（跳过，不阻断）".into(),
        },
    }
}

/// 运行全部防篡改检查，返回报告列表。
pub fn self_check() -> Vec<TamperReport> {
    vec![
        check_self_integrity(),
        check_debugger(),
        check_codesign(),
    ]
}

/// 汇总：返回 (是否有阻断项, 报告文本)。
pub fn summarize(reports: &[TamperReport]) -> (bool, String) {
    let mut blocked = false;
    let mut lines = Vec::new();
    for r in reports {
        if !r.ok && r.check != "codesign" {
            blocked = true; // codesign 失败不阻断（最佳努力）
        }
        lines.push(format!(
            "  [{}] {}: {}",
            if r.ok { "OK" } else { "FAIL" },
            r.check,
            r.detail
        ));
    }
    (blocked, lines.join("\n"))
}

// ===================== 平台特定：调试器检测 =====================

#[cfg(target_os = "linux")]
fn debugger_attached() -> bool {
    // 读取 /proc/self/status 的 TracerPid 行；非 0 = 被调试。无副作用。
    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("TracerPid:") {
                if let Some(v) = line.split_whitespace().nth(1) {
                    if let Ok(pid) = v.parse::<i32>() {
                        return pid != 0;
                    }
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn debugger_attached() -> bool {
    use std::os::raw::{c_int, c_void};
    extern "C" {
        // int ptrace(int request, pid_t pid, caddr_t addr, int data);
        fn ptrace(request: c_int, pid: c_int, addr: *mut c_void, data: c_int) -> c_int;
    }
    const PT_TRACE_ME: c_int = 0; // macOS / Linux 均为 0
    // 若已被调试，PT_TRACE_ME 失败（返回 -1）；无调试器时成功（返回 0）。
    // 注意：成功后本进程会被其父进程标记为 traced，对常驻守护进程无害。
    unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) < 0 }
}

#[cfg(target_os = "windows")]
fn debugger_attached() -> bool {
    use std::os::raw::c_int;
    extern "C" {
        fn IsDebuggerPresent() -> c_int;
    }
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn debugger_attached() -> bool {
    false // 其它平台暂不支持运行时调试器检测
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_path_resolvable() {
        assert!(executable_path().is_some());
    }

    #[test]
    fn self_sha256_stable_and_valid() {
        let a = self_sha256().expect("应能计算自身哈希");
        let b = self_sha256().expect("应能计算自身哈希");
        assert_eq!(a, b, "两次哈希应一致");
        assert_eq!(a.len(), 64, "SHA-256 hex 长度应为 64");
        // 校验是合法 hex
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn self_integrity_report_formatted() {
        let r = check_self_integrity();
        assert_eq!(r.check, "self_integrity");
        // 未设置期望值时应 ok=true（开发态）
        if expected_sha256().is_none() {
            assert!(r.ok);
        }
    }

    #[test]
    fn debugger_check_runs_without_panic() {
        let r = check_debugger();
        // 未启用反调试时必定 ok=true（不 panic 即可）
        if !anti_debug_enabled() {
            assert!(r.ok);
        }
    }

    #[test]
    fn codesign_check_runs_without_panic() {
        let r = check_codesign();
        // 非 macOS 或工具缺失时不会 panic；返回 ok 不阻塞
        let _ = r;
    }

    #[test]
    fn self_check_collects_three_reports() {
        let reports = self_check();
        assert_eq!(reports.len(), 3);
    }

    #[test]
    fn summarize_no_false_block_when_all_ok() {
        let reports = vec![
            TamperReport { check: "self_integrity", ok: true, detail: "ok".into() },
            TamperReport { check: "anti_debug", ok: true, detail: "ok".into() },
            TamperReport { check: "codesign", ok: true, detail: "ok".into() },
        ];
        let (blocked, text) = summarize(&reports);
        assert!(!blocked);
        assert!(text.contains("self_integrity"));
    }

    #[test]
    fn summarize_blocks_on_self_integrity_fail() {
        let reports = vec![
            TamperReport { check: "self_integrity", ok: false, detail: "tampered".into() },
            TamperReport { check: "anti_debug", ok: true, detail: "ok".into() },
            TamperReport { check: "codesign", ok: true, detail: "ok".into() },
        ];
        let (blocked, _) = summarize(&reports);
        assert!(blocked);
    }

    #[test]
    fn summarize_codesign_fail_does_not_block() {
        let reports = vec![
            TamperReport { check: "self_integrity", ok: true, detail: "ok".into() },
            TamperReport { check: "anti_debug", ok: true, detail: "ok".into() },
            TamperReport { check: "codesign", ok: false, detail: "unsigned".into() },
        ];
        let (blocked, _) = summarize(&reports);
        assert!(!blocked, "codesign 失败不应阻断启动");
    }
}
