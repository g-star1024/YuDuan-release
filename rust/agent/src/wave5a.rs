// wave5a.rs —— 波次 5a（W5-1 合规基线采集 / W5-2 违规软件卸载 / W5-5 补丁修复）
// Rust 生产副端实现。
//
// 与 Go 参考副端 `dev/cmd/agent/wave5a.go` + `internal/collect/compliance*.go` 同构
// （铁律 2/9）：同一套 action、同一套合规项 Key（中枢基线按 Key 比对）、同一套
// 诚实回告（unknown 就是 unknown，绝不伪造 pass）。
//
// 采集项 Key：patch.automatic_check / patch.auto_download / patch.pending_updates /
// antivirus.installed / antivirus.running / firewall.enabled / screensaver.enabled /
// screensaver.timeout_sec / screensaver.lock / disk_encrypt.enabled。
// 三平台实现：macOS（defaults/fdesetup/pmset）、Linux（systemctl/ufw/gsettings/apt）、
// Windows（reg/sc/netsh/manage-bde/tasklist）。

use crate::{json_string, Json};
use std::process::Command;

// ===================== 采集小工具 =====================

fn c_run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    if !o.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn c_run_shell(sh: &str) -> Option<String> {
    let (shell, flag) = if cfg!(windows) { ("cmd", "/c") } else { ("sh", "-c") };
    c_run(shell, &[flag, sh])
}

fn c_run_any(cmds: &[(&str, Vec<&str>)]) -> Option<String> {
    for (c, a) in cmds {
        if let Some(s) = c_run(c, a) {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// 解析系统命令输出的开关值：1/true/yes/on/enabled/active → true。
fn c_truthy(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "enabled" | "active" | "enabled." | "running" => Some(true),
        "0" | "false" | "no" | "off" | "disabled" | "inactive" | "stopped" | "unknown" => Some(false),
        _ => None,
    }
}

fn c_int(s: &str) -> Option<i64> {
    s.trim().parse::<i64>().ok()
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

// ===================== 合规项模型 =====================

const CAT_PATCH: &str = "patch";
const CAT_AV: &str = "antivirus";
const CAT_FW: &str = "firewall";
const CAT_SCR: &str = "screensaver";
const CAT_ENC: &str = "disk_encrypt";

struct CItem {
    key: String,
    name: String,
    category: String,
    state: String,
    actual: String,
    expected: String,
    detail: String,
}

impl CItem {
    fn pass_fail(key: &str, name: &str, cat: &str, ok: bool, actual: &str, expected: &str, detail: &str) -> CItem {
        CItem {
            key: key.to_string(),
            name: name.to_string(),
            category: cat.to_string(),
            state: if ok { "pass".to_string() } else { "fail".to_string() },
            actual: actual.to_string(),
            expected: expected.to_string(),
            detail: detail.to_string(),
        }
    }
    fn unknown(key: &str, name: &str, cat: &str, expected: &str, detail: &str) -> CItem {
        CItem {
            key: key.to_string(),
            name: name.to_string(),
            category: cat.to_string(),
            state: "unknown".to_string(),
            actual: String::new(),
            expected: expected.to_string(),
            detail: detail.to_string(),
        }
    }
    fn to_json(&self) -> String {
        format!(
            "{{\"key\":{},\"name\":{},\"category\":{},\"state\":{},\"actual\":{},\"expected\":{},\"detail\":{}}}",
            json_string(&self.key),
            json_string(&self.name),
            json_string(&self.category),
            json_string(&self.state),
            json_string(&self.actual),
            json_string(&self.expected),
            json_string(&self.detail)
        )
    }
}

// ---- 杀毒 / EDR 厂商关键字 ----

const AV_VENDORS: &[&str] = &[
    "symantec", "norton", "mcafee", "crowdstrike", "falcon", "sentinelone", "sentinel",
    "kaspersky", "bitdefender", "eset", "nod32", "trend micro", "trendmicro", "sophos",
    "avast", "avg ", "carbon black", "cylance", "malwarebytes", "clamav", "clam",
    "microsoft defender", "windows defender", "defender", "xprotect", "jamf protect",
    "360", "qihoo", "huorong", "火绒", "江民", "瑞星", "金山毒霸", "深信服", "edr",
];

fn match_vendor(names: &[String]) -> String {
    for n in names {
        let low = n.to_ascii_lowercase();
        for v in AV_VENDORS {
            if low.contains(v) {
                return n.clone();
            }
        }
    }
    String::new()
}

fn running_procs() -> Vec<String> {
    let mut names = Vec::new();
    if let Some(out) = c_run_any(&[("ps", vec!["-ax", "-o", "comm="]), ("ps", vec!["-e", "-o", "comm="])]) {
        for line in out.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let base = line.rsplit('/').next().unwrap_or(line).to_ascii_lowercase();
            names.push(base);
        }
    }
    names
}

fn av_items(installed: &[String], running: &[String], detail: &str) -> Vec<CItem> {
    let mut hit = match_vendor(installed);
    if hit.is_empty() {
        hit = match_vendor(running);
    }
    let inst_ok = !hit.is_empty();
    let inst_actual = if inst_ok { hit } else { "none".to_string() };
    let run_hit = match_vendor(running);
    let run_ok = !run_hit.is_empty();
    let run_actual = if run_ok { run_hit } else { "none".to_string() };
    vec![
        CItem::pass_fail(
            "antivirus.installed",
            "杀毒/EDR 已安装",
            CAT_AV,
            inst_ok,
            &inst_actual,
            "installed",
            detail,
        ),
        CItem::pass_fail(
            "antivirus.running",
            "杀毒/EDR 运行中",
            CAT_AV,
            run_ok,
            &run_actual,
            "running",
            detail,
        ),
    ]
}

// ===================== 平台采集 =====================

pub fn collect_compliance() -> Vec<CItem> {
    if cfg!(target_os = "macos") {
        darwin_compliance()
    } else if cfg!(target_os = "windows") {
        windows_compliance()
    } else {
        linux_compliance()
    }
}

const SU_DOMAIN: &str = "/Library/Preferences/com.apple.SoftwareUpdate";

fn darwin_compliance() -> Vec<CItem> {
    let mut out = Vec::new();
    // ---- 补丁 ----
    match c_run("defaults", &["read", SU_DOMAIN, "AutomaticCheckEnabled"]) {
        Some(s) => match c_truthy(&s) {
            Some(on) => out.push(CItem::pass_fail(
                "patch.automatic_check",
                "系统更新自动检查",
                CAT_PATCH,
                on,
                on_off(on),
                "on",
                &format!("defaults read {} AutomaticCheckEnabled={}", SU_DOMAIN, s),
            )),
            None => out.push(CItem::unknown(
                "patch.automatic_check",
                "系统更新自动检查",
                CAT_PATCH,
                "on",
                "defaults 输出无法解析",
            )),
        },
        None => out.push(CItem::unknown(
            "patch.automatic_check",
            "系统更新自动检查",
            CAT_PATCH,
            "on",
            "defaults 读取失败（无偏好项或权限不足）",
        )),
    }
    match c_run_any(&[
        ("defaults", vec!["read", SU_DOMAIN, "AutomaticDownload"]),
        ("defaults", vec!["read", SU_DOMAIN, "AutomaticDownloadEnabled"]),
    ]) {
        Some(s) => {
            if let Some(on) = c_truthy(&s) {
                out.push(CItem::pass_fail(
                    "patch.auto_download",
                    "补丁自动下载",
                    CAT_PATCH,
                    on,
                    on_off(on),
                    "on",
                    &format!("AutomaticDownload={}", s),
                ))
            }
        }
        None => out.push(CItem::unknown(
            "patch.auto_download",
            "补丁自动下载",
            CAT_PATCH,
            "on",
            "无 AutomaticDownload 偏好项",
        )),
    }
    match c_run("defaults", &["read", SU_DOMAIN, "LastUpdatesAvailable"]) {
        Some(s) => {
            if let Some(n) = c_int(&s) {
                out.push(CItem::pass_fail(
                    "patch.pending_updates",
                    "待安装补丁数",
                    CAT_PATCH,
                    n == 0,
                    &n.to_string(),
                    "0",
                    &format!("LastUpdatesAvailable={}", s),
                ))
            }
        }
        None => out.push(CItem::unknown(
            "patch.pending_updates",
            "待安装补丁数",
            CAT_PATCH,
            "0",
            "无 LastUpdatesAvailable 偏好项（未执行过更新检查）",
        )),
    }
    // ---- 杀毒 / EDR ----
    let mut installed: Vec<String> = Vec::new();
    let mut dirs = vec![
        "/Applications".to_string(),
        "/System/Applications".to_string(),
        "/Library/Application Support".to_string(),
    ];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(format!("{}/Applications", home));
    }
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                installed.push(n.trim_end_matches(".app").to_string());
            }
        }
    }
    out.extend(av_items(
        &installed,
        &running_procs(),
        "扫描 /Applications + /Library/Application Support + 进程表",
    ));
    // ---- 防火墙 ----
    out.push(darwin_firewall());
    // ---- 屏保 / 锁屏 ----
    out.extend(darwin_screen_items());
    // ---- 磁盘加密 ----
    out.push(darwin_encrypt());
    out
}

fn darwin_firewall() -> CItem {
    let detail = "defaults read /Library/Preferences/com.apple.alf globalstate";
    if let Some(s) = c_run("defaults", &["read", "/Library/Preferences/com.apple.alf", "globalstate"]) {
        if let Some(n) = c_int(&s) {
            return CItem::pass_fail(
                "firewall.enabled",
                "防火墙已开启",
                CAT_FW,
                n >= 1,
                on_off(n >= 1),
                "on",
                &format!("{}={}", detail, s),
            );
        }
    }
    if let Some(s) = c_run(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    ) {
        let low = s.to_ascii_lowercase();
        if low.contains("state = 0") || low.contains("disabled") {
            return CItem::pass_fail("firewall.enabled", "防火墙已开启", CAT_FW, false, "off", "on", &format!("socketfilterfw: {}", s));
        }
        if low.contains("state = 1") || low.contains("state = 2") || low.contains("enabled") {
            return CItem::pass_fail("firewall.enabled", "防火墙已开启", CAT_FW, true, "on", "on", &format!("socketfilterfw: {}", s));
        }
    }
    CItem::unknown("firewall.enabled", "防火墙已开启", CAT_FW, "on", "alf/socketfilterfw 均不可用")
}

fn darwin_screen_items() -> Vec<CItem> {
    let mut out = Vec::new();
    let idle = match c_run_any(&[
        ("defaults", vec!["-currentHost", "read", "com.apple.screensaver", "idleTime"]),
        ("defaults", vec!["read", "com.apple.screensaver", "idleTime"]),
    ]) {
        Some(s) => c_int(&s).unwrap_or(-1),
        None => -1,
    };
    if idle >= 0 {
        out.push(CItem::pass_fail(
            "screensaver.enabled",
            "屏保已启用",
            CAT_SCR,
            idle > 0,
            on_off(idle > 0),
            "on",
            &format!("idleTime={}s", idle),
        ));
        if idle > 0 {
            out.push(CItem::pass_fail(
                "screensaver.timeout_sec",
                "屏保超时(秒)",
                CAT_SCR,
                true,
                &idle.to_string(),
                "",
                &format!("idleTime={}s（阈值由中枢基线判定）", idle),
            ));
        } else {
            out.push(CItem::unknown(
                "screensaver.timeout_sec",
                "屏保超时(秒)",
                CAT_SCR,
                "",
                "屏保未启用（idleTime=0）",
            ));
        }
    } else {
        out.push(CItem::unknown(
            "screensaver.enabled",
            "屏保已启用",
            CAT_SCR,
            "on",
            "无 idleTime 偏好项",
        ));
        out.push(CItem::unknown(
            "screensaver.timeout_sec",
            "屏保超时(秒)",
            CAT_SCR,
            "",
            "无 idleTime 偏好项",
        ));
    }
    match c_run_any(&[
        ("defaults", vec!["read", "com.apple.screensaver", "askForPassword"]),
        ("defaults", vec!["-currentHost", "read", "com.apple.screensaver", "askForPassword"]),
    ]) {
        Some(s) => {
            if let Some(on) = c_truthy(&s) {
                out.push(CItem::pass_fail(
                    "screensaver.lock",
                    "屏保恢复需口令",
                    CAT_SCR,
                    on,
                    on_off(on),
                    "on",
                    &format!("askForPassword={}", s),
                ))
            }
        }
        None => out.push(CItem::unknown(
            "screensaver.lock",
            "屏保恢复需口令",
            CAT_SCR,
            "on",
            "无 askForPassword 偏好项",
        )),
    }
    out
}

fn darwin_encrypt() -> CItem {
    match c_run("fdesetup", &["status"]) {
        Some(s) => {
            let low = s.to_ascii_lowercase();
            if low.contains("filevault is on") {
                CItem::pass_fail("disk_encrypt.enabled", "磁盘加密已开启", CAT_ENC, true, "on", "on", &s)
            } else if low.contains("filevault is off") {
                CItem::pass_fail("disk_encrypt.enabled", "磁盘加密已开启", CAT_ENC, false, "off", "on", &s)
            } else {
                CItem::unknown(
                    "disk_encrypt.enabled",
                    "磁盘加密已开启",
                    CAT_ENC,
                    "on",
                    &format!("fdesetup 输出无法解析: {}", s),
                )
            }
        }
        None => CItem::unknown("disk_encrypt.enabled", "磁盘加密已开启", CAT_ENC, "on", "fdesetup 不可用"),
    }
}

fn linux_compliance() -> Vec<CItem> {
    let mut out = Vec::new();
    match c_run_shell("apt list --upgradable 2>/dev/null | tail -n +2 | grep -c upgradable") {
        Some(s) => {
            if let Some(n) = c_int(&s) {
                out.push(CItem::pass_fail(
                    "patch.pending_updates",
                    "待安装补丁数",
                    CAT_PATCH,
                    n == 0,
                    &n.to_string(),
                    "0",
                    "apt list --upgradable",
                ))
            }
        }
        None => out.push(CItem::unknown(
            "patch.pending_updates",
            "待安装补丁数",
            CAT_PATCH,
            "0",
            "apt 不可用（仅支持 Debian 系；RPM 系待扩展）",
        )),
    }
    match c_run_any(&[
        ("systemctl", vec!["is-enabled", "unattended-upgrades"]),
        ("systemctl", vec!["is-enabled", "dnf-automatic"]),
    ]) {
        Some(s) => {
            let on = s.trim() == "enabled";
            out.push(CItem::pass_fail(
                "patch.automatic_check",
                "系统更新自动检查",
                CAT_PATCH,
                on,
                on_off(on),
                "on",
                &format!("systemctl is-enabled={}", s),
            ))
        }
        None => out.push(CItem::unknown(
            "patch.automatic_check",
            "系统更新自动检查",
            CAT_PATCH,
            "on",
            "未检测到 unattended-upgrades/dnf-automatic",
        )),
    }
    out.push(CItem::unknown(
        "patch.auto_download",
        "补丁自动下载",
        CAT_PATCH,
        "on",
        "Linux 未实现该采集项（诚实回告，不伪造）",
    ));
    let mut installed: Vec<String> = Vec::new();
    if let Some(s) = c_run_shell("systemctl list-units --all --no-legend 2>/dev/null | cut -d' ' -f1") {
        for line in s.lines() {
            let line = line.trim();
            if !line.is_empty() {
                installed.push(line.to_string());
            }
        }
    }
    out.extend(av_items(&installed, &running_procs(), "扫描 systemd 单元 + 进程表"));
    out.push(linux_firewall());
    out.extend(linux_screen_items());
    out.push(linux_encrypt());
    out
}

fn linux_firewall() -> CItem {
    if let Some(s) = c_run("ufw", &["status"]) {
        let low = s.to_ascii_lowercase();
        if low.contains("status: active") {
            return CItem::pass_fail("firewall.enabled", "防火墙已开启", CAT_FW, true, "on", "on", "ufw status: active");
        }
        if low.contains("status: inactive") {
            return CItem::pass_fail("firewall.enabled", "防火墙已开启", CAT_FW, false, "off", "on", "ufw status: inactive");
        }
    }
    if let Some(s) = c_run("systemctl", &["is-active", "firewalld"]) {
        let on = s.trim() == "active";
        return CItem::pass_fail("firewall.enabled", "防火墙已开启", CAT_FW, on, on_off(on), "on", &format!("firewalld={}", s));
    }
    CItem::unknown("firewall.enabled", "防火墙已开启", CAT_FW, "on", "ufw/firewalld 均不可用")
}

fn linux_screen_items() -> Vec<CItem> {
    let mut out = Vec::new();
    if c_run("gsettings", &["get", "org.gnome.desktop.session", "idle-delay"]).is_none()
        && c_run("which", &["gsettings"]).is_none()
    {
        out.push(CItem::unknown(
            "screensaver.enabled",
            "屏保已启用",
            CAT_SCR,
            "on",
            "无 gsettings（非 GNOME/无图形会话）",
        ));
        out.push(CItem::unknown("screensaver.timeout_sec", "屏保超时(秒)", CAT_SCR, "", "无 gsettings"));
        out.push(CItem::unknown("screensaver.lock", "屏保恢复需口令", CAT_SCR, "on", "无 gsettings"));
        return out;
    }
    match c_run("gsettings", &["get", "org.gnome.desktop.session", "idle-delay"]) {
        Some(s) => {
            if let Some(n) = s.split_whitespace().last().and_then(|v| c_int(v)) {
                out.push(CItem::pass_fail(
                    "screensaver.enabled",
                    "屏保已启用",
                    CAT_SCR,
                    n > 0,
                    on_off(n > 0),
                    "on",
                    &format!("idle-delay={}", s),
                ));
                out.push(CItem::pass_fail(
                    "screensaver.timeout_sec",
                    "屏保超时(秒)",
                    CAT_SCR,
                    true,
                    &n.to_string(),
                    "",
                    &format!("idle-delay={}（阈值由中枢基线判定）", s),
                ));
            }
        }
        None => {
            out.push(CItem::unknown("screensaver.enabled", "屏保已启用", CAT_SCR, "on", "idle-delay 不可读"));
            out.push(CItem::unknown("screensaver.timeout_sec", "屏保超时(秒)", CAT_SCR, "", "idle-delay 不可读"));
        }
    }
    match c_run("gsettings", &["get", "org.gnome.desktop.screensaver", "lock-enabled"]) {
        Some(s) => {
            if let Some(on) = c_truthy(&s) {
                out.push(CItem::pass_fail(
                    "screensaver.lock",
                    "屏保恢复需口令",
                    CAT_SCR,
                    on,
                    on_off(on),
                    "on",
                    &format!("lock-enabled={}", s),
                ))
            }
        }
        None => out.push(CItem::unknown(
            "screensaver.lock",
            "屏保恢复需口令",
            CAT_SCR,
            "on",
            "lock-enabled 不可读",
        )),
    }
    out
}

fn linux_encrypt() -> CItem {
    if let Ok(b) = std::fs::read("/etc/crypttab") {
        if !String::from_utf8_lossy(&b).trim().is_empty() {
            return CItem::pass_fail("disk_encrypt.enabled", "磁盘加密已开启", CAT_ENC, true, "on", "on", "/etc/crypttab 非空");
        }
    }
    match c_run_shell("lsblk -o TYPE 2>/dev/null | grep -c crypt") {
        Some(s) => match c_int(&s) {
            Some(n) if n > 0 => CItem::pass_fail(
                "disk_encrypt.enabled",
                "磁盘加密已开启",
                CAT_ENC,
                true,
                "on",
                "on",
                "lsblk 检测到 crypt 设备",
            ),
            _ => CItem::unknown(
                "disk_encrypt.enabled",
                "磁盘加密已开启",
                CAT_ENC,
                "on",
                "未检测到 crypt 设备/容器",
            ),
        },
        None => CItem::unknown("disk_encrypt.enabled", "磁盘加密已开启", CAT_ENC, "on", "lsblk 不可用"),
    }
}

// ---- Windows：注册表读取走 `reg query` 命令（纯 std，无 FFI）----

/// 读取注册表值，返回字符串形式；不可用或无该值返回 None。
fn reg_query(key: &str, value: &str) -> Option<String> {
    let out = c_run("reg", &["query", key, "/v", value])?;
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("HKEY") || line.starts_with("ERROR") {
            continue;
        }
        // 形如：    NoAutoUpdate    REG_DWORD    0x0
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap_or("");
        if name != value {
            continue;
        }
        let typ = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();
        if rest.is_empty() {
            return None;
        }
        let data = rest.join(" ");
        return Some(match typ {
            "REG_DWORD" => data
                .trim_start_matches("0x")
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect::<String>()
                .parse::<i64>()
                .ok()
                .map(|_| {
                    i64::from_str_radix(data.trim_start_matches("0x").trim(), 16)
                        .map(|v| v.to_string())
                        .unwrap_or(data.clone())
                })
                .unwrap_or(data.clone()),
            _ => data,
        });
    }
    None
}

fn windows_compliance() -> Vec<CItem> {
    let mut out = Vec::new();
    // ---- 补丁 ----
    let au_policy = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
    let au_legacy = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update";
    let mut known = false;
    let mut on = false;
    let mut detail = String::new();
    if let Some(v) = reg_query(au_policy, "NoAutoUpdate") {
        if let Some(n) = c_int(&v) {
            on = n == 0;
            known = true;
            detail = format!("{}\\NoAutoUpdate={}", au_policy, v);
        }
    }
    if !known {
        if let Some(v) = reg_query(au_legacy, "AUOptions") {
            if let Some(n) = c_int(&v) {
                on = n >= 2;
                known = true;
                detail = format!("{}\\AUOptions={}", au_legacy, v);
            }
        }
    }
    if known {
        out.push(CItem::pass_fail(
            "patch.automatic_check",
            "系统更新自动检查",
            CAT_PATCH,
            on,
            on_off(on),
            "on",
            &detail,
        ));
    } else {
        out.push(CItem::unknown(
            "patch.automatic_check",
            "系统更新自动检查",
            CAT_PATCH,
            "on",
            "无 WindowsUpdate 策略/AUOptions 注册表项",
        ));
    }
    match reg_query(au_legacy, "AUOptions") {
        Some(v) => {
            if let Some(n) = c_int(&v) {
                let dl = n >= 3;
                out.push(CItem::pass_fail(
                    "patch.auto_download",
                    "补丁自动下载",
                    CAT_PATCH,
                    dl,
                    on_off(dl),
                    "on",
                    &format!("AUOptions={}", v),
                ))
            }
        }
        None => out.push(CItem::unknown(
            "patch.auto_download",
            "补丁自动下载",
            CAT_PATCH,
            "on",
            "无 AUOptions 注册表项",
        )),
    }
    out.push(CItem::unknown(
        "patch.pending_updates",
        "待安装补丁数",
        CAT_PATCH,
        "0",
        "Windows 未实现该采集项（需 WUA COM 接口；诚实回告，不伪造）",
    ));

    // ---- 杀毒 / EDR ----
    let mut installed: Vec<String> = Vec::new();
    for d in [
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
    ] {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                installed.push(e.file_name().to_string_lossy().to_string());
            }
        }
    }
    if reg_query(r"HKLM\SOFTWARE\Microsoft\Windows Defender", "InstallLocation").is_some()
        || reg_query(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Scan", "DisableAntiSpyware").is_some()
        || reg_query(r"HKLM\SOFTWARE\Microsoft\Windows Defender", "ProductName").is_some()
    {
        installed.push("Windows Defender".to_string());
    }
    let mut running: Vec<String> = Vec::new();
    if let Some(s) = c_run("sc", &["query", "WinDefend"]) {
        if s.to_ascii_uppercase().contains("RUNNING") {
            running.push("WinDefend".to_string());
        }
    }
    if let Some(s) = c_run("tasklist", &["/FO", "CSV", "/NH"]) {
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(first) = line.split(',').next() {
                running.push(first.trim_matches('"').to_string());
            }
        }
    }
    out.extend(av_items(
        &installed,
        &running,
        "程序目录 + Windows Defender 注册表 + sc/tasklist",
    ));

    // ---- 防火墙 ----
    out.push(windows_firewall());
    // ---- 屏保 / 锁屏 ----
    out.extend(windows_screen_items());
    // ---- 磁盘加密 ----
    out.push(windows_encrypt());
    out
}

fn windows_firewall() -> CItem {
    let std_prof =
        r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";
    let dom_prof =
        r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";
    for k in [std_prof, dom_prof] {
        if let Some(v) = reg_query(k, "EnableFirewall") {
            if let Some(on) = c_truthy(&v) {
                return CItem::pass_fail(
                    "firewall.enabled",
                    "防火墙已开启",
                    CAT_FW,
                    on,
                    on_off(on),
                    "on",
                    &format!("{}\\EnableFirewall={}", k, v),
                );
            }
        }
    }
    if let Some(s) = c_run("netsh", &["advfirewall", "show", "allprofiles", "state"]) {
        let up = s.to_ascii_uppercase();
        if up.contains("OFF") && !up.contains("ON") {
            return CItem::pass_fail("firewall.enabled", "防火墙已开启", CAT_FW, false, "off", "on", "netsh: 全部配置档关闭");
        }
        if up.contains("ON") {
            return CItem::pass_fail("firewall.enabled", "防火墙已开启", CAT_FW, true, "on", "on", "netsh: 存在开启的配置档");
        }
    }
    CItem::unknown("firewall.enabled", "防火墙已开启", CAT_FW, "on", "注册表与 netsh 均不可用")
}

fn windows_screen_items() -> Vec<CItem> {
    let mut out = Vec::new();
    let desk = r"HKCU\Control Panel\Desktop";
    let active = reg_query(desk, "ScreenSaveActive");
    let timeout = reg_query(desk, "ScreenSaveTimeOut");
    let secure = reg_query(desk, "ScreenSaverIsSecure");
    match active.as_deref().and_then(c_truthy) {
        Some(on) => out.push(CItem::pass_fail(
            "screensaver.enabled",
            "屏保已启用",
            CAT_SCR,
            on,
            on_off(on),
            "on",
            &format!("{}\\ScreenSaveActive={}", desk, active.clone().unwrap_or_default()),
        )),
        None => out.push(CItem::unknown(
            "screensaver.enabled",
            "屏保已启用",
            CAT_SCR,
            "on",
            "无 ScreenSaveActive 注册表项",
        )),
    }
    match timeout.as_deref().and_then(c_int) {
        Some(n) if n > 0 => out.push(CItem::pass_fail(
            "screensaver.timeout_sec",
            "屏保超时(秒)",
            CAT_SCR,
            true,
            &n.to_string(),
            "",
            &format!("ScreenSaveTimeOut={}（阈值由中枢基线判定）", n),
        )),
        _ => out.push(CItem::unknown(
            "screensaver.timeout_sec",
            "屏保超时(秒)",
            CAT_SCR,
            "",
            "无 ScreenSaveTimeOut 或未启用屏保",
        )),
    }
    match secure.as_deref().and_then(c_truthy) {
        Some(on) => out.push(CItem::pass_fail(
            "screensaver.lock",
            "屏保恢复需口令",
            CAT_SCR,
            on,
            on_off(on),
            "on",
            &format!("{}\\ScreenSaverIsSecure={}", desk, secure.clone().unwrap_or_default()),
        )),
        None => out.push(CItem::unknown(
            "screensaver.lock",
            "屏保恢复需口令",
            CAT_SCR,
            "on",
            "无 ScreenSaverIsSecure 注册表项",
        )),
    }
    out
}

fn windows_encrypt() -> CItem {
    match c_run("manage-bde", &["-status"]) {
        Some(s) => {
            let up = s.to_ascii_uppercase();
            if up.contains("PROTECTION ON") {
                CItem::pass_fail("disk_encrypt.enabled", "磁盘加密已开启", CAT_ENC, true, "on", "on", "BitLocker Protection On")
            } else if up.contains("PROTECTION OFF") {
                CItem::pass_fail("disk_encrypt.enabled", "磁盘加密已开启", CAT_ENC, false, "off", "on", "BitLocker Protection Off")
            } else {
                CItem::unknown("disk_encrypt.enabled", "磁盘加密已开启", CAT_ENC, "on", "manage-bde 输出无法解析")
            }
        }
        None => CItem::unknown(
            "disk_encrypt.enabled",
            "磁盘加密已开启",
            CAT_ENC,
            "on",
            "manage-bde 不可用（家庭版或权限不足）",
        ),
    }
}

// ===================== 指令处理 =====================

/// 是否允许真实卸载（默认 false，仅演练；避免不可逆破坏）。
fn uninstall_enabled() -> bool {
    std::env::var("YUDUAN_W5A_UNINSTALL").map(|v| v == "1").unwrap_or(false)
}

/// 处理 compliance_collect / sw_uninstall / patch_apply；返回 (state, exit_code, output_log)。
pub fn handle(action: &str, command: &str) -> (String, i64, String) {
    match action {
        "compliance_collect" => {
            let items = collect_compliance();
            let body: Vec<String> = items.iter().map(|i| i.to_json()).collect();
            eprintln!("[agent] 合规采集回执 platform={} 项={}", std::env::consts::OS, items.len());
            (
                "success".to_string(),
                0,
                format!(
                    "{{\"platform\":{},\"items\":[{}]}}",
                    json_string(std::env::consts::OS),
                    body.join(",")
                ),
            )
        }
        "sw_uninstall" => uninstall(command),
        "patch_apply" => {
            let d = crate::parse_json(command.as_bytes()).ok();
            let s = |k: &str| {
                d.as_ref()
                    .and_then(|j| j.get(k))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let msg = format!(
                "patch_plan software={} target_version={} repo_item={} dry_run=true (实际安装待分发管线)",
                s("software"),
                s("target_version"),
                s("repo_item_id")
            );
            eprintln!("[agent] 补丁回执 {}", msg);
            ("success".to_string(), 0, msg)
        }
        other => (
            "failed".to_string(),
            1,
            format!("unknown wave5a action: {}", other),
        ),
    }
}

struct UninstallResult {
    software: String,
    platform: String,
    dry_run: bool,
    state: String,
    detail: String,
}

/// sw_uninstall：同一 action 承载两类语义（W3-3 前置卸载用 package 字段，
/// W5-2 黑名单卸载用 software 字段），与 Go 副端一样按 JSON 双字段兼容解析。
fn uninstall(command: &str) -> (String, i64, String) {
    let d = match crate::parse_json(command.as_bytes()) {
        Ok(j) => j,
        Err(e) => {
            return (
                "failed".to_string(),
                -1,
                format!("卸载载荷解析失败: {}", e),
            )
        }
    };
    let s = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (target, dry) = {
        let pkg = s("package");
        if !pkg.is_empty() {
            (pkg, false)
        } else {
            (
                s("software"),
                d.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false),
            )
        }
    };
    let dry_run = dry || !uninstall_enabled();
    let res = do_uninstall(&target, dry_run);
    let out = format!(
        "{{\"software\":{},\"platform\":{},\"dry_run\":{},\"state\":{},\"detail\":{}}}",
        json_string(&res.software),
        json_string(&res.platform),
        res.dry_run,
        json_string(&res.state),
        json_string(&res.detail)
    );
    eprintln!(
        "[agent] 卸载回执 software={} dry_run={} state={}",
        target, res.dry_run, res.state
    );
    let state = if res.state == "failed" { "failed" } else { "success" };
    (state.to_string(), 0, out)
}

fn do_uninstall(software: &str, dry_run: bool) -> UninstallResult {
    let mut res = UninstallResult {
        software: software.to_string(),
        platform: std::env::consts::OS.to_string(),
        dry_run,
        state: "failed".to_string(),
        detail: String::new(),
    };
    if software.trim().is_empty() {
        res.detail = "软件名为空".to_string();
        return res;
    }
    if cfg!(target_os = "windows") {
        match find_uninstall_string(software) {
            None => {
                res.state = "unsupported".to_string();
                res.detail = "未在注册表 Uninstall 找到匹配项".to_string();
            }
            Some(unin) => {
                if dry_run {
                    res.state = "success".to_string();
                    res.detail = format!("演练：将执行 {}", unin);
                } else {
                    let mut c = Command::new("cmd");
                    c.arg("/C").arg(&unin);
                    match c.output() {
                        Ok(o) if o.status.success() => {
                            res.state = "success".to_string();
                            res.detail = format!("已执行卸载：{}", unin);
                        }
                        Ok(o) => {
                            res.detail = format!(
                                "执行失败: {} | {}",
                                o.status,
                                String::from_utf8_lossy(&o.stdout)
                            );
                        }
                        Err(e) => res.detail = format!("执行失败: {}", e),
                    }
                }
            }
        }
        return res;
    }
    if cfg!(target_os = "macos") {
        match find_app(software) {
            None => {
                res.state = "unsupported".to_string();
                res.detail = "未在 /Applications 找到匹配 .app".to_string();
            }
            Some(app) => {
                if dry_run {
                    res.state = "success".to_string();
                    res.detail = format!("演练：将删除 {}", app);
                } else if let Err(e) = std::fs::remove_dir_all(&app) {
                    res.detail = format!("删除失败: {}", e);
                } else {
                    res.state = "success".to_string();
                    res.detail = format!("已删除：{}", app);
                }
            }
        }
        return res;
    }
    // linux
    match find_deb_rpm(software) {
        None => {
            res.state = "unsupported".to_string();
            res.detail = "未找到 dpkg/rpm 包".to_string();
        }
        Some((mgr, rm, name)) => {
            let cmd = format!("{} {} {}", mgr, rm, name);
            if dry_run {
                res.state = "success".to_string();
                res.detail = format!("演练：将执行 {}", cmd);
            } else {
                match Command::new(&mgr).arg(&rm).arg(&name).output() {
                    Ok(o) if o.status.success() => {
                        res.state = "success".to_string();
                        res.detail = format!("已卸载：{}", name);
                    }
                    Ok(o) => {
                        res.detail = format!(
                            "执行失败: {} | {}",
                            o.status,
                            String::from_utf8_lossy(&o.stderr)
                        )
                    }
                    Err(e) => res.detail = format!("执行失败: {}", e),
                }
            }
        }
    }
    res
}

/// 在 Windows 三根 Uninstall 键中按显示名模糊匹配，返回 UninstallString。
fn find_uninstall_string(software: &str) -> Option<String> {
    let keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ];
    let needle = software.to_ascii_lowercase();
    for base in keys {
        let out = match c_run("reg", &["query", base, "/s"]) {
            Some(o) => o,
            None => continue,
        };
        let mut disp = String::new();
        let mut unin = String::new();
        for line in out.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("HKEY") {
                if !disp.is_empty() && !unin.is_empty() && disp.to_ascii_lowercase().contains(&needle) {
                    return Some(unin);
                }
                disp.clear();
                unin.clear();
                continue;
            }
            if line.starts_with("DisplayName") {
                disp = line.splitn(2, "REG_SZ").nth(1).unwrap_or("").trim().to_string();
            } else if line.starts_with("UninstallString") {
                unin = line.splitn(2, "REG_SZ").nth(1).unwrap_or("").trim().to_string();
            }
        }
        if !disp.is_empty() && !unin.is_empty() && disp.to_ascii_lowercase().contains(&needle) {
            return Some(unin);
        }
    }
    None
}

fn find_app(software: &str) -> Option<String> {
    let needle = software.to_ascii_lowercase();
    let rd = std::fs::read_dir("/Applications").ok()?;
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if !n.to_ascii_lowercase().ends_with(".app") {
            continue;
        }
        if n.to_ascii_lowercase().trim_end_matches(".app").contains(&needle) {
            return Some(format!("/Applications/{}", n));
        }
    }
    None
}

fn find_deb_rpm(software: &str) -> Option<(String, String, String)> {
    let needle = software.to_ascii_lowercase();
    if let Some(out) = c_run("dpkg-query", &["-W", "-f=${Package} ${Version}\n"]) {
        for line in out.lines() {
            if let Some(first) = line.split_whitespace().next() {
                if first.to_ascii_lowercase().contains(&needle) {
                    return Some(("dpkg".to_string(), "-r".to_string(), first.to_string()));
                }
            }
        }
    }
    if let Some(out) = c_run("rpm", &["-qa", "--qf", "%{NAME}\n"]) {
        for line in out.lines() {
            if line.to_ascii_lowercase().contains(&needle) {
                return Some(("rpm".to_string(), "-e".to_string(), line.trim().to_string()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthy_parses_platform_values() {
        assert_eq!(c_truthy("1"), Some(true));
        assert_eq!(c_truthy("YES"), Some(true));
        assert_eq!(c_truthy("disabled"), Some(false));
        assert_eq!(c_truthy("garbage"), None);
    }

    #[test]
    fn vendor_match_is_case_insensitive() {
        let names = vec!["CrowdStrike Falcon".to_string(), "Zoom".to_string()];
        assert_eq!(match_vendor(&names), "CrowdStrike Falcon");
        assert_eq!(match_vendor(&["zoom".to_string()]), "");
    }

    #[test]
    fn uninstall_requires_target() {
        let r = do_uninstall("", true);
        assert_eq!(r.state, "failed");
        assert_eq!(r.detail, "软件名为空");
    }

    #[test]
    fn compliance_items_are_honest() {
        // 采集结果不得为空，且每项 state 只能是 pass/fail/unknown
        let items = collect_compliance();
        assert!(!items.is_empty());
        for it in &items {
            assert!(
                it.state == "pass" || it.state == "fail" || it.state == "unknown",
                "非法 state: {}",
                it.state
            );
            assert!(!it.key.is_empty());
        }
    }
}
