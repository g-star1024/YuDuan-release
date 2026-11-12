// wave3.rs —— 波次 3（W3-2 分发安装 / W3-3 差异升级）Rust 生产副端实现。
//
// 与 Go 参考副端 `dev/cmd/agent/wave3.go` 严格同构（铁律 2/9）：
//   · 同一 action（sw_dist）、同一载荷字段（SwDistDetail JSON 承载在 command 字段）；
//   · 同一开关（YUDUAN_W3_INSTALL=1 才真实安装，默认演练）；
//   · 同样的诚实回告：下载失败/校验失败/未确认/平台不支持一律回告原因，绝不伪造成功。
//
// 纯 std：下载复用 httpget（手写 HTTP/1.1），哈希复用 sha256（FIPS 180-4）。

use crate::{json_string, Json};
use std::process::Command;

/// 单安装包上限 512MB（与中枢分发仓储上限一致）。
const MAX_PACKAGE_BYTES: usize = 512 << 20;

/// 是否允许真实安装（默认 false：仅下载+校验+演练，避免误装）。
fn install_enabled() -> bool {
    std::env::var("YUDUAN_W3_INSTALL").map(|v| v == "1").unwrap_or(false)
}

/// 分发执行结果（与中枢 w3DispatchRecord 期望的 JSON 结构一致）。
#[derive(Clone)]
struct InstallResult {
    state: String,
    exit_code: i64,
    detail: String,
    dry_run: bool,
    pkg: String,
    platform: String,
}

impl InstallResult {
    fn to_json(&self) -> String {
        format!(
            "{{\"state\":{},\"exit_code\":{},\"detail\":{},\"dry_run\":{},\"pkg\":{},\"platform\":{}}}",
            json_string(&self.state),
            self.exit_code,
            json_string(&self.detail),
            self.dry_run,
            json_string(&self.pkg),
            json_string(&self.platform)
        )
    }
}

/// 处理 sw_dist 指令，返回 (state, exit_code, output_log)。
pub fn handle_sw_dist(payload: &Json, command: &str) -> (String, i64, String) {
    let url = payload.get("software_url").and_then(|v| v.as_str()).unwrap_or("");
    let platform_raw = payload.get("platform").and_then(|v| v.as_str()).unwrap_or("");
    let pkg_name = payload.get("pkg_name").and_then(|v| v.as_str()).unwrap_or("");
    let want_sha = payload.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
    // 平台缺省时以本机为准（中枢下发跨平台包时会显式给出目标平台）。
    let platform = if platform_raw.is_empty() {
        crate::detect_os()
    } else {
        platform_raw.to_string()
    };

    let d = match crate::parse_json(command.as_bytes()) {
        Ok(j) => j,
        Err(e) => {
            return (
                "failed".to_string(),
                -1,
                format!("分发载荷解析失败: {}", e),
            )
        }
    };
    let s = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let custom_args = s("custom_args");
    let silent_args = s("silent_args");
    let mode = s("mode");
    let confirmed = d.get("confirmed").and_then(|v| v.as_bool()).unwrap_or(false);

    let mut res = InstallResult {
        state: "failed".to_string(),
        exit_code: -1,
        detail: String::new(),
        dry_run: false,
        pkg: pkg_name.to_string(),
        platform: platform.clone(),
    };

    if url.trim().is_empty() && custom_args.trim().is_empty() {
        res.detail = "缺少安装包地址与自定义命令行".to_string();
        return (res.state.clone(), res.exit_code, res.to_json());
    }

    // ---- 可选分发：未取得终端用户确认时挂起（非终态，中枢据此等待 confirm）----
    if mode == "optional" && !confirmed {
        res.state = "confirm_required".to_string();
        res.exit_code = 0;
        res.detail = "可选分发：等待终端用户确认安装".to_string();
        return (res.state.clone(), res.exit_code, res.to_json());
    }

    // ---- 下载安装包并做 SHA-256 校验（M5 加固口径）----
    let mut tmp: Option<String> = None;
    if !url.trim().is_empty() {
        match download(url) {
            Err(e) => {
                res.detail = format!("下载安装包失败: {}", e);
                return (res.state.clone(), res.exit_code, res.to_json());
            }
            Ok(path) => {
                // ---- M5 加固 / S-8 修复：SHA-256 强制校验（缺省即拒绝）----
                //
                // 与 Go 参考副端同口径（铁律 2：三平台同构）。此前摘要「有则校、
                // 无则放行」，而安装包最终以 SYSTEM/root 权限静默执行——内网对路径者
                // 替换响应体即可获得任意代码执行。摘要由中枢经 HMAC 签名的指令通道
                // 送达（不可篡改），是与传输无关的完整性依据。
                if want_sha.trim().is_empty() {
                    let _ = std::fs::remove_file(&path);
                    res.detail = "拒绝安装：分发指令缺少 SHA-256 摘要（伪造包防护强制项）；\
                                  仓库包请在软件仓库重新上传以生成摘要，外部地址请在任务里显式提供 sha256"
                        .to_string();
                    return (res.state.clone(), res.exit_code, res.to_json());
                }
                match std::fs::read(&path) {
                    Err(e) => {
                        res.detail = format!("读取安装包失败: {}", e);
                        let _ = std::fs::remove_file(&path);
                        return (res.state.clone(), res.exit_code, res.to_json());
                    }
                    Ok(buf) => {
                        let got = crate::sha256::hex_encode(&crate::sha256::sha256(&buf));
                        if !got.eq_ignore_ascii_case(want_sha.trim()) {
                            res.detail = format!("SHA-256 校验失败: 期望 {} 实得 {}", want_sha.trim(), got);
                            let _ = std::fs::remove_file(&path);
                            return (res.state.clone(), res.exit_code, res.to_json());
                        }
                    }
                }
                tmp = Some(path);
            }
        }
    }

    // ---- 静默安装 ----
    if !install_enabled() {
        res.state = "success".to_string();
        res.exit_code = 0;
        res.dry_run = true;
        res.detail = "演练：安装包已就绪并通过校验，但未开启真实安装（YUDUAN_W3_INSTALL!=1）".to_string();
        if let Some(p) = &tmp {
            let _ = std::fs::remove_file(p);
        }
        return (res.state.clone(), res.exit_code, res.to_json());
    }

    let mut args = silent_args.trim().to_string();
    if args.is_empty() {
        args = custom_args.trim().to_string();
    }
    if args.is_empty() {
        args = default_args(&platform, pkg_name);
    }
    let local = tmp.clone().unwrap_or_default();
    let (out, code, err) = run_installer(&platform, &local, pkg_name, &args);
    if let Some(p) = &tmp {
        let _ = std::fs::remove_file(p);
    }
    if err {
        res.detail = format!("安装执行失败: {}", first_n(&out, 400));
        if code != 0 {
            res.exit_code = code;
        }
        return (res.state.clone(), res.exit_code, res.to_json());
    }
    res.state = "success".to_string();
    res.exit_code = code;
    res.detail = first_n(&format!("安装完成: {}", out), 400);
    (res.state.clone(), res.exit_code, res.to_json())
}

/// 从中枢 REST 下载安装包到临时文件；返回落盘路径。
fn download(raw: &str) -> Result<String, String> {
    let mut u = raw.trim().to_string();
    if !u.starts_with("http://") && !u.starts_with("https://") {
        // 相对路径 / 仅 host:port —— 补协议与中枢地址（与 Go 副端 w3Download 同口径）
        let base = hub_rest().ok_or_else(|| "无法解析中枢地址（YUDUAN_HUB 未配置）".to_string())?;
        u = format!("{}/{}", base.trim_end_matches('/'), u.trim_start_matches('/'));
    }
    // v0.4.25：https 直连下载已补齐（openssl s_client 管道，与 wss/claim 共用严格校验规划）。
    // http 路径一字不动，局域网明文仓库行为不变。
    let resp = if u.starts_with("https://") {
        crate::httpget::https_get(&u, 600)?
    } else {
        crate::httpget::http_get(&u, 600).map_err(|e| e.to_string())?
    };
    if resp.status != 200 {
        return Err(format!("HTTP {}", resp.status));
    }
    if resp.body.len() > MAX_PACKAGE_BYTES {
        return Err(format!("安装包超过上限 {} 字节", MAX_PACKAGE_BYTES));
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "yuduan-pkg-{}-{}.bin",
        std::process::id(),
        nanos % 1_000_000
    ));
    std::fs::write(&path, &resp.body).map_err(|e| format!("写临时文件失败: {}", e))?;
    Ok(path.to_string_lossy().to_string())
}

/// 从 YUDUAN_HUB 推导中枢 REST 基址（ws://host:port/ws/agent → http://host:port）。
fn hub_rest() -> Option<String> {
    let hub = std::env::var("YUDUAN_HUB").ok()?;
    let hub = hub.trim().to_string();
    if hub.is_empty() {
        return None;
    }
    let rest = hub
        .trim_start_matches("ws://")
        .trim_start_matches("wss://");
    let host = match rest.find('/') {
        Some(i) => &rest[..i],
        None => rest,
    };
    Some(format!("http://{}", host))
}

/// 平台默认静默参数（模板未命中时兜底，避免交互式安装挂起）。
fn default_args(platform: &str, pkg_name: &str) -> String {
    let ext = ext_of(pkg_name);
    match platform {
        "windows" => match ext.as_str() {
            "msi" => "/qn /norestart".to_string(),
            "exe" => "/VERYSILENT /NORESTART".to_string(),
            _ => "/S".to_string(),
        },
        "macos" | "darwin" => {
            if ext == "dmg" {
                "mount-and-copy".to_string()
            } else {
                "-target /".to_string()
            }
        }
        _ => String::new(),
    }
}

fn ext_of(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.rfind('.') {
        Some(i) => base[i + 1..].to_ascii_lowercase(),
        None => String::new(),
    }
}

/// 按平台执行静默安装，返回 (输出, 退出码, 是否失败)。
fn run_installer(platform: &str, local: &str, pkg_name: &str, args: &str) -> (String, i64, bool) {
    let ext = ext_of(pkg_name);
    let argv: Vec<String> = args.split_whitespace().map(|s| s.to_string()).collect();
    match platform {
        "windows" => {
            if ext == "msi" {
                let mut c = Command::new("msiexec");
                c.arg("/i").arg(local);
                for a in &argv {
                    c.arg(a);
                }
                return run_out(c);
            }
            let mut c = Command::new(local);
            for a in &argv {
                c.arg(a);
            }
            run_out(c)
        }
        "macos" | "darwin" => {
            if ext == "dmg" {
                return install_dmg(local, args);
            }
            if ext == "pkg" {
                let mut c = Command::new("installer");
                c.arg("-pkg").arg(local).arg("-target").arg("/");
                for a in &argv {
                    c.arg(a);
                }
                return run_out(c);
            }
            let dst = format!("/Applications/{}", basename(local));
            let mut c = Command::new("ditto");
            c.arg(local).arg(dst);
            run_out(c)
        }
        _ => {
            if ext == "deb" {
                let mut c = Command::new("dpkg");
                c.arg("-i").arg(local);
                for a in &argv {
                    c.arg(a);
                }
                return run_out(c);
            }
            if ext == "rpm" {
                let mut c = Command::new("rpm");
                c.arg("-i").arg(local);
                for a in &argv {
                    c.arg(a);
                }
                return run_out(c);
            }
            run_out_shell(&format!("{} {}", local, args))
        }
    }
}

/// dmg：挂载 → 拷贝 .app → 卸载（macOS）。
fn install_dmg(local: &str, _args: &str) -> (String, i64, bool) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mnt = std::env::temp_dir().join(format!("yuduan-dmg-{}-{}", std::process::id(), nanos % 1_000_000));
    if let Err(e) = std::fs::create_dir_all(&mnt) {
        return (format!("创建挂载点失败: {}", e), -1, true);
    }
    let ms = mnt.to_string_lossy().to_string();
    let (out, code, failed) = run_out_shell(&format!("hdiutil attach {} -mountpoint {}", quote(local), quote(&ms)));
    if failed {
        let _ = std::fs::remove_dir_all(&mnt);
        return (out, code, true);
    }
    let mut apps: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&mnt) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.ends_with(".app") {
                apps.push(e.path().to_string_lossy().to_string());
            }
        }
    }
    if apps.is_empty() {
        let _ = run_out_shell(&format!("hdiutil detach {}", quote(&ms)));
        let _ = std::fs::remove_dir_all(&mnt);
        return ("未找到 .app".to_string(), -1, true);
    }
    for app in &apps {
        let dst = format!("/Applications/{}", basename(app));
        let (o, c, f) = run_out_shell(&format!("ditto {} {}", quote(app), quote(&dst)));
        if f {
            let _ = run_out_shell(&format!("hdiutil detach {}", quote(&ms)));
            let _ = std::fs::remove_dir_all(&mnt);
            return (o, c, true);
        }
    }
    let _ = run_out_shell(&format!("hdiutil detach {}", quote(&ms)));
    let _ = std::fs::remove_dir_all(&mnt);
    (format!("已安装 {}", basename(&apps[0])), 0, false)
}

fn quote(s: &str) -> String {
    if s.contains(' ') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

fn basename(p: &str) -> String {
    p.rsplit(['/', '\\']).next().unwrap_or(p).to_string()
}

fn run_out(mut c: Command) -> (String, i64, bool) {
    match c.output() {
        Ok(o) => {
            let mut log = String::from_utf8_lossy(&o.stdout).to_string();
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            if !err.is_empty() {
                if !log.is_empty() {
                    log.push('\n');
                }
                log.push_str(&err);
            }
            let code = o.status.code().unwrap_or(-1);
            (log, code as i64, !o.status.success())
        }
        Err(e) => (format!("执行失败: {}", e), 127, true),
    }
}

fn run_out_shell(cmd: &str) -> (String, i64, bool) {
    let (shell, flag) = if cfg!(windows) { ("cmd", "/c") } else { ("sh", "-c") };
    let mut c = Command::new(shell);
    c.arg(flag).arg(cmd);
    run_out(c)
}

fn first_n(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{}…", t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_of_parses_pkg_type() {
        assert_eq!(ext_of("a/b/Demo.PKG"), "pkg");
        assert_eq!(ext_of("setup"), "");
    }

    #[test]
    fn default_args_cover_three_platforms() {
        assert_eq!(default_args("windows", "x.msi"), "/qn /norestart");
        assert_eq!(default_args("windows", "x.exe"), "/VERYSILENT /NORESTART");
        assert_eq!(default_args("macos", "x.dmg"), "mount-and-copy");
        assert_eq!(default_args("macos", "x.pkg"), "-target /");
        assert_eq!(default_args("linux", "x.deb"), "");
    }

    #[test]
    fn hub_rest_derives_from_ws_url() {
        std::env::set_var("YUDUAN_HUB", "ws://127.0.0.1:8080/ws/agent");
        assert_eq!(hub_rest().unwrap(), "http://127.0.0.1:8080");
        std::env::remove_var("YUDUAN_HUB");
        assert!(hub_rest().is_none());
    }
}
