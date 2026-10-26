// 御端 Rust 副端 —— M5 软件分发安装（参考互通版）。
// 下载：internal httpget（Content-Length/chunked）。安装：按平台调用系统静默安装器。
//   macOS: .pkg → installer -pkg -target / ；.zip → 解包（ditto/unzip），含 .app 则复制到 /Applications
//   Linux: .deb → dpkg -i（无 root 时 sudo -n）；.rpm → rpm -i；.sh → bash
//   Windows: .msi → msiexec /i /qn /norestart；.exe → 尽力以 /S 静默运行
// 安全（生产化）：安装前校验包 SHA-256 与 Ed25519 签名（中枢 Go crypto/ed25519 签发，
//   签名为「对 32 字节摘要原文」的签名；受信公钥来自指令 payload 或 YUDUAN_SW_PUBKEY）。
//   哈希不符 exit_code=3，验签失败 exit_code=4，均拒绝安装并回报。

use crate::ed25519;
use crate::httpget::download_to_temp;
use crate::sha256::sha256;
use std::process::Command;

pub struct InstallOutcome {
    pub state: String,
    pub exit_code: i64,
    pub output_log: String,
}

/// 安装前校验参数（均可用空串跳过对应校验）。
pub struct PkgVerify<'a> {
    pub sha256: &'a str,    // 期望 SHA-256（hex）
    pub signature: &'a str, // Ed25519 签名（hex），对「32 字节摘要原文」签名
    pub pubkey: &'a str,    // 受信签名公钥（hex）
}

/// 处理 sw_install 指令：下载 → 校验 → 安装。
pub fn handle_sw_install(
    url: &str,
    platform: &str,
    pkg_name: &str,
    verify: &PkgVerify,
) -> InstallOutcome {
    if url.is_empty() {
        return InstallOutcome {
            state: "failed".into(),
            exit_code: 1,
            output_log: "sw_install: 缺少 software_url".into(),
        };
    }
    let (local, suggested) = match download_to_temp(url, "yuduan-sw") {
        Ok(p) => p,
        Err(e) => {
            return InstallOutcome {
                state: "failed".into(),
                exit_code: 1,
                output_log: format!("download failed: {}", e),
            }
        }
    };
    // 安装器按扩展名分派（.pkg/.zip/.dmg/.deb/.rpm/.sh/.msi/.exe），
    // 而下载临时文件统一为 .bin：按「服务端建议文件名 → URL → 包名」顺序补扩展名。
    let local = match suggested
        .as_deref()
        .and_then(ext_of)
        .or_else(|| ext_of(url))
        .or_else(|| ext_of(pkg_name))
    {
        Some(e) if !local.to_ascii_lowercase().ends_with(&format!(".{}", e)) => {
            let renamed = format!("{}.{}", local, e);
            match std::fs::rename(&local, &renamed) {
                Ok(()) => renamed,
                Err(_) => local,
            }
        }
        _ => local,
    };

    // —— 安全校验：先哈希、后验签，任一不符即拒绝安装 ——
    let data = match std::fs::read(&local) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::remove_file(&local);
            return InstallOutcome {
                state: "failed".into(),
                exit_code: 2,
                output_log: format!("read downloaded package failed: {}", e),
            };
        }
    };
    let logs = match verify_package(&data, verify) {
        Ok(l) => l,
        Err((code, reason)) => {
            let _ = std::fs::remove_file(&local);
            return InstallOutcome {
                state: "failed".into(),
                exit_code: code,
                output_log: reason,
            };
        }
    };

    let mut out = install_package(&local, platform, pkg_name);
    out.output_log = format!("{} | {}", logs.join(" | "), out.output_log);
    let _ = std::fs::remove_file(&local);
    out
}

/// 安装前校验（纯函数，便于单测）：SHA-256 比对 + Ed25519 验签。
/// 返回 Ok(日志行) 或 Err((exit_code, 原因))。
pub fn verify_package(data: &[u8], verify: &PkgVerify) -> Result<Vec<String>, (i64, String)> {
    let digest = sha256(data);
    let digest_hex = hex_lower(&digest);
    let mut logs = vec![format!("sha256={}", digest_hex)];

    if !verify.sha256.is_empty() {
        let want = verify.sha256.trim().to_ascii_lowercase();
        if want != digest_hex {
            return Err((
                3,
                format!(
                    "sha256 mismatch: expected {} got {}（包被篡改或信源不符，拒绝安装）",
                    want, digest_hex
                ),
            ));
        }
        logs.push("sha256 ok".into());
    }

    if !verify.signature.is_empty() && !verify.pubkey.is_empty() {
        let sig = match hex_decode(verify.signature) {
            Some(s) if s.len() == 64 => s,
            _ => return Err((4, "signature 字段非法（非 64 字节 hex）".into())),
        };
        let pk = match hex_decode(verify.pubkey) {
            Some(p) if p.len() == 32 => p,
            _ => return Err((4, "signer 公钥字段非法（非 32 字节 hex）".into())),
        };
        if !ed25519::verify(&pk, &digest, &sig) {
            return Err((
                4,
                "Ed25519 验签失败：签名与包内容/受信公钥不匹配，拒绝安装".into(),
            ));
        }
        logs.push("ed25519 signature ok".into());
    } else if !verify.signature.is_empty() || !verify.pubkey.is_empty() {
        // 只给一半 = 配置错误，按拒绝处理（避免「以为验签了其实没验」）
        return Err((
            4,
            "验签参数不完整（signature 与 signer 必须同时提供）".into(),
        ));
    }

    Ok(logs)
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    crate::sha256::hex_decode(s)
}

/// 从 URL 或包名提取合法扩展名（纯字母数字、≤6 字符；拒绝查询串等噪声）。
fn ext_of(s: &str) -> Option<String> {
    let last = s.rsplit('/').next().unwrap_or(s);
    let idx = last.rfind('.')?;
    let ext = &last[idx + 1..];
    if ext.is_empty() || ext.len() > 6 || !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

fn install_package(path: &str, _platform: &str, _pkg: &str) -> InstallOutcome {
    let lower = path.to_ascii_lowercase();
    let (cmd, args): (&str, Vec<String>) = if cfg!(target_os = "macos") {
        if lower.ends_with(".pkg") {
            ("installer", vec!["-pkg".into(), path.into(), "-target".into(), "/".into()])
        } else if lower.ends_with(".zip") {
            return install_zip(path);
        } else if lower.ends_with(".dmg") {
            return install_dmg(path);
        } else {
            return InstallOutcome {
                state: "failed".into(),
                exit_code: 1,
                output_log: format!("macOS 不支持的安装包类型: {}", path),
            };
        }
    } else if cfg!(target_os = "linux") {
        if lower.ends_with(".deb") {
            // 无 root 时尝试 sudo -n（免密）；失败则原样报错
            let uid = uid_is_root();
            if uid {
                ("dpkg", vec!["-i".into(), path.into()])
            } else {
                ("sudo", vec!["-n".into(), "dpkg".into(), "-i".into(), path.into()])
            }
        } else if lower.ends_with(".rpm") {
            ("rpm", vec!["-i".into(), path.into()])
        } else if lower.ends_with(".sh") {
            ("bash", vec![path.into()])
        } else {
            return InstallOutcome {
                state: "failed".into(),
                exit_code: 1,
                output_log: format!("Linux 不支持的安装包类型: {}", path),
            };
        }
    } else if cfg!(target_os = "windows") {
        if lower.ends_with(".msi") {
            ("msiexec", vec!["/i".into(), path.into(), "/qn".into(), "/norestart".into()])
        } else if lower.ends_with(".exe") {
            (path, vec!["/S".into()])
        } else {
            return InstallOutcome {
                state: "failed".into(),
                exit_code: 1,
                output_log: format!("Windows 不支持的安装包类型: {}", path),
            };
        }
    } else {
        return InstallOutcome {
            state: "failed".into(),
            exit_code: 1,
            output_log: "未知平台，无法安装".into(),
        };
    };
    run_cmd(cmd, &args)
}

fn run_cmd(cmd: &str, args: &[String]) -> InstallOutcome {
    match Command::new(cmd).args(args).output() {
        Ok(o) => {
            let mut log = String::from_utf8_lossy(&o.stdout).to_string();
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            if !err.is_empty() {
                if !log.is_empty() {
                    log.push('\n');
                }
                log.push_str(&err);
            }
            let code = o.status.code().unwrap_or(-1) as i64;
            InstallOutcome {
                state: if code == 0 { "success".into() } else { "failed".into() },
                exit_code: code,
                output_log: log,
            }
        }
        Err(e) => InstallOutcome {
            state: "failed".into(),
            exit_code: 127,
            output_log: format!("执行 {} 失败: {}", cmd, e),
        },
    }
}

fn uid_is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

// macOS .zip：解包，含 .app 则复制到 /Applications
fn install_zip(path: &str) -> InstallOutcome {
    let workdir = format!("/tmp/yuduan-unzip-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&workdir);
    if let Err(e) = std::fs::create_dir_all(&workdir) {
        return InstallOutcome { state: "failed".into(), exit_code: 1, output_log: format!("mkdir failed: {}", e) };
    }
    let unzip = run_cmd("ditto", &["-x".into(), "-k".into(), path.into(), workdir.clone()]);
    if unzip.state != "success" {
        let _ = std::fs::remove_dir_all(&workdir);
        return unzip;
    }
    // 查找 .app 并复制到 /Applications
    let apps = find_apps(&workdir);
    let mut logs = vec![unzip.output_log];
    let mut ok = true;
    for app in apps {
        let dest = format!("/Applications/{}", basename(&app));
        let cp = run_cmd("ditto", &[app.clone(), dest.clone()]);
        logs.push(format!("cp {} -> {}: {}", app, dest, cp.output_log.trim()));
        if cp.state != "success" {
            ok = false;
        }
    }
    let _ = std::fs::remove_dir_all(&workdir);
    InstallOutcome {
        state: if ok { "success".into() } else { "failed".into() },
        exit_code: if ok { 0 } else { 1 },
        output_log: logs.join("\n"),
    }
}

// macOS .dmg：挂载 → 复制 .app → 卸载
fn install_dmg(path: &str) -> InstallOutcome {
    let mount_point = format!("/tmp/yuduan-mnt-{}", std::process::id());
    let _ = std::fs::create_dir_all(&mount_point);
    let attach = run_cmd("hdiutil", &["attach".into(), path.into(), "-nobrowse".into(), "-mountpoint".into(), mount_point.clone()]);
    if attach.state != "success" {
        let _ = std::fs::remove_dir_all(&mount_point);
        return attach;
    }
    let apps = find_apps(&mount_point);
    let mut logs = vec![attach.output_log];
    let mut ok = true;
    for app in apps {
        let dest = format!("/Applications/{}", basename(&app));
        let cp = run_cmd("ditto", &[app.clone(), dest.clone()]);
        logs.push(format!("cp {} -> {}: {}", app, dest, cp.output_log.trim()));
        if cp.state != "success" {
            ok = false;
        }
    }
    let _ = run_cmd("hdiutil", &["detach".into(), mount_point.clone(), "-quiet".into()]);
    let _ = std::fs::remove_dir_all(&mount_point);
    InstallOutcome {
        state: if ok { "success".into() } else { "failed".into() },
        exit_code: if ok { 0 } else { 1 },
        output_log: logs.join("\n"),
    }
}

fn find_apps(dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    walk(dir, &mut |p| {
        if p.to_ascii_lowercase().ends_with(".app") {
            out.push(p.to_string());
        }
    });
    out
}

fn walk(dir: &str, f: &mut dyn FnMut(&str)) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Some(s) = p.to_str() {
                    f(s);
                    walk(s, f);
                }
            }
        }
    }
}

fn basename(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_works() {
        assert_eq!(basename("/Applications/Foo.app"), "Foo.app");
    }

    #[test]
    fn ext_of_works() {
        assert_eq!(ext_of("http://h:8080/api/v1/repo/sw-abc123"), None);
        assert_eq!(ext_of("http://h:8080/api/v1/repo/sw-abc123.zip"), Some("zip".into()));
        assert_eq!(ext_of("http://h:8080/x.pkg?token=1"), None);
        assert_eq!(ext_of("my-tool"), None);
        assert_eq!(ext_of("my-tool.pkg"), Some("pkg".into()));
    }

    #[test]
    fn missing_url_fails_fast() {
        let v = PkgVerify { sha256: "", signature: "", pubkey: "" };
        let o = handle_sw_install("", "macos", "x", &v);
        assert_eq!(o.state, "failed");
    }

    #[test]
    fn verify_params_must_be_paired() {
        // 只给签名不给公钥 = 配置错误，必须拒绝（不能当成「无需验签」）
        let v = PkgVerify { sha256: "", signature: "aa", pubkey: "" };
        assert!(verify_package(b"whatever", &v).is_err());
        let v2 = PkgVerify { sha256: "", signature: "", pubkey: "bb" };
        assert!(verify_package(b"whatever", &v2).is_err());
    }

    #[test]
    fn verify_package_signature_flow() {
        // 与 Go crypto/ed25519 同语义：对「32 字节摘要原文」签名
        let seed = crate::sha256::hex_decode("79756475616e2d656432353531392d63726f7373636865636b2d736565642d33").unwrap();
        let pk = crate::ed25519::public_key(&seed).unwrap();
        let pkg = b"yuduan-installer-payload-v1";
        let digest = sha256(pkg);
        let sig = crate::ed25519::sign(&seed, &digest).unwrap();
        let sig_hex = hex_lower(&sig);
        let pk_hex = hex_lower(&pk);
        let want_sha = hex_lower(&digest);

        // 1) 完整校验通过
        let v = PkgVerify { sha256: &want_sha, signature: &sig_hex, pubkey: &pk_hex };
        let logs = verify_package(pkg, &v).expect("正确签名应通过");
        assert!(logs.iter().any(|l| l == "ed25519 signature ok"));

        // 2) 包被篡改 → 拒（exit 3）
        let v = PkgVerify { sha256: &want_sha, signature: &sig_hex, pubkey: &pk_hex };
        let (code, why) = verify_package(b"yuduan-installer-payload-v2", &v).unwrap_err();
        assert_eq!(code, 3);
        assert!(why.contains("sha256 mismatch"));

        // 3) 哈希相符但签名是别的内容 → 拒（exit 4）
        let bad_sig = crate::ed25519::sign(&seed, b"other-message").unwrap();
        let v = PkgVerify { sha256: &want_sha, signature: &hex_lower(&bad_sig), pubkey: &pk_hex };
        let (code, why) = verify_package(pkg, &v).unwrap_err();
        assert_eq!(code, 4);
        assert!(why.contains("验签失败"));

        // 4) 错误公钥 → 拒（exit 4）
        let other_seed = crate::sha256::hex_decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let other_pk = crate::ed25519::public_key(&other_seed).unwrap();
        let v = PkgVerify { sha256: &want_sha, signature: &sig_hex, pubkey: &hex_lower(&other_pk) };
        let (code, _) = verify_package(pkg, &v).unwrap_err();
        assert_eq!(code, 4);

        // 5) 无校验参数 = 放行（兼容旧中枢，仅记录哈希）
        let v = PkgVerify { sha256: "", signature: "", pubkey: "" };
        assert!(verify_package(pkg, &v).is_ok());
    }
}
