// swinv.rs —— W1-1 已安装软件清单采集（Rust 生产副端）。
//
// 与 Go 参考副端 `internal/collect/software*.go` 同构（铁律 2/9）：
//   · 同一份字段（name/version/source/publisher）、同一个注册载荷字段 `software`；
//   · 三平台实现：macOS 扫 .app 读 Info.plist、Linux dpkg-query→rpm 回退、
//     Windows 三根 Uninstall 注册表键（`reg query /s`；管道输出字节经
//     win_net::decode_console_bytes 解码：Windows 走 CP_ACP 的 Win32 FFI，
//     非 Windows 走 std 桩，非 Windows 路径仍纯 std 无 FFI）；
//   · 进程级缓存（软件清单不会在进程生命周期内频繁变化，避免重复枚举开销）。
//
// 该能力是黑名单（W5-2）、漏洞（W5-5）、版本比对差异升级（W3-3）的共同上游：
// 生产副端不上报清单 ⇒ 这些能力在生产副端全线失效，故属必须补齐的缺口。

use std::process::Command;
use std::sync::{Mutex, OnceLock};

#[derive(Clone)]
pub struct SwItem {
    pub name: String,
    pub version: String,
    pub source: String,
    pub publisher: String,
}

impl SwItem {
    pub fn to_json(&self) -> String {
        // 与 proto.InstalledSoftware 的 JSON 标签一致（license 由主端补录，副端不臆测）
        format!(
            "{{\"name\":{},\"version\":{},\"source\":{},\"publisher\":{}}}",
            crate::json_string(&self.name),
            crate::json_string(&self.version),
            crate::json_string(&self.source),
            crate::json_string(&self.publisher)
        )
    }
}

fn cache() -> &'static Mutex<Option<Vec<SwItem>>> {
    static C: OnceLock<Mutex<Option<Vec<SwItem>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// 采集本进程生命周期内的软件清单（首次调用真实枚举，其后走缓存）。
pub fn software() -> Vec<SwItem> {
    let mut c = cache().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(v) = &*c {
        return v.clone();
    }
    let items = if cfg!(target_os = "macos") {
        mac_software()
    } else if cfg!(target_os = "windows") {
        windows_software()
    } else {
        linux_software()
    };
    *c = Some(items.clone());
    items
}

/// 序列化为注册载荷的 software 字段（空清单返回 "[]"）。
pub fn to_json_array(items: &[SwItem]) -> String {
    if items.is_empty() {
        return "[]".to_string();
    }
    let parts: Vec<String> = items.iter().map(|i| i.to_json()).collect();
    format!("[{}]", parts.join(","))
}

fn run_out(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    if !o.status.success() {
        return None;
    }
    // F-03：中文 Windows 下 reg.exe 管道输出是系统 ANSI(CP936/GBK) 字节，
    // 直接 from_utf8_lossy 会把每个非法字节替换成 U+FFFD（publisher 中文全毁）。
    // 统一交给 win_net::decode_console_bytes（严格 UTF-8 → CP_ACP MultiByteToWideChar）。
    // 该函数在 Windows 与非 Windows 均有定义（main.rs 的 mod win_net 双定义），
    // 故此处无需 cfg 分支；非 Windows stub 仍是 from_utf8_lossy，行为保持不变。
    Some(crate::win_net::decode_console_bytes(&o.stdout))
}

// ---- macOS：扫 .app 读 Info.plist ----

fn mac_software() -> Vec<SwItem> {
    let mut dirs = vec!["/Applications".to_string(), "/System/Applications".to_string()];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(format!("{}/Applications", home));
    }
    let mut out: Vec<SwItem> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for dir in &dirs {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let file_name = e.file_name().to_string_lossy().to_string();
            if !file_name.ends_with(".app") {
                continue;
            }
            let info = e.path().join("Contents").join("Info.plist");
            let b = match std::fs::read(&info) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let s = String::from_utf8_lossy(&b).to_string();
            let mut app_name = plist_string(&s, "CFBundleName");
            if app_name.is_empty() {
                app_name = file_name.trim_end_matches(".app").to_string();
            }
            let key = app_name.to_ascii_lowercase();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            out.push(SwItem {
                name: app_name,
                version: plist_string(&s, "CFBundleShortVersionString"),
                source: format!("app_bundle:{}", dir),
                publisher: plist_string(&s, "CFBundleIdentifier"),
            });
        }
    }
    out.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
    out
}

/// 从 Info.plist XML 中提取 <key>k</key><string>v</string> 的 v（只处理 string 类型值）。
fn plist_string(xml: &str, key: &str) -> String {
    let needle = format!("<key>{}</key>", key);
    let idx = match xml.find(&needle) {
        Some(i) => i + needle.len(),
        None => return String::new(),
    };
    let rest = &xml[idx..];
    let si = match rest.find("<string>") {
        Some(i) => i + "<string>".len(),
        None => return String::new(),
    };
    let rest = &rest[si..];
    let ei = match rest.find("</string>") {
        Some(i) => i,
        None => return String::new(),
    };
    rest[..ei].trim().to_string()
}

// ---- Linux：dpkg 优先，rpm 回退 ----

fn linux_software() -> Vec<SwItem> {
    if let Some(out) = run_out("dpkg-query", &["-W", "-f=${Package}\t${Version}\t${Maintainer}\n"]) {
        if out.contains('\t') {
            return parse_tab_lines(&out, "linux_pkg");
        }
    }
    if let Some(out) = run_out("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"]) {
        if out.contains('\t') {
            return parse_tab_lines(&out, "linux_rpm");
        }
    }
    Vec::new()
}

fn parse_tab_lines(out: &str, source: &str) -> Vec<SwItem> {
    let mut items: Vec<SwItem> = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let name = f.first().unwrap_or(&"").trim().to_string();
        if name.is_empty() {
            continue;
        }
        items.push(SwItem {
            name,
            version: f.get(1).unwrap_or(&"").trim().to_string(),
            source: source.to_string(),
            publisher: f.get(2).unwrap_or(&"").trim().to_string(),
        });
    }
    items.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
    items
}

// ---- Windows：三根 Uninstall 键 ----

const WIN_UNINSTALL_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
];

fn windows_software() -> Vec<SwItem> {
    let mut out: Vec<SwItem> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for base in WIN_UNINSTALL_KEYS {
        let dump = match run_out("reg", &["query", base, "/s"]) {
            Some(d) => d,
            None => continue,
        };
        let mut name = String::new();
        let mut version = String::new();
        let mut publisher = String::new();
        let mut flush = |name: &mut String, version: &mut String, publisher: &mut String| {
            if name.is_empty() {
                return;
            }
            let key = name.to_ascii_lowercase();
            if seen.contains(&key) {
                *name = String::new();
                *version = String::new();
                *publisher = String::new();
                return;
            }
            seen.push(key);
            out.push(SwItem {
                name: name.clone(),
                version: version.clone(),
                source: "registry".to_string(),
                publisher: publisher.clone(),
            });
            *name = String::new();
            *version = String::new();
            *publisher = String::new();
        };
        for line in dump.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("HKEY") {
                flush(&mut name, &mut version, &mut publisher);
                continue;
            }
            let val = |line: &str| -> String {
                line.splitn(2, "REG_SZ").nth(1).unwrap_or("").trim().to_string()
            };
            if line.starts_with("DisplayName") {
                name = val(line);
            } else if line.starts_with("DisplayVersion") {
                version = val(line);
            } else if line.starts_with("Publisher") {
                publisher = val(line);
            }
        }
        flush(&mut name, &mut version, &mut publisher);
    }
    out.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_string_extracts_values() {
        let xml = "<dict><key>CFBundleName</key><string>Demo App</string>\
                   <key>CFBundleShortVersionString</key><string>1.2.3</string></dict>";
        assert_eq!(plist_string(xml, "CFBundleName"), "Demo App");
        assert_eq!(plist_string(xml, "CFBundleShortVersionString"), "1.2.3");
        assert_eq!(plist_string(xml, "CFBundleIdentifier"), "");
    }

    #[test]
    fn tab_lines_parse_name_version_publisher() {
        let out = "zoom\t5.0.1\tZoom Video Communications\nvim\t2:8.2\tDebian\n";
        let items = parse_tab_lines(out, "linux_pkg");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "vim"); // 按名称排序（小写）
        assert_eq!(items[1].name, "zoom");
        assert_eq!(items[1].version, "5.0.1");
        assert_eq!(items[1].publisher, "Zoom Video Communications");
    }

    #[test]
    fn json_array_shape_matches_proto() {
        assert_eq!(to_json_array(&[]), "[]");
        let one = vec![SwItem {
            name: "Demo".to_string(),
            version: "1.0".to_string(),
            source: "app_bundle:/Applications".to_string(),
            publisher: "com.demo".to_string(),
        }];
        let s = to_json_array(&one);
        assert!(s.starts_with("[{"));
        assert!(s.contains("\"name\":\"Demo\""));
        assert!(s.contains("\"publisher\":\"com.demo\""));
    }

    #[test]
    fn software_collection_is_cached_and_sorted() {
        let a = software();
        let b = software();
        assert_eq!(a.len(), b.len());
        for w in a.windows(2) {
            assert!(w[0].name.to_ascii_lowercase() <= w[1].name.to_ascii_lowercase());
        }
    }

    #[test]
    fn run_out_decode_contract_utf8_passthrough() {
        // F-03 接线验证：run_out 现在统一经 win_net::decode_console_bytes。
        // 合法 UTF-8（含中文）在 Windows（严格 UTF-8 分支）与非 Windows
        // （stub 的 from_utf8_lossy）都应原样返回，不产生 U+FFFD。
        let s = "360 安全卫士";
        let decoded = crate::win_net::decode_console_bytes(s.as_bytes());
        assert_eq!(decoded, s);
        assert!(!decoded.contains('\u{FFFD}'));
    }

    #[test]
    fn old_lossy_decode_would_corrupt_cp936() {
        // 反证 F-03 根因：同样的 CP936 字节若走旧的 from_utf8_lossy，
        // 必然出现 U+FFFD。此用例三平台均可跑，与下方 Windows 修复断言形成对照。
        let bytes: &[u8] = &[0xB0, 0xB2, 0xC8, 0xAB, 0xCE, 0xC0, 0xCA, 0xBF]; // 安全卫士
        let old = String::from_utf8_lossy(bytes);
        assert!(old.contains('\u{FFFD}'));
    }

    // CP936 真值断言只能在 Windows 跑：非 Windows 的 win_net stub 是
    // from_utf8_lossy，对 CP936 字节必然产出 U+FFFD（该桩语义不可改，
    // run_output_gbk 等既有调用方共用）。故用 #[cfg(windows)] 门控，
    // 保证 macOS/Linux 全量 cargo test 不被此用例拖红。
    #[cfg(windows)]
    #[test]
    fn cp936_publisher_decodes_without_replacement_char() {
        // 「360 安全卫士」的 CP936(GBK) 字节（Python: "360 安全卫士".encode('gbk') 核证）：
        // 中文 Windows 下 reg query /s 输出的 publisher 即此编码。
        let bytes: &[u8] = &[
            0x33, 0x36, 0x30, 0x20, 0xB0, 0xB2, 0xC8, 0xAB, 0xCE, 0xC0, 0xCA, 0xBF,
        ];
        let decoded = crate::win_net::decode_console_bytes(bytes);
        assert!(
            !decoded.contains('\u{FFFD}'),
            "CP936 字节不应产生 U+FFFD，实际解码: {:?}",
            decoded
        );
        assert_eq!(decoded, "360 安全卫士");
    }
}
