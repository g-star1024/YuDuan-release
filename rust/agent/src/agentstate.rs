// 副端本地身份持久化（device_id 持久化，Windows 实机验证报告建议项）。
//
// 背景：hub 按 register 载荷中的 token 复用设备身份（store.byToken）。此前 token
// 只存内存，副端重启后重新注册会被 hub 当作**新设备**（设备列表漂移/重复）。
// 本模块把 (device_id, token) 落盘，重启后复用，保持设备身份稳定。
//
// 存储位置：YUDUAN_STATE_FILE 环境变量优先；默认 `~/.yuduan/agent-state.json`
// （HOME / USERPROFILE，三平台同构）。格式：{"device_id":"...","token":"..."}。

use std::path::PathBuf;

/// 状态文件路径：YUDUAN_STATE_FILE 优先，否则 $HOME/.yuduan/agent-state.json。
/// 无法定位主目录时返回 None（调用方跳过持久化，行为退回重启即新身份）。
pub fn state_file() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("YUDUAN_STATE_FILE") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    if home.trim().is_empty() {
        return None;
    }
    let mut p = PathBuf::from(home);
    p.push(".yuduan");
    p.push("agent-state.json");
    Some(p)
}

/// 读取本地身份：(device_id, token)；文件缺失/损坏返回 ("", "")。
pub fn load() -> (String, String) {
    let Some(path) = state_file() else {
        return (String::new(), String::new());
    };
    let Ok(data) = std::fs::read_to_string(&path) else {
        return (String::new(), String::new());
    };
    let v = crate::parse_json(data.as_bytes()).unwrap_or_else(|_| crate::Json::Null);
    let get = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    (get("device_id"), get("token"))
}

/// 保存身份（写临时文件后原子改名，防中途崩溃留下半截 JSON）。
/// 失败仅记日志——持久化是增强，不阻塞注册主流程。
pub fn save(device_id: &str, token: &str) {
    let Some(path) = state_file() else { return };
    let body = format!(
        "{{\"device_id\":{},\"token\":{}}}",
        crate::json_string(device_id),
        crate::json_string(token)
    );
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, body.as_bytes())
        .and_then(|_| std::fs::rename(&tmp, &path))
        .is_err()
    {
        eprintln!("[agent] 设备身份落盘失败（不影响注册，重启后将以新身份注册）: {}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip_with_env_file() {
        let _g = crate::test_lock(); // 进程全局状态互斥（并行测试隔离）
        let path = std::env::temp_dir().join(format!("yd-state-test-{}.json", std::process::id()));
        std::env::set_var("YUDUAN_STATE_FILE", &path);
        std::fs::remove_file(&path).ok();

        // 未落盘 → 空身份
        let (did, tok) = load();
        assert!(did.is_empty() && tok.is_empty());

        // 保存 → 读回一致
        save("dev-abc123", "tok-xyz");
        let (did, tok) = load();
        assert_eq!(did, "dev-abc123");
        assert_eq!(tok, "tok-xyz");

        // 损坏文件 → 空身份（不 panic）
        std::fs::write(&path, "{broken json").unwrap();
        let (did, tok) = load();
        assert!(did.is_empty() && tok.is_empty());

        std::fs::remove_file(&path).ok();
        std::env::remove_var("YUDUAN_STATE_FILE");
    }
}
