// 副端每设备 Ed25519 身份密钥（v0.4.31 安全 P2 基础，§9.2）。
//
// 【本期新增了什么】交叉调研（probe-p2-rust / probe-p2b-rust）确认：本期之前
// `rust/agent/src/` **四件已有**——① Ed25519 原语（ed25519.rs，RFC 8032 纯实现）、
// ② SHA-256 / HMAC 原语（sha256.rs）、③ 本地二进制度量（tamper.rs self_sha256）、
// ④ 审计链（既有）；但 Grep 全目录**无任何密码学随机源**（urandom / BCryptGenRandom /
// SystemFunction036 / RtlGenRandom / getrandom / SecRandomCopyBytes / OsRng /
// CryptGenRandom 全部 No matches），`main.rs:534-558 Lcg` 仅用于掩码、Sec-WebSocket-Key、
// msg_id、session rng，全非密码学。故本期**第五件从零新建**：CSPRNG + 每设备密钥
// 生命周期（本文件）。这也是本期唯一落地路线——副端自生成 Ed25519 keypair；
// mTLS 客户端证书仅作「中枢已具备每设备证书签发能力」的参考事实，本期不接线，
// 若将来叠加为双因子属修改既有 Gate 裁决，须单独评审。
//
// 与 HMAC 引导密钥（config.rs / agent-config.json）**彻底分开**：
//   - HMAC 密钥是全网同一把、随中枢轮换需重新 claim（生命周期短）；
//   - 设备密钥是每台机器独有的长期身份，绝不能被密钥轮换自愈
//     （main.rs 连续注册被拒 → config::delete_config_file()）或 --setup 重装连带删除，
//     否则中枢台账里同一台机器会冒出新公钥、旧记录成孤儿。
// 故落盘为**独立文件 agent-devicekey.json**。
//
// 纯 std + 系统 FFI（零新增 crate，离线 `rustc -O src/main.rs` 单文件直编铁律）：
//   - Windows：RtlGenRandom（SystemFunction036 / advapi32），显式 #[link(name = "advapi32")]；
//   - macOS/Linux：/dev/urandom 读满 32 字节。
// 三平台 CSPRNG 同构（铁律 2）。读不满 32 字节 / FFI 返回 false 一律 **fail-closed 安全失败**：
// seed 可预测 ⇒ 设备私钥可预测 ⇒ 每设备签名与二进制度量证明全部可伪造 ⇒ attestation
// 信任根整体失效，比「本设备暂不支持证明」严重得多。宁可不证明，不可用假证明。
// 故绝不回落 Lcg / SystemTime / 固定值 / 设备指纹（MAC/序列号/hostname 派生）；失败即
// 拒绝启用 attestation + 日志告警，保持原 HMAC 共享密钥链路（原三字段）继续注册与心跳，
// 功能不中断、不 panic、不退出。
//
// 落盘：seed(32B) → hex 字符串 → [Windows DPAPI protect → blob → hex] → JSON
// {"seed":...,"enc":...}；非 Windows 明文 + 0600（如实标注：mac/Linux 无系统密钥库）。
// 原子写 tmp + rename。读取时 seed hex 反解并重新推导公钥（不信任文件里的任何公钥）。

use std::path::PathBuf;

// ===================== 平台 CSPRNG =====================

// RtlGenRandom 在 advapi32.dll 的真实导出名是 SystemFunction036。
// 铁律：新增 Windows extern "system" 块必须显式 #[link(name = "advapi32")]——
// 漏写只在 MSVC 链接阶段才爆（本地/cargo 测试都发现不了）。BOOLEAN 返回 u8。
#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    #[link_name = "SystemFunction036"]
    fn rtl_gen_random(buffer: *mut u8, length: u32) -> u8;
}

// CSPRNG 测试注入点（仅测试二进制、仅非 Windows）：thread_local 隔离，避免并行测试串扰。
// 生产二进制完全不编译此段，路径恒为 /dev/urandom，无任何可被利用的覆盖入口。
#[cfg(all(test, not(windows)))]
thread_local! {
    static TEST_URANDOM: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}
#[cfg(all(test, not(windows)))]
fn set_test_urandom(path: Option<&str>) {
    TEST_URANDOM.with(|c| *c.borrow_mut() = path.map(|s| s.to_string()));
}
#[cfg(all(test, not(windows)))]
fn urandom_path() -> String {
    TEST_URANDOM
        .with(|c| c.borrow().clone())
        .unwrap_or_else(|| "/dev/urandom".to_string())
}

/// 生成 32 字节密码学随机 seed。任一环节失败返回 None，绝不退化（fail-closed）。
/// 失败时由调用方拒绝启用 attestation、保持原 HMAC 链路继续注册，功能不中断。
fn random_seed_32() -> Option<[u8; 32]> {
    let mut buf = [0u8; 32];
    #[cfg(windows)]
    {
        let ok = unsafe { rtl_gen_random(buf.as_mut_ptr(), buf.len() as u32) };
        if ok == 0 {
            return None; // FFI 返回 false：安全失败，绝不回落伪随机
        }
    }
    #[cfg(not(windows))]
    {
        use std::io::Read;
        #[cfg(test)]
        let path = urandom_path();
        #[cfg(not(test))]
        let path = "/dev/urandom".to_string();
        let mut f = std::fs::File::open(&path).ok()?; // 打不开 → None
        f.read_exact(&mut buf).ok()?; // 读不满 32 字节 → None，不补零、不退化
    }
    Some(buf)
}

// ===================== 密钥结构 =====================

/// 每设备密钥：私钥种子 + 由种子推导的公钥。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceKey {
    pub seed: [u8; 32],
    pub public: Vec<u8>, // 32 字节
}

/// 生成新 keypair：CSPRNG seed → ed25519::public_key(seed)。
pub fn generate() -> Option<DeviceKey> {
    let seed = random_seed_32()?;
    let public = crate::ed25519::public_key(&seed)?;
    if public.len() != 32 {
        return None;
    }
    Some(DeviceKey { seed, public })
}

// ===================== 文件路径 =====================

/// 设备密钥文件路径。与 config::config_file() **同目录规则**、独立文件名：
/// YUDUAN_CONFIG_FILE 优先（取其父目录）；Windows 默认 %PROGRAMDATA%\YuDuan\，
/// 其它平台 $HOME/.yuduan/。返回 None 时调用方跳过持久化（仅本次会话生效）。
pub fn devicekey_file() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("YUDUAN_CONFIG_FILE") {
        if !p.trim().is_empty() {
            let cfg = PathBuf::from(p);
            let dir = cfg.parent().unwrap_or_else(|| std::path::Path::new("."));
            return Some(dir.join("agent-devicekey.json"));
        }
    }
    #[cfg(windows)]
    {
        if let Ok(pd) = std::env::var("PROGRAMDATA") {
            if !pd.trim().is_empty() {
                let mut p = PathBuf::from(pd);
                p.push("YuDuan");
                p.push("agent-devicekey.json");
                return Some(p);
            }
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
    p.push("agent-devicekey.json");
    Some(p)
}

// ===================== 落盘 / 加载 / 轮换 / 删除 =====================

/// 落盘 keypair。返回是否成功；失败仅记中文日志（不阻塞主流程）。
/// 原子写 tmp + rename；非 Windows 追加 0600 权限。
pub fn save(key: &DeviceKey) -> bool {
    let Some(path) = devicekey_file() else {
        eprintln!("[agent] 无法定位设备密钥落盘路径，设备身份仅本次会话生效");
        return false;
    };
    let seed_hex = crate::sha256::hex_encode(&key.seed);
    let (field, enc) = {
        #[cfg(windows)]
        {
            match crate::dpapi::protect(seed_hex.as_bytes()) {
                Some(blob) => (crate::sha256::hex_encode(&blob), "dpapi"),
                None => {
                    eprintln!("[agent] ⚠️ 设备密钥 DPAPI 加密失败，退回明文落盘（0600 权限防护）");
                    (seed_hex.clone(), "plain")
                }
            }
        }
        #[cfg(not(windows))]
        {
            // mac/Linux 无系统密钥库：明文 hex + 0600 文件权限为唯一防护。
            (seed_hex.clone(), "plain")
        }
    };
    let body = format!(
        "{{\"seed\":{},\"enc\":{}}}",
        crate::json_string(&field),
        crate::json_string(enc)
    );
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    let ok = std::fs::write(&tmp, body.as_bytes())
        .and_then(|_| std::fs::rename(&tmp, &path));
    if ok.is_ok() {
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(
                &path,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            );
        }
        eprintln!(
            "[agent] 已持久化设备身份密钥（{}）：{}",
            if enc == "dpapi" { "DPAPI 加密" } else { "明文 + 0600" },
            path.display()
        );
        true
    } else {
        eprintln!("[agent] ⚠️ 设备身份密钥落盘失败（本次会话仍生效）：{}", path.display());
        false
    }
}

/// 读取落盘密钥。缺失/损坏/长度非法/公钥推导失败一律返回 None（不 panic）。
pub fn load() -> Option<DeviceKey> {
    let path = devicekey_file()?;
    let data = std::fs::read_to_string(&path).ok()?;
    let v = crate::parse_json(data.as_bytes()).ok()?;
    let enc = v
        .get("enc")
        .and_then(|x| x.as_str())
        .unwrap_or("plain")
        .to_string();
    let field = v.get("seed").and_then(|x| x.as_str())?.to_string();
    let seed_hex = match enc.as_str() {
        "dpapi" => {
            #[cfg(windows)]
            {
                let blob = crate::sha256::hex_decode(&field)?;
                crate::dpapi::unprotect(&blob)?
            }
            #[cfg(not(windows))]
            {
                return None; // 非 Windows 无 DPAPI，跨平台 blob 不可解
            }
        }
        _ => field,
    };
    let seed_vec = crate::sha256::hex_decode(&seed_hex)?;
    if seed_vec.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_vec);
    let public = crate::ed25519::public_key(&seed)?;
    if public.len() != 32 {
        return None;
    }
    Some(DeviceKey { seed, public })
}

/// 加载，失败（不存在/损坏）则重新生成新 keypair 并落盘、记日志。
/// CSPRNG 失败才返回 None（此时不产出 attestation，不阻断服务）。
pub fn load_or_create() -> Option<DeviceKey> {
    if let Some(k) = load() {
        return Some(k);
    }
    if let Some(path) = devicekey_file() {
        if path.exists() {
            eprintln!("[agent] 设备身份密钥文件损坏或不可读，重新生成新 keypair：{}", path.display());
        }
    }
    let key = generate()?;
    save(&key); // 失败仅记日志，密钥本次会话仍可用
    Some(key)
}

/// 轮换：生成新 keypair 并覆盖落盘（运维显式调用；日常路径不会自动轮换）。
#[allow(dead_code)] // 生命周期 API：当前版本无自动调用点，供运维/后续接线使用
pub fn rotate() -> Option<DeviceKey> {
    let key = generate()?;
    save(&key);
    Some(key)
}

/// 删除落盘密钥（运维显式调用；**绝不**由 delete_config_file / --setup 触发）。
#[allow(dead_code)] // 生命周期 API：当前版本无自动调用点，供运维/后续接线使用
pub fn delete() {
    let Some(path) = devicekey_file() else { return };
    match std::fs::remove_file(&path) {
        Ok(()) => eprintln!("[agent] 已删除设备身份密钥 {:?}", path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("[agent] 删除设备身份密钥失败（忽略）: {}", e),
    }
}

/// 本地设备公钥 hex（32B）。文件缺失/损坏返回 None（build_register_payload 据此省略字段）。
pub fn public_key_hex() -> Option<String> {
    load().map(|k| crate::sha256::hex_encode(&k.public))
}

/// 启动期自检：确保设备上有一份可用密钥，中文日志，失败不阻断服务。
pub fn startup_self_check() {
    match load_or_create() {
        Some(k) => {
            let pk = crate::sha256::hex_encode(&k.public);
            eprintln!("[agent] 设备身份密钥自检通过（pubkey={}…）", &pk[..16.min(pk.len())]);
        }
        None => eprintln!(
            "[agent] ⚠️ 设备身份密钥不可用（CSPRNG 或落盘失败）：拒绝启用 attestation（fail-closed，绝不以可预测 seed 伪造证明）；保持原 HMAC 共享密钥链路照旧完成注册与心跳，功能不中断（不 panic、不退出）"
        ),
    }
}

// ===================== 单测 =====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 设置隔离的临时配置目录，返回 (cfg 路径, devicekey 路径)。调用方须持 test_lock。
    /// 各用例传不同 tag，目录名即不同，避免并行测试踩到同一 devicekey 文件。
    fn with_temp_dir(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("yd-dk-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("agent-config.json");
        std::env::set_var("YUDUAN_CONFIG_FILE", &cfg);
        let dk = devicekey_file().expect("应能定位 devicekey 路径");
        std::fs::remove_file(&dk).ok();
        (cfg, dk)
    }

    #[test]
    fn csprng_not_degenerate() {
        // 绝不退化到时间种子/Lcg：两次生成必须不同、非全零、长度 32、公钥 32B。
        let a = generate().expect("CSPRNG 生成失败");
        let b = generate().expect("CSPRNG 生成失败");
        assert_eq!(a.seed.len(), 32);
        assert_eq!(a.public.len(), 32);
        assert_ne!(a.seed, b.seed, "两次 seed 相同：疑似退化到确定性/时间种子");
        assert!(a.seed.iter().any(|&x| x != 0), "seed 全零：疑似未填充随机数");
        assert_eq!(a.public, crate::ed25519::public_key(&a.seed).unwrap());
    }

    /// CSPRNG 不可用必须 fail-closed：generate / load_or_create 返回 None、不产出 keypair，
    /// 且原 HMAC 共享密钥链路（旧三字段）仍可正常构造——功能不中断、attestation 不启用。
    /// 注入用 thread_local（仅本测试线程），不污染并行测试的真实 urandom 路径。
    #[cfg(not(windows))]
    #[test]
    fn csprng_unavailable_fails_closed() {
        let _g = crate::test_lock();
        let dir = std::env::temp_dir().join(format!("yd-dk-csprng-fail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // 1) 打不开 urandom（不存在路径）
        set_test_urandom(Some("/no/such/urandom/for/yuduan-test"));
        assert!(generate().is_none(), "CSPRNG 打不开必须拒绝生成密钥");

        // 2) 读不满 32 字节（短文件）→ read_exact 失败
        let short = dir.join("short-urandom");
        std::fs::write(&short, b"0123456789").unwrap(); // 仅 10 字节
        set_test_urandom(Some(short.to_str().unwrap()));
        assert!(generate().is_none(), "读不满 32 字节必须拒绝生成密钥（不补零、不退化）");

        // 3) 文件损坏 + CSPRNG 失败 → load_or_create 也不得用固定值/设备指纹兜底
        let (_cfg, dk_path) = with_temp_dir("csprng-fail");
        std::fs::write(&dk_path, "{broken json").unwrap();
        assert!(
            load_or_create().is_none(),
            "CSPRNG 失败且文件损坏时不得产出 keypair（禁止固定值/设备指纹派生兜底）"
        );

        // 4) 原 HMAC 共享密钥链路不受影响：旧三字段仍逐字节可构造（注册/心跳不中断）
        let resp = crate::secure::build_auth_response("n", "m", "t", None);
        assert_eq!(resp, r#"{"nonce":"n","mac":"m","token":"t"}"#);

        // 清理（放最后，避免提前清掉导致后续断言误判）
        set_test_urandom(None);
        std::fs::remove_file(&dk_path).ok();
        std::fs::remove_file(&short).ok();
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    /// 跨重启不重复：用两个独立临时目录模拟两次「首次启动」的 load_or_create，
    /// 两次 seed 必须不同（防用设备指纹/固定值派生导致跨重启可预测）。
    #[cfg(not(windows))]
    #[test]
    fn seed_not_repeated_across_restarts() {
        let _g = crate::test_lock();
        set_test_urandom(None); // 确保用真实 urandom，不受上例注入影响（thread_local 本已隔离）
        let (_cfg1, dk1) = with_temp_dir("restart-1");
        let first = load_or_create().expect("首次启动应生成 seed");
        let (_cfg2, dk2) = with_temp_dir("restart-2");
        let second = load_or_create().expect("第二次启动应生成 seed");
        assert_ne!(
            first.seed, second.seed,
            "跨重启 seed 重复：疑似固定值/设备指纹派生"
        );

        std::fs::remove_file(&dk1).ok();
        std::fs::remove_file(&dk2).ok();
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    #[test]
    fn devicekey_file_is_separate_from_config() {
        let _g = crate::test_lock();
        let (cfg, dk) = with_temp_dir("sep");
        assert_eq!(cfg.file_name().unwrap(), "agent-config.json");
        assert_eq!(dk.file_name().unwrap(), "agent-devicekey.json");
        assert_ne!(cfg, dk, "设备密钥必须与引导配置是不同文件");
        assert_eq!(dk.parent().unwrap(), cfg.parent().unwrap(), "两者应同目录");
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    #[test]
    fn save_load_roundtrip() {
        let _g = crate::test_lock();
        let (_cfg, dk_path) = with_temp_dir("roundtrip");
        assert!(load().is_none(), "初始应无密钥");

        let key = generate().unwrap();
        assert!(save(&key));
        let loaded = load().expect("应能读回密钥");
        assert_eq!(loaded, key, "seed 与公钥往返不一致");

        std::fs::remove_file(&dk_path).ok();
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    #[test]
    fn load_corrupt_file_is_none_and_load_or_create_regenerates() {
        let _g = crate::test_lock();
        let (_cfg, dk_path) = with_temp_dir("corrupt");
        std::fs::write(&dk_path, "{broken json").unwrap();
        assert!(load().is_none(), "损坏文件不得 panic，应返回 None");

        let regenerated = load_or_create().expect("损坏后应重新生成新 keypair");
        assert_eq!(regenerated.public.len(), 32);
        assert_eq!(load(), Some(regenerated), "重新生成后应能读回");

        std::fs::remove_file(&dk_path).ok();
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    #[test]
    fn delete_removes_devicekey_only() {
        let _g = crate::test_lock();
        let (cfg, dk_path) = with_temp_dir("delete");
        let key = generate().unwrap();
        assert!(save(&key));
        // 引导配置文件独立存在，delete() 不得碰它
        std::fs::write(&cfg, r#"{"hmacSecret":"x"}"#).unwrap();

        delete();
        assert!(load().is_none(), "设备密钥应已删除");
        assert!(cfg.exists(), "delete() 绝不能删引导配置文件");

        delete(); // 幂等：再删一次不 panic
        std::fs::remove_file(&dk_path).ok(); // 清理（delete 已删，幂等）
        std::fs::remove_file(&cfg).ok();
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    #[test]
    fn rotate_replaces_seed() {
        let _g = crate::test_lock();
        let (_cfg, dk_path) = with_temp_dir("rotate");
        let k1 = rotate().unwrap();
        let k2 = rotate().unwrap();
        assert_ne!(k1.seed, k2.seed, "轮换应产生新 seed");
        assert_eq!(load(), Some(k2), "落盘应为最新一轮密钥");
        std::fs::remove_file(&dk_path).ok();
        std::env::remove_var("YUDUAN_CONFIG_FILE");
    }

    /// seed → hex → DPAPI(protect) → hex → 反解 → seed 的 hex 层往返。
    /// 非 Windows 只验证 hex 层（DPAPI 分支由 cfg 隔离，非 Windows 编译通过即可）。
    #[test]
    fn seed_hex_roundtrip() {
        let seed = generate().unwrap().seed;
        let hex = crate::sha256::hex_encode(&seed);
        assert_eq!(hex.len(), 64);
        let back = crate::sha256::hex_decode(&hex).unwrap();
        assert_eq!(back, seed.to_vec());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_protect_unprotect_hex_roundtrip() {
        // Windows：seed hex 字符串（纯 ASCII，unprotect 的 String::from_utf8 可解）经
        // DPAPI protect → blob hex → 反解 → unprotect 还原同一 hex 字符串。
        let seed_hex = crate::sha256::hex_encode(&generate().unwrap().seed);
        let blob = crate::dpapi::protect(seed_hex.as_bytes()).expect("protect 失败");
        let blob_hex = crate::sha256::hex_encode(&blob);
        let blob_back = crate::sha256::hex_decode(&blob_hex).unwrap();
        let restored = crate::dpapi::unprotect(&blob_back).expect("unprotect 失败");
        assert_eq!(restored, seed_hex);
    }
}
