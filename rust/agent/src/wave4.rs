// wave4.rs —— 波次 4（W4-1 文件下发/采集 / W4-3 断点续传+哈希校验）Rust 生产副端实现。
//
// 与 Go 参考副端 `dev/cmd/agent/wave4.go` 严格同构（铁律 2/9）：
//   · 同一套 action（file.push_begin / push_chunk / push_end / pull_meta / pull_chunk / abort）；
//   · 同一套允许根校验（YUDUAN_FS_WRITE_ROOT / YUDUAN_FS_PULL_ROOT，未配置即拒绝）；
//   · 同一套路径三重防护（字面 '..' → 前缀冒充 → 符号链接越界）；
//   · 同样的诚实回告（失败一律带 error 原因，绝不伪造成功）。
//
// 与波次 2 的「远控会话内文件传输」边界不同：本文件是**无人在场**的后台分发/采集，
// 因此默认关闭（未配允许根即拒绝），符合铁律 5 的最小必要与合规默认受控。

use crate::{base64_encode, json_string, Json};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

const DEFAULT_CHUNK: i64 = 256 * 1024;
const MIN_CHUNK: i64 = 4 * 1024;
const MAX_CHUNK: i64 = 2 * 1024 * 1024;
const MAX_FILE_BYTES: i64 = 512 << 20;
const MAX_PULL_ENTRIES: usize = 2000;
const MAX_PULL_BYTES: i64 = 2 << 30;
const IDLE_TTL_SECS: u64 = 30 * 60;

// ---- 全局传输状态（进程内单例；与 Go 副端的 fsPushes/fsPulls 等价）----

struct PushState {
    path: String,
    file: std::fs::File,
    size: i64,
    expect_sha: String,
    chunk: i64,
    have: i64,
    next_seq: i64,
    bits: Vec<u8>,
    last: Instant,
}

struct PullState {
    hasher: crate::sha256::Sha256,
    next: i64,
}

fn pushes() -> &'static Mutex<HashMap<String, PushState>> {
    static M: OnceLock<Mutex<HashMap<String, PushState>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pulls() -> &'static Mutex<HashMap<String, PullState>> {
    static M: OnceLock<Mutex<HashMap<String, PullState>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn write_root() -> String {
    std::env::var("YUDUAN_FS_WRITE_ROOT").unwrap_or_default().trim().to_string()
}

fn pull_root() -> String {
    std::env::var("YUDUAN_FS_PULL_ROOT").unwrap_or_default().trim().to_string()
}

// ---- 路径安全 ----

/// 拒绝显式相对路径穿越段（哪怕最终路径仍在根内，也不接受该写法本身）。
fn reject_traversal(p: &str) -> Result<(), String> {
    for seg in p.split(|c| c == '/' || c == '\\') {
        if seg == ".." {
            return Err("路径含 '..' 穿越段，已拒绝".to_string());
        }
    }
    Ok(())
}

/// child 是否严格位于 parent 之内（含相等）。
fn inside(parent: &std::path::Path, child: &std::path::Path) -> bool {
    if child == parent {
        return true;
    }
    match child.strip_prefix(parent) {
        Ok(rest) => !rest
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        Err(_) => false,
    }
}

/// 把目标路径解析到 root 内部，三重防护（字面量 / 前缀冒充 / 符号链接）。
fn resolve_in_root(root: &str, p: &str) -> Result<String, String> {
    if root.is_empty() {
        return Err("本机未配置文件允许根".to_string());
    }
    let root_abs = std::fs::canonicalize(root).unwrap_or_else(|_| std::path::PathBuf::from(root));
    reject_traversal(p)?;
    let target = if std::path::Path::new(p).is_absolute() {
        std::path::PathBuf::from(p)
    } else {
        root_abs.join(p)
    };
    let target = normalize(&target);
    if !inside(&root_abs, &target) {
        return Err(format!(
            "目标路径不在允许根 {} 内，已拒绝",
            root_abs.display()
        ));
    }
    // 符号链接穿越：能解析的最终路径必须仍在根内（目标不存在时改判其父目录）
    let real = std::fs::canonicalize(&target).unwrap_or_else(|_| match target.parent() {
        Some(par) => std::fs::canonicalize(par)
            .map(|rp| rp.join(target.file_name().unwrap_or_default()))
            .unwrap_or_else(|_| target.clone()),
        None => target.clone(),
    });
    if !inside(&root_abs, &real) {
        return Err(format!(
            "目标路径经符号链接解析后越出允许根 {}，已拒绝",
            root_abs.display()
        ));
    }
    Ok(target.to_string_lossy().to_string())
}

/// 词法归一化（去掉 . 与冗余分隔符，保留 .. 由上层判定）。
fn normalize(p: &std::path::Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => out.push(".."),
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn clamp_chunk(n: i64) -> i64 {
    match n {
        n if n <= 0 => DEFAULT_CHUNK,
        n if n < MIN_CHUNK => MIN_CHUNK,
        n if n > MAX_CHUNK => MAX_CHUNK,
        n => n,
    }
}

// ---- 位图（断点续传观测）----

fn set_bit(bits: &mut Vec<u8>, seq: i64) {
    let need = (seq / 8 + 1) as usize;
    if bits.len() < need {
        bits.resize(need, 0);
    }
    let idx = (seq / 8) as usize;
    bits[idx] |= 1u8 << (seq as u32 & 7);
}

fn bitmap_of(bits: &[u8]) -> String {
    if bits.is_empty() {
        String::new()
    } else {
        base64_encode(bits)
    }
}

fn count_bits(bits: &[u8]) -> i64 {
    let mut n = 0i64;
    for b in bits {
        for i in 0..8u32 {
            if b & (1u8 << i) != 0 {
                n += 1;
            }
        }
    }
    n
}

// ---- e2e 一次性故障注入（YUDUAN_E2E_CHUNK_FAIL_AT=N）：验证断点续传 ----

fn should_fail(seq: i64) -> bool {
    match std::env::var("YUDUAN_E2E_CHUNK_FAIL_AT") {
        Ok(v) => match v.trim().parse::<i64>() {
            Ok(n) if n >= 0 && n == seq => {
                // 触发一次即自清除：与 Go 副端 fsFailUsed 语义一致（每进程一次）
                std::env::remove_var("YUDUAN_E2E_CHUNK_FAIL_AT");
                true
            }
            _ => false,
        },
        Err(_) => false,
    }
}

fn drop_push(id: &str) {
    if let Ok(mut m) = pushes().lock() {
        m.remove(id);
    }
}

fn sweep_idle() {
    if let Ok(mut m) = pushes().lock() {
        let stale: Vec<String> = m
            .iter()
            .filter(|(_, st)| st.last.elapsed().as_secs() > IDLE_TTL_SECS)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            m.remove(&k);
            eprintln!("[agent] 清理超时未完成的下发传输 {}", k);
        }
    }
}

fn file_sha256(path: &str) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = crate::sha256::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(crate::sha256::hex_encode(&h.finalize()))
}

// ===================== 指令入口 =====================

/// 处理 file.* 指令；返回 (state, exit_code, output_log)。
pub fn handle(action: &str, command: &str) -> (String, i64, String) {
    let req = match crate::parse_json(command.as_bytes()) {
        Ok(j) => j,
        Err(_) if !command.trim().is_empty() => {
            return ("failed".to_string(), 1, "参数解析失败: 载荷不是合法 JSON".to_string())
        }
        Err(_) => return ("failed".to_string(), 1, "参数解析失败: 空载荷".to_string()),
    };
    let (body, ok) = match action {
        "file.push_begin" => handle_push_begin(&req),
        "file.push_chunk" => handle_push_chunk(&req),
        "file.push_end" => handle_push_end(&req),
        "file.pull_meta" => handle_pull_meta(&req),
        "file.pull_chunk" => handle_pull_chunk(&req),
        "file.abort" => {
            do_abort(&req);
            ("{\"ok\":true}".to_string(), true)
        }
        other => (format!("unknown wave4 action: {}", other), false),
    };
    let state = if ok { "success" } else { "failed" };
    (state.to_string(), 0, body)
}

fn gstr(j: &Json, k: &str) -> String {
    j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
}
fn gi64(j: &Json, k: &str) -> i64 {
    j.get(k).and_then(|v| v.as_i64()).unwrap_or(0)
}
fn gbool(j: &Json, k: &str) -> bool {
    j.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn fail(msg: &str) -> (String, bool) {
    (format!("{{\"error\":{}}}", json_string(msg)), false)
}

// ---- 下发 ----

fn handle_push_begin(req: &Json) -> (String, bool) {
    let root = write_root();
    if root.is_empty() {
        return fail("本机未配置文件写入根（YUDUAN_FS_WRITE_ROOT），拒绝接收下发文件");
    }
    let tid = gstr(req, "transfer_id");
    let path = gstr(req, "path");
    let size = gi64(req, "size");
    if path.is_empty() {
        return fail("缺少目标路径");
    }
    if size < 0 || size > MAX_FILE_BYTES {
        return fail(&format!("文件大小非法或超过 {}MB 上限", MAX_FILE_BYTES >> 20));
    }
    let target = match resolve_in_root(&root, &path) {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    if let Some(parent) = std::path::Path::new(&target).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return fail(&format!("创建目标目录失败: {}", e));
        }
    }
    let mut exists = 0i64;
    if let Ok(meta) = std::fs::metadata(&target) {
        if meta.is_dir() {
            return fail("目标路径是目录");
        }
        exists = meta.len() as i64;
    }
    let req_offset = gi64(req, "offset");
    let resume = gbool(req, "resume");
    let overwrite = gbool(req, "overwrite");
    let (offset, resumed) = if resume && req_offset > 0 && exists >= req_offset && req_offset <= size {
        (req_offset, true)
    } else {
        if exists > 0 && !resume && !overwrite {
            return fail("目标文件已存在（未允许覆盖/续传）");
        }
        (0i64, false)
    };
    let mut f = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&target)
    {
        Ok(f) => f,
        Err(e) => return fail(&format!("打开目标文件失败: {}", e)),
    };
    if let Err(e) = f.set_len(offset as u64) {
        return fail(&format!("截断目标文件失败: {}", e));
    }
    if let Err(e) = f.seek(SeekFrom::Start(offset as u64)) {
        return fail(&format!("定位目标文件失败: {}", e));
    }
    let chunk = clamp_chunk(gi64(req, "chunk_size"));
    sweep_idle();
    {
        let mut m = pushes().lock().unwrap_or_else(|p| p.into_inner());
        m.remove(&tid);
        m.insert(
            tid.clone(),
            PushState {
                path: target.clone(),
                file: f,
                size,
                expect_sha: gstr(req, "sha256"),
                chunk,
                have: offset,
                next_seq: if chunk > 0 { offset / chunk } else { 0 },
                bits: Vec::new(),
                last: Instant::now(),
            },
        );
    }
    eprintln!(
        "[agent] 下发握手 tid={} → {} 续传={} offset={}/{}",
        tid, target, resumed, offset, size
    );
    (
        format!(
            "{{\"ok\":true,\"transfer_id\":{},\"path\":{},\"offset\":{},\"exists\":{},\"size\":{},\"resumed\":{}}}",
            json_string(&tid),
            json_string(&target),
            offset,
            exists,
            size,
            resumed
        ),
        true,
    )
}

fn handle_push_chunk(req: &Json) -> (String, bool) {
    let tid = gstr(req, "transfer_id");
    let seq = gi64(req, "seq");
    let data = gstr(req, "data");
    let exists = pushes().lock().unwrap_or_else(|p| p.into_inner()).contains_key(&tid);
    if !exists {
        return fail("传输不存在或已结束（请先 push_begin）");
    }
    if should_fail(seq) {
        eprintln!("[agent] 注入链路中断 tid={} seq={}（e2e 断点续传场景）", tid, seq);
        drop_push(&tid);
        return fail("simulated link failure");
    }
    let raw = match crate::sha256::base64_decode(&data) {
        Some(b) => b,
        None => return fail("分片 base64 解码失败"),
    };
    let mut m = pushes().lock().unwrap_or_else(|p| p.into_inner());
    let st = match m.get_mut(&tid) {
        Some(st) => st,
        None => return fail("传输不存在或已结束（请先 push_begin）"),
    };
    if seq != st.next_seq {
        let expect = st.next_seq;
        drop_push(&tid);
        return fail(&format!(
            "分片序号不连续（期望 {} 收到 {}），已中断本次传输",
            expect, seq
        ));
    }
    if let Err(e) = st.file.write_all(&raw) {
        let msg = format!("写入失败: {}", e);
        m.remove(&tid);
        return fail(&msg);
    }
    st.have += raw.len() as i64;
    st.next_seq = seq + 1;
    st.last = Instant::now();
    set_bit(&mut st.bits, seq);
    let bitmap = bitmap_of(&st.bits);
    let (have, size, done) = (st.have, st.size, count_bits(&st.bits));
    let _ = st.file.sync_all();
    (
        format!(
            "{{\"ok\":true,\"received\":{},\"have\":{},\"size\":{},\"chunks_done\":{},\"bitmap\":{},\"eof\":{}}}",
            raw.len(),
            have,
            size,
            done,
            json_string(&bitmap),
            have >= size
        ),
        true,
    )
}

fn handle_push_end(req: &Json) -> (String, bool) {
    let tid = gstr(req, "transfer_id");
    let mut m = pushes().lock().unwrap_or_else(|p| p.into_inner());
    let st = match m.get_mut(&tid) {
        Some(st) => st,
        None => return fail("传输不存在或已结束（可能已被中断）"),
    };
    if st.have < st.size {
        return fail(&format!("文件未传完（已收 {}/{}），需续传", st.have, st.size));
    }
    if let Err(e) = st.file.sync_all() {
        return fail(&format!("落盘失败: {}", e));
    }
    let actual = match file_sha256(&st.path) {
        Ok(s) => s,
        Err(e) => return fail(&format!("整文件校验失败（无法读取落盘文件）: {}", e)),
    };
    let (have, expect, done, bits) = (st.have, st.expect_sha.clone(), count_bits(&st.bits), st.bits.clone());
    let path = st.path.clone();
    m.remove(&tid);
    if !expect.is_empty() && !expect.eq_ignore_ascii_case(&actual) {
        eprintln!("[agent] ❌ 下发文件校验失败 tid={} → {}", tid, path);
        return fail(&format!(
            "SHA-256 校验不一致（期望 {} 实得 {}）",
            expect, actual
        ));
    }
    eprintln!(
        "[agent] 下发完成 tid={} → {}（{}B sha256={}…）",
        tid,
        path,
        have,
        &actual.chars().take(16).collect::<String>()
    );
    (
        format!(
            "{{\"ok\":true,\"bytes\":{},\"sha256\":{},\"expected\":{},\"chunks_done\":{},\"bitmap\":{}}}",
            have,
            json_string(&actual),
            json_string(&expect),
            done,
            json_string(&bitmap_of(&bits))
        ),
        true,
    )
}

// ---- 采集 ----

fn handle_pull_meta(req: &Json) -> (String, bool) {
    let root = pull_root();
    if root.is_empty() {
        return fail("本机未配置文件采集根（YUDUAN_FS_PULL_ROOT），拒绝采集");
    }
    let target = match resolve_in_root(&root, &gstr(req, "path")) {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    let meta = match std::fs::metadata(&target) {
        Ok(m) => m,
        Err(e) => return fail(&format!("来源不存在: {}", e)),
    };
    let root_abs = std::fs::canonicalize(&root).unwrap_or_else(|_| std::path::PathBuf::from(&root));
    if !meta.is_dir() {
        let name = std::path::Path::new(&target)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        return (
            format!(
                "{{\"ok\":true,\"root\":{},\"entries\":[{{\"rel\":{},\"path\":{},\"size\":{}}}]}}",
                json_string(&root_abs.to_string_lossy()),
                json_string(&name),
                json_string(&target),
                meta.len()
            ),
            true,
        );
    }
    if !gbool(req, "recursive") {
        return fail("来源是目录但未声明递归采集（recursive=true）");
    }
    let mut entries = String::new();
    let mut n = 0usize;
    let mut total = 0i64;
    let mut err: Option<String> = None;
    collect_files(&target, &target, &mut entries, &mut n, &mut total, &mut err);
    if let Some(e) = err {
        return fail(&e);
    }
    eprintln!("[agent] 采集清单 path={} 条目={}", target, n);
    (
        format!(
            "{{\"ok\":true,\"root\":{},\"entries\":[{}]}}",
            json_string(&root_abs.to_string_lossy()),
            entries
        ),
        true,
    )
}

fn collect_files(
    root: &str,
    dir: &str,
    out: &mut String,
    n: &mut usize,
    total: &mut i64,
    err: &mut Option<String>,
) {
    if err.is_some() {
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return, // 单个不可读条目跳过，不阻断整次采集
    };
    for e in rd.flatten() {
        if err.is_some() {
            return;
        }
        let p = e.path();
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            collect_files(root, &p.to_string_lossy(), out, n, total, err);
            continue;
        }
        if !meta.is_file() {
            continue; // 跳过非常规文件（含软链：避免采集出允许根之外的文件）
        }
        if *n >= MAX_PULL_ENTRIES {
            *err = Some(format!("采集条目超过上限 {}", MAX_PULL_ENTRIES));
            return;
        }
        *total += meta.len() as i64;
        if *total > MAX_PULL_BYTES {
            *err = Some(format!("采集字节总量超过上限 {}MB", MAX_PULL_BYTES >> 20));
            return;
        }
        let rel = std::path::Path::new(&p)
            .strip_prefix(root)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| p.to_string_lossy().to_string());
        if *n > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"rel\":{},\"path\":{},\"size\":{}}}",
            json_string(&rel),
            json_string(&p.to_string_lossy()),
            meta.len()
        ));
        *n += 1;
    }
}

fn handle_pull_chunk(req: &Json) -> (String, bool) {
    let root = pull_root();
    if root.is_empty() {
        return fail("本机未配置文件采集根（YUDUAN_FS_PULL_ROOT），拒绝采集");
    }
    let path = gstr(req, "path");
    let target = match resolve_in_root(&root, &path) {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    let meta = match std::fs::metadata(&target) {
        Ok(m) if m.is_file() => m,
        _ => return fail("文件不存在或不是普通文件"),
    };
    let size = meta.len() as i64;
    let offset = gi64(req, "offset");
    if offset < 0 || offset > size {
        return fail("读取偏移越界");
    }
    // 哈希必须在「同一文件的连续顺序读」上累加：offset 回到 0 或不连续时重开一次摘要。
    let key = format!("{}|{}", gstr(req, "task_id"), target);
    {
        let mut m = pulls().lock().unwrap_or_else(|p| p.into_inner());
        let need_new = match m.get(&key) {
            Some(st) => offset == 0 || st.next != offset,
            None => true,
        };
        if need_new {
            m.insert(
                key.clone(),
                PullState {
                    hasher: crate::sha256::Sha256::new(),
                    next: offset,
                },
            );
        }
    }
    let mut f = match std::fs::File::open(&target) {
        Ok(f) => f,
        Err(e) => return fail(&format!("打开文件失败: {}", e)),
    };
    if let Err(e) = f.seek(SeekFrom::Start(offset as u64)) {
        return fail(&format!("定位失败: {}", e));
    }
    let mut buf = vec![0u8; clamp_chunk(gi64(req, "chunk_size")) as usize];
    let n = match f.read(&mut buf) {
        Ok(n) => n,
        Err(e) => return fail(&format!("读取失败: {}", e)),
    };
    buf.truncate(n);
    let eof = offset + n as i64 >= size;
    let mut sha = String::new();
    {
        let mut m = pulls().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(st) = m.get_mut(&key) {
            st.hasher.update(&buf);
            st.next = offset + n as i64;
        }
        if eof {
            // EOF：消费掉该文件的摘要状态（finalize 取所有权），避免串味到下一次读取
            if let Some(st) = m.remove(&key) {
                sha = crate::sha256::hex_encode(&st.hasher.finalize());
            }
        }
    }
    (
        format!(
            "{{\"ok\":true,\"data\":{},\"offset\":{},\"read\":{},\"size\":{},\"eof\":{},\"sha256\":{}}}",
            json_string(&base64_encode(&buf)),
            offset,
            n,
            size,
            eof,
            json_string(&sha)
        ),
        true,
    )
}

fn do_abort(req: &Json) {
    let tid = gstr(req, "transfer_id");
    if !tid.is_empty() {
        drop_push(&tid);
    }
    let path = gstr(req, "path");
    if !path.is_empty() {
        let mut m = pulls().lock().unwrap_or_else(|p| p.into_inner());
        let keys: Vec<String> = m.keys().filter(|k| k.ends_with(&format!("|{}", path))).cloned().collect();
        for k in keys {
            m.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_clamp_bounds() {
        assert_eq!(clamp_chunk(0), DEFAULT_CHUNK);
        assert_eq!(clamp_chunk(1), MIN_CHUNK);
        assert_eq!(clamp_chunk(999 * 1024 * 1024), MAX_CHUNK);
        assert_eq!(clamp_chunk(65536), 65536);
    }

    #[test]
    fn traversal_is_rejected() {
        assert!(reject_traversal("a/../../etc/passwd").is_err());
        assert!(reject_traversal("a\\..\\b").is_err());
        assert!(reject_traversal("a/b/c.txt").is_ok());
    }

    #[test]
    fn inside_checks_prefix_impersonation() {
        let root = std::path::Path::new("/tmp/root");
        assert!(inside(root, std::path::Path::new("/tmp/root/a/b")));
        assert!(inside(root, root));
        assert!(!inside(root, std::path::Path::new("/tmp/rootX/a")));
        assert!(!inside(root, std::path::Path::new("/tmp/roo/a")));
    }

    #[test]
    fn bitmap_counts_and_encodes() {
        let mut bits: Vec<u8> = Vec::new();
        set_bit(&mut bits, 0);
        set_bit(&mut bits, 3);
        set_bit(&mut bits, 8);
        assert_eq!(count_bits(&bits), 3);
        assert!(!bitmap_of(&bits).is_empty());
        assert_eq!(bitmap_of(&[]), "");
    }

    #[test]
    fn resolve_in_root_requires_configured_root() {
        assert!(resolve_in_root("", "a.txt").is_err());
    }
}
