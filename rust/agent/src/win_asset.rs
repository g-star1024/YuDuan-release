// Windows 平台资产采集：使用原生 Win32 API（注册表 + GlobalMemoryStatusEx +
// GetDiskFreeSpaceExW），wmic 仅作回退。
//
// 背景：Windows 11 起 WMIC 已被系统移除（仅作为可选功能包 FEATURE_WMIC on Demand
// 提供），依赖 `wmic` 的采集实现在新系统上会静默返回空值——设备台账出现
// cpu/memory/disk 全空。本模块用稳定可用的 Win32 API 覆盖同样字段，
// 保证三平台同构的采集契约在 Windows 上成立。
//
// 与 Go 参考副端（internal/collect/collect_windows.go）保持同口径。
//
// 依据：
//   - CPU 名称/序列号/系统版本：注册表（HKLM\HARDWARE\DESCRIPTION\System\...）
//   - 物理内存：GlobalMemoryStatusEx（kernel32）
//   - 磁盘容量：GetDiskFreeSpaceExW（kernel32），按固定盘逐卷累加

#![cfg(windows)]

use std::os::raw::{c_void, c_ushort};

const HKEY_LOCAL_MACHINE: isize = 0x80000002;
const KEY_READ: u32 = 0x20019;
const REG_SZ: u32 = 1;
const DRIVE_FIXED: u64 = 3;

#[repr(C)]
struct FileTime {
    low: u32,
    high: u32,
}

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(
        hkey: isize,
        subkey: *const u16,
        options: u32,
        desired: u32,
        result: *mut isize,
    ) -> i32;
    fn RegQueryValueExW(
        hkey: isize,
        name: *const u16,
        reserved: *mut u32,
        vtype: *mut u32,
        buf: *mut u8,
        buflen: *mut u32,
    ) -> i32;
    fn RegCloseKey(hkey: isize) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn GetDiskFreeSpaceExW(
        root: *const u16,
        free_to_caller: *mut u64,
        total_bytes: *mut u64,
        total_free: *mut u64,
    ) -> i32;
    fn GlobalMemoryStatusEx(buf: *mut MemoryStatusEx) -> i32;
}

#[repr(C)]
struct MemoryStatusEx {
    dw_length: u32,
    dw_memory_load: u32,
    ull_total_phys: u64,
    ull_avail_phys: u64,
    ull_total_page_file: u64,
    ull_avail_page_file: u64,
    ull_total_virtual: u64,
    ull_avail_virtual: u64,
    ull_avail_extended_virtual: u64,
}

/// UTF-16 字符串转 Rust String（遇到 NUL 截断）。
/// 用标准 UTF-16 解码（from_utf16_lossy）：注册表值可能含非 ASCII
///（如中文 OEM 型号），按 u8 截断会得到乱码。
fn utf16_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// 读 HKLM 下某子键的字符串值；失败返回空串。
fn reg_query_string(subkey: &str, value_name: &str) -> String {
    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let name_w: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut hkey: isize = 0;
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return String::new();
        }

        let mut vtype: u32 = 0;
        let mut size: u32 = 0;
        if RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            std::ptr::null_mut(),
            &mut vtype,
            std::ptr::null_mut(),
            &mut size,
        ) != 0
        {
            RegCloseKey(hkey);
            return String::new();
        }
        if vtype != REG_SZ || size == 0 {
            RegCloseKey(hkey);
            return String::new();
        }

        let mut buf = vec![0u16; (size / 2) as usize + 1];
        let mut sz = size;
        let rc = RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            std::ptr::null_mut(),
            &mut vtype,
            buf.as_mut_ptr() as *mut u8,
            &mut sz,
        );
        RegCloseKey(hkey);
        if rc != 0 {
            return String::new();
        }
        utf16_to_string(&buf)
    }
}

/// 物理内存总量（GB）。
fn win_memory_gb() -> i64 {
    unsafe {
        let mut st = MemoryStatusEx {
            dw_length: std::mem::size_of::<MemoryStatusEx>() as u32,
            dw_memory_load: 0,
            ull_total_phys: 0,
            ull_avail_phys: 0,
            ull_total_page_file: 0,
            ull_avail_page_file: 0,
            ull_total_virtual: 0,
            ull_avail_virtual: 0,
            ull_avail_extended_virtual: 0,
        };
        if GlobalMemoryStatusEx(&mut st) == 0 {
            return 0;
        }
        (st.ull_total_phys / (1024 * 1024 * 1024)) as i64
    }
}

/// 固定盘总容量（GB）。
///
/// 盘符枚举用 A–Z 逐个探测 GetDriveTypeW（不依赖 GetLogicalDriveStringsW——
/// 后者第二个参数是「字符数」而非字节数，传错会越界写崩）。
fn win_disk_gb() -> i64 {
    let mut total: u64 = 0;
    let mut counted = 0u32;
    for c in b'A'..=b'Z' {
        let root_w: Vec<u16> = [c as u16, b':' as u16, b'\\' as u16, 0].to_vec();
        unsafe {
            if GetDriveTypeW(root_w.as_ptr()) as u64 != DRIVE_FIXED {
                continue;
            }
            let mut free_to_caller: u64 = 0;
            let mut total_bytes: u64 = 0;
            let mut total_free: u64 = 0;
            if GetDiskFreeSpaceExW(
                root_w.as_ptr(),
                &mut free_to_caller,
                &mut total_bytes,
                &mut total_free,
            ) == 0
            {
                continue;
            }
            total += total_bytes;
            counted += 1;
        }
    }
    if counted == 0 {
        return 0;
    }
    (total / (1024 * 1024 * 1024)) as i64
}

/// 系统版本。
///
/// 注意：注册表 ProductName 恒为 "Windows 10 ..."（微软在 Win11 上不更新该值），
/// 因此以 CurrentBuildNumber 判定实际版本（22000+ = Win11，10240~21999 = Win10）。
pub fn win_os_version() -> String {
    let build = reg_query_string(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuildNumber",
    );
    let display = reg_query_string(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "DisplayVersion",
    );
    let edition = reg_query_string(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "EditionID",
    );

    if build.is_empty() {
        // 无 Build 信息时回退 wmic
        let out = crate::run_output("wmic", &["os", "get", "version"]);
        return out
            .lines()
            .find(|l| l.trim().starts_with("Version="))
            .map(|l| l.trim().trim_start_matches("Version=").trim().to_string())
            .unwrap_or_default();
    }

    let name = if build.as_str() >= "22000" {
        "Windows 11"
    } else if build.as_str() >= "10240" {
        "Windows 10"
    } else {
        "Windows"
    };

    let mut parts: Vec<String> = vec![name.to_string()];
    if !display.is_empty() {
        parts.push(display);
    }
    parts.push(format!("build {}", build));
    if !edition.is_empty() {
        parts.push(edition);
    }
    parts.join(" ")
}

/// CPU 型号（注册表 ProcessorNameString，回退 wmic）。
pub fn win_cpu() -> String {
    let s = reg_query_string(
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "ProcessorNameString",
    );
    if !s.is_empty() {
        return s;
    }
    let out = crate::run_output("wmic", &["cpu", "get", "name"]);
    out.lines()
        .nth(1)
        .map(|l| l.trim().to_string())
        .unwrap_or_default()
}

/// 整机唯一标识：BIOS 序列号 → MachineGuid → wmic。
pub fn win_serial_no() -> String {
    let s = reg_query_string(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemSerialNumber");
    if !s.is_empty() {
        return s;
    }
    let g = reg_query_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid");
    if !g.is_empty() {
        return g;
    }
    let out = crate::run_output("wmic", &["bios", "get", "serialnumber"]);
    out.lines()
        .nth(1)
        .map(|l| l.trim().to_string())
        .unwrap_or_default()
}

/// 内存（GB）：原生 API 优先，wmic 回退。
pub fn win_memory_gb_() -> i64 {
    let v = win_memory_gb();
    if v > 0 {
        return v;
    }
    let out = crate::run_output("wmic", &["computersystem", "get", "totalphysicalmemory"]);
    out.lines()
        .nth(1)
        .and_then(|l| l.trim().parse::<f64>().ok())
        .map(|b| (b / 1e9).round() as i64)
        .unwrap_or(0)
}

/// 磁盘（GB）：原生 API 优先，wmic 回退。
pub fn win_disk_gb_() -> i64 {
    let v = win_disk_gb();
    if v > 0 {
        return v;
    }
    let out = crate::run_output("wmic", &["logicaldisk", "get", "size"]);
    let mut total = 0f64;
    for line in out.lines().skip(1) {
        if let Ok(v) = line.trim().parse::<f64>() {
            if v > 0.0 {
                total += v;
            }
        }
    }
    (total / 1e9).round() as i64
}

// 抑制未使用警告：保留类型供后续扩展（FileTime / c_ushort / c_void 未直接使用）。
#[allow(dead_code)]
type UnusedWinTypes = (FileTime, c_ushort, c_void);
