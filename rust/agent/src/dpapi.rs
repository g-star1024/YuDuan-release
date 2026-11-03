// Windows DPAPI（CryptProtectData/CryptUnprotectData）——副端本机落盘密钥加密。
//
// 用途（档位 A 设备引导）：副端经 /api/agent/claim 取得明文 HMAC 密钥后，在
// **本机**用 DPAPI LocalMachine 作用域加密后落盘 agent-config.json，启动时本机解密。
// 加密与解密必须发生在同一台机器（DPAPI 主密钥为本机级）——这正好符合"副端
// 自己加密自己解密"的模型；跨机器分发明文由 claim 的 TLS 传输保障，不依赖 DPAPI。
//
// 纯 std：通过 extern "system" 直连 crypt32.dll，无任何 crate 依赖（副端零依赖铁律）。
// 仅 Windows 编译；其它平台由 config.rs 走明文 + 0600 文件权限（ACL）。

#![cfg(windows)]

use std::os::raw::{c_void};

#[repr(C)]
struct DataBlob {
    cbData: u32,
    pbData: *mut u8,
}

#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        pDataIn: *const DataBlob,
        szDataDescr: *const u16,
        pOptionalEntropy: *const DataBlob,
        pvReserved: *mut c_void,
        pPromptStruct: *mut c_void,
        dwFlags: u32,
        pDataOut: *mut DataBlob,
    ) -> i32;
    fn CryptUnprotectData(
        pDataIn: *const DataBlob,
        ppszDataDescr: *mut *mut u16,
        pOptionalEntropy: *const DataBlob,
        pvReserved: *mut c_void,
        pPromptStruct: *mut c_void,
        dwFlags: u32,
        pDataOut: *mut DataBlob,
    ) -> i32;
}

// CRYPTPROTECT_LOCAL_MACHINE：本机任何账户可解密（服务身份 SYSTEM 与管理员一致），
// 解决"中枢以管理员加密、副端以 SYSTEM 解密"的账户上下文不一致；跨机器不可解
// （DPAPI 主密钥本机级），符合"副端本机加密本机解密"模型。
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x1;

fn blob_from(data: &[u8]) -> DataBlob {
    DataBlob {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

fn blob_to_vec(b: &DataBlob) -> Vec<u8> {
    if b.pbData.is_null() || b.cbData == 0 {
        return Vec::new();
    }
    let out = unsafe { std::slice::from_raw_parts(b.pbData, b.cbData as usize) };
    out.to_vec()
}

/// 加密明文（UTF-8 字节）为 DPAPI blob（LocalMachine 作用域）。失败返回 None。
pub fn protect(plain: &[u8]) -> Option<Vec<u8>> {
    let input = blob_from(plain);
    let mut out = DataBlob {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out,
        )
    };
    if ok == 0 {
        return None;
    }
    let v = blob_to_vec(&out);
    unsafe { local_free(out.pbData) };
    Some(v)
}

/// 解密 DPAPI blob（LocalMachine 作用域）为 UTF-8 字符串。失败返回 None。
pub fn unprotect(blob: &[u8]) -> Option<String> {
    if blob.is_empty() {
        return None;
    }
    let input = blob_from(blob);
    let mut out = DataBlob {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out,
        )
    };
    if ok == 0 {
        return None;
    }
    let v = blob_to_vec(&out);
    unsafe { local_free(out.pbData) };
    String::from_utf8(v).ok()
}

// LocalFree（kernel32）：释放 DPAPI 返回的缓冲区。
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
}

fn local_free(p: *mut u8) {
    if !p.is_null() {
        unsafe {
            LocalFree(p as *mut c_void);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_unprotect_roundtrip() {
        let secret = "yuduan-hmac-secret-roundtrip";
        let blob = protect(secret.as_bytes()).expect("protect 失败");
        assert!(!blob.is_empty());
        let back = unprotect(&blob).expect("unprotect 失败");
        assert_eq!(back, secret);
    }

    #[test]
    fn unprotect_rejects_garbage() {
        assert!(unprotect(b"not-a-dpapi-blob").is_none());
        assert!(unprotect(&[]).is_none());
    }
}
