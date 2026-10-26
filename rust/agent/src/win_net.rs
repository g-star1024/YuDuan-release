// Windows 网络信息采集：使用原生 Win32 API，不依赖 ipconfig 文本解析。
//
// 两个根因（实机踩坑）：
//  1. ipconfig 输出随系统语言本地化（中文系统标签为「物理地址」「IPv4 地址」），
//     按英文字符串匹配必然落空；
//  2. ipconfig 输出编码为 GBK/CP936，按 UTF-8 解码得到乱码，值同样被破坏。
//
// 因此改为：
//   - MAC：GetAdaptersAddresses（iphlpapi.dll）遍历适配器，取 PhysicalAddress；
//   - IP：UDP socket connect 到 8.8.8.8:80（不实际发包）+ getsockname 取源地址；
//   - 仍保留 ipconfig 解析作为兜底（英文系统上仍可工作）。

#![cfg(windows)]

use std::os::raw::c_void;

const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;
const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0008;
const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
const IF_TYPE_IEEE80211: u32 = 71;
const OPERSTATUS_UP: i32 = 1;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

const AF_UNSPEC: u32 = 0;
const AF_INET: i32 = 2;
const SOCK_DGRAM: i32 = 2;
const IPPROTO_UDP: i32 = 17;

#[repr(C)]
struct IpAdapterAddresses {
    length: u32,
    if_index: u32,
    next: *mut IpAdapterAddresses,
    adapter_name: *const u16,
    first_unicast_address: *mut c_void,
    first_anycast_address: *mut c_void,
    first_multicast_address: *mut c_void,
    physical_address: [u8; MAX_ADAPTER_ADDRESS_LENGTH],
    physical_address_length: u32,
    flags: u32,
    mtu: u32,
    if_type: u32,
    oper_status: i32,
    if_speed: u32,
    dhcp_enabled: u32,
    ipv6_if_index: u32,
    zone_indices: [u16; 256],
    first_prefix: *mut c_void,
    first_dns_server_address: *mut c_void,
    dns_suffix: *const u16,
    description: *const u16,
    friendly_name: *const u16,
}

#[link(name = "iphlpapi")]
extern "system" {
    /// 注意参数顺序：GetAdaptersAddresses(Family, Flags, Size, AdapterAddresses, Reserved)
    /// —— Family 是第 1 个参数（AF_UNSPEC），不是 Flags。
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        size: *mut u32,
        addresses: *mut c_void,
        reserved: *mut c_void,
    ) -> u32;
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSAStartup(version: u16, data: *mut c_void) -> i32;
    fn WSACleanup() -> i32;
    fn socket(af: i32, ty: i32, proto: i32) -> i32;
    fn connect(s: i32, name: *const c_void, namelen: i32) -> i32;
    fn closesocket(s: i32) -> i32;
    fn getsockname(s: i32, name: *mut c_void, namelen: *mut i32) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    /// MultiByteToWideChar：把系统 ANSI 代码页字节流转 UTF-16。
    /// 用途：中文 Windows 的 ipconfig 输出是 CP936(GBK) 编码，
    /// 用 Latin-1 回退解码会破坏中文标签（"地址" → "µµ地址µµ" 之类乱码），
    /// 交由系统自带转换表处理才正确。
    fn MultiByteToWideChar(
        codepage: u32,
        flags: u32,
        mb: *const u8,
        mb_len: i32,
        wc: *mut u16,
        wc_len: i32,
    ) -> i32;
}

const CP_ACP: u32 = 0;

/// 把 Windows 命令输出字节流解码为 Rust String。
/// 优先 UTF-8；否则按系统 ANSI 代码页（本机为 CP936/GBK）转换。
pub fn decode_console_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    unsafe {
        let need = MultiByteToWideChar(
            CP_ACP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if need > 0 {
            let mut wbuf = vec![0u16; need as usize + 1];
            let got = MultiByteToWideChar(
                CP_ACP,
                0,
                bytes.as_ptr(),
                bytes.len() as i32,
                wbuf.as_mut_ptr(),
                need,
            );
            if got > 0 {
                return String::from_utf16_lossy(&wbuf[..got as usize]);
            }
        }
        bytes.iter().map(|&b| b as char).collect()
    }
}

/// sockaddr_in：family(2) + port(2) + addr(4) + zero(8)
/// addr 显式用 [u8;4] 承载网络字节序，避免 u32 主机/网络序歧义。
#[repr(C)]
struct SockAddrIn {
    family: u16,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

/// 取本机首选出口 IPv4（UDP connect 技巧：不实际发包，只取路由选定的源地址）。
pub fn win_outbound_ip() -> String {
    unsafe {
        // WSAStartup(2.2)
        let mut wsadata = [0u8; 512];
        if WSAStartup(0x0202, wsadata.as_mut_ptr() as *mut c_void) != 0 {
            return String::new();
        }

        let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if s < 0 {
            WSACleanup();
            return String::new();
        }

        // 目标 8.8.8.8:80（仅用于让系统选路由，不发送任何数据）
        let target = SockAddrIn {
            family: AF_INET as u16,
            port: 80u16.to_be(),
            addr: [8, 8, 8, 8],
            zero: [0u8; 8],
        };

        let mut ip = String::new();
        if connect(s, &target as *const SockAddrIn as *const c_void, 16) == 0 {
            let mut local = SockAddrIn {
                family: 0,
                port: 0,
                addr: [0u8; 4],
                zero: [0u8; 8],
            };
            let mut len = 16i32;
            if getsockname(
                s,
                &mut local as *mut SockAddrIn as *mut c_void,
                &mut len,
            ) == 0
            {
                // local.addr 已是网络字节序的原样字节
                ip = format!(
                    "{}.{}.{}.{}",
                    local.addr[0], local.addr[1], local.addr[2], local.addr[3]
                );
            }
        }
        closesocket(s);
        WSACleanup();
        ip
    }
}

/// 取首个处于工作状态、且带物理地址的以太网/Wi-Fi 适配器 MAC（冒号分隔大写）。
pub fn win_mac_addr() -> String {
    unsafe {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        // 与 Go 标准库一致：Family=AF_UNSPEC，初始 size=15000，
        // 遇 ERROR_BUFFER_OVERFLOW 时按 API 回填的 size 重新分配并重试。
        let mut size: u32 = 15000;
        let mut buf: Vec<u8> = Vec::new();
        let mut attempt = 0;
        loop {
            let mut b = vec![0u8; size as usize];
            let rc = GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                &mut size,
                b.as_mut_ptr() as *mut c_void,
                std::ptr::null_mut(),
            );
            if rc == 0 {
                buf = b;
                break;
            }
            if rc != ERROR_BUFFER_OVERFLOW || attempt >= 4 {
                // 原生枚举不可用 → 回退到 ipconfig 输出值模式解析
                return win_ip_mac_pair().1;
            }
            attempt += 1;
        }

        let mut cur = buf.as_mut_ptr() as *mut IpAdapterAddresses;
        let mut fallback = String::new();
        while !cur.is_null() {
            let a = &*cur;
            if a.physical_address_length > 0
                && a.physical_address_length as usize <= MAX_ADAPTER_ADDRESS_LENGTH
            {
                let len = a.physical_address_length as usize;
                let mut parts: Vec<String> = Vec::with_capacity(len);
                for i in 0..len {
                    parts.push(format!("{:02X}", a.physical_address[i]));
                }
                let mac = parts.join(":");
                // 全零是虚拟适配器的占位值，不代表真实硬件
                if parts.iter().all(|p| p == "00") {
                    cur = a.next;
                    continue;
                }
                // 只要有物理地址的适配器都作为候选（不按 ifType 过滤：
                // 无线/以太网/USB 网卡的 ifType 分类在不同系统上不一致）
                if a.oper_status == OPERSTATUS_UP {
                    return mac;
                }
                if fallback.is_empty() {
                    fallback = mac;
                }
            }
            cur = a.next;
        }
        if fallback.is_empty() {
            win_ip_mac_pair().1
        } else {
            fallback
        }
    }
}

/// 从 ipconfig 输出中提取（IPv4, MAC）配对。
///
/// ipconfig 的标签随系统语言变化（中文为「物理地址」「IPv4 地址」），
/// 按标签匹配不可靠；但**值形态是语言无关的**：
///   - MAC：6 组十六进制，- 或 : 分隔；
///   - IPv4：点分十进制。
/// 因此按适配器块（以「适配器名:」开头为界）解析，取**同时具备 IP 与 MAC 的块**，
/// 保证 MAC 与上报的 IP 属于同一张网卡。
pub fn win_ip_mac_pair() -> (String, String) {
    // 逐适配器块收集（IP, MAC）候选，只接受**同时具备 IP 与 MAC** 的块，
    // 保证 MAC 与上报的 IP 属于同一张网卡（避免取到「已断开连接」网卡的 MAC）。
    let text = crate::run_output_gbk("ipconfig", &["/all"]);
    let mut cur_mac = String::new();
    let mut cur_ip = String::new();
    let mut found: Option<(String, String)> = None;

    for line in text.lines() {
        let trimmed = line.trim();

        // 适配器块起点：形如 "以太网适配器 以太网:" / "Ethernet adapter Ethernet:"
        if trimmed.ends_with(':') && !trimmed.contains('.') {
            // 上一块结束：若 IP 与 MAC 都拿到了，记录并继续（取第一个完整块）
            if !cur_ip.is_empty() && !cur_mac.is_empty() && found.is_none() {
                found = Some((cur_ip.clone(), cur_mac.clone()));
            }
            cur_mac.clear();
            cur_ip.clear();
            continue;
        }

        // 本机 IP 与 MAC 行都以「标签 + . . . . : 值」形式出现（标签在前、值在最后
        // 一个 ':' 之后）；而网关/掩码等行形态不同（掩码 255.x、无标签的裸值行）。
        // 因此：只接受「最后一个 ':' 之前存在非空标签」的行。
        let Some(idx) = trimmed.rfind(':') else { continue };
        let label = trimmed[..idx].trim();
        if label.is_empty() || label == "." {
            continue;
        }
        // 值可能带后缀（如中文 ipconfig 的 "192.168.0.108(首选)" / 英文 "(Preferred)"），
        // 取首个 '(' 之前的部分。
        let raw_value = trimmed[idx + 1..].trim();
        let value = raw_value.split('(').next().unwrap_or("").trim();

        // MAC 值形态
        let hex: String = value
            .chars()
            .filter(|c| c.is_ascii_hexdigit() || *c == '-' || *c == ':')
            .collect();
        let groups: Vec<&str> = hex
            .split(|c| c == '-' || c == ':')
            .filter(|s| !s.is_empty())
            .collect();
        if groups.len() == 6
            && groups
                .iter()
                .all(|g| g.len() == 2 && g.chars().all(|c| c.is_ascii_hexdigit()))
            && !groups.iter().all(|g| g.eq_ignore_ascii_case("00"))
        {
            cur_mac = groups
                .iter()
                .map(|g| g.to_ascii_uppercase())
                .collect::<Vec<String>>()
                .join(":");
            continue;
        }

        // 本机 IPv4：值形态合法、且不是子网掩码（255.x）
        if is_ipv4(value) && !value.starts_with("255.") {
            // 只取**块内第一个**此类 IP：ipconfig 的输出顺序为
            //   IPv4 地址 → 子网掩码(255.x) → 默认网关 → DHCP 服务器
            // 因此首个非掩码 IPv4 即本机地址，后续的是网关/DHCP。
            // 该判据与系统语言无关（不依赖标签文本）。
            if cur_ip.is_empty() {
                cur_ip = value.to_string();
            }
        }
    }

    // 收尾：最后一块
    if found.is_none() && !cur_ip.is_empty() && !cur_mac.is_empty() {
        found = Some((cur_ip, cur_mac));
    }

    match found {
        Some((ip, mac)) => (ip, mac),
        None => (String::new(), String::new()),
    }
}

/// 判断是否为合法点分十进制 IPv4（且不是 0.0.0.0）。
fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit())
    }) && s != "0.0.0.0"
}
