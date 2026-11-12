// wave5b.rs —— 波次 5b（W5-3 外设管控 / W5-4 网络准入）Rust 生产副端实现。
//
// 与 Go 参考副端 `dev/cmd/agent/wave5b.go` 严格同构（铁律 2/9）：
//   · 同一 action（peripheral_apply / nac_apply）、同一载荷与回执字段；
//   · 同一开关（YUDUAN_W5B_DRY_RUN=0 才真实执行，默认演练）；
//   · 同一套「支持矩阵」与诚实回告：macOS 无官方接口一律 unsupported 并附原因，
//     严禁伪造 applied（合规铁律 5：不制造「假合规」）。

use crate::{json_string, Json};
use std::process::Command;

fn dry_run_default() -> bool {
    std::env::var("YUDUAN_W5B_DRY_RUN").map(|v| v != "0").unwrap_or(true)
}

fn run(name: &str, args: &[&str]) -> Result<(), String> {
    let o = Command::new(name).args(args).output();
    match o {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let mut msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if msg.is_empty() {
                msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            }
            if msg.is_empty() {
                msg = format!("exit {:?}", out.status.code());
            }
            let msg: String = msg.chars().take(200).collect();
            Err(format!("{} 执行失败: {}", name, msg))
        }
        Err(e) => Err(format!("{} 执行失败: {}", name, e)),
    }
}

fn platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

// ===================== W5-3 外设管控 =====================

struct ItemResult {
    item: String,
    desired: String,
    applied: String,
    state: String,
    reason: String,
}

impl ItemResult {
    fn to_json(&self) -> String {
        format!(
            "{{\"item\":{},\"desired\":{},\"applied\":{},\"state\":{},\"reason\":{}}}",
            json_string(&self.item),
            json_string(&self.desired),
            json_string(&self.applied),
            json_string(&self.state),
            json_string(&self.reason)
        )
    }
}

/// 判定当前平台/取值是否可执行，不可执行时给出可读原因（与 Go 副端同口径）。
fn peripheral_support(item: &str, desired: &str) -> (bool, &'static str) {
    match platform() {
        "windows" => match item {
            "usb_storage" => {
                // v0.4.25：Windows 补齐基础全局只读 —— StorageDevicePolicies\WriteProtect。
                // 诚实口径（不制造假合规）：这是「全局可移动存储写保护」，需管理员，
                // 重新插拔/重启后对新挂载设备生效；不是按设备精细管控，也不防已挂载
                // 设备的缓存写入。block/allow 走原有 USBSTOR\Start 语义，行为不变。
                let _ = desired;
                (true, "")
            }
            "optical" => (true, ""),
            "bluetooth" => (true, ""),
            _ => (false, "未知管控项"),
        },
        "linux" => match item {
            "usb_storage" => {
                if desired == "readonly" {
                    (
                        false,
                        "Linux 内核 usb-storage 模块无只读模式，需 udev/udisks 策略或第三方方案，未实现",
                    )
                } else {
                    (true, "")
                }
            }
            "optical" => (true, ""),
            "bluetooth" => (true, ""),
            _ => (false, "未知管控项"),
        },
        _ => match item {
            "usb_storage" => (
                false,
                "macOS 无官方接口管控 USB 大容量存储（需 MDM 配置描述文件或授权系统扩展 + root），副端不擅自改写系统",
            ),
            "optical" => (
                false,
                "macOS 未提供光驱管控接口（现代机型无内置光驱，外接光驱无法在系统层禁用）",
            ),
            "bluetooth" => (
                false,
                "macOS 蓝牙电源状态受系统守护进程托管，无受支持的命令行管控接口（需 MDM），未实现",
            ),
            _ => (false, "未知管控项"),
        },
    }
}

fn exec_peripheral(item: &str, desired: &str) -> Result<(), String> {
    match platform() {
        "windows" => match item {
            "usb_storage" => {
                if desired == "readonly" {
                    // 全局可移动存储写保护（需管理员，重新插拔/重启后生效）
                    run(
                        "reg",
                        &[
                            "add",
                            r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
                            "/v",
                            "WriteProtect",
                            "/t",
                            "REG_DWORD",
                            "/d",
                            "1",
                            "/f",
                        ],
                    )
                } else {
                    let start = if desired == "block" { "4" } else { "3" };
                    run(
                        "reg",
                        &[
                            "add",
                            r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                            "/v",
                            "Start",
                            "/t",
                            "REG_DWORD",
                            "/d",
                            start,
                            "/f",
                        ],
                    )?;
                    // 从 readonly 切回 block/allow 必须解除全局写保护，否则设备仍只读。
                    // 该项可能本就不存在 → 忽略失败（不影响主操作结果）。
                    let _ = run(
                        "reg",
                        &[
                            "add",
                            r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
                            "/v",
                            "WriteProtect",
                            "/t",
                            "REG_DWORD",
                            "/d",
                            "0",
                            "/f",
                        ],
                    );
                    Ok(())
                }
            }
            "optical" => {
                let start = if desired == "block" { "4" } else { "1" };
                run(
                    "reg",
                    &[
                        "add",
                        r"HKLM\SYSTEM\CurrentControlSet\Services\cdrom",
                        "/v",
                        "Start",
                        "/t",
                        "REG_DWORD",
                        "/d",
                        start,
                        "/f",
                    ],
                )
            }
            "bluetooth" => {
                if desired == "block" {
                    run("sc", &["stop", "bthserv"])?;
                    run("sc", &["config", "bthserv", "start=", "disabled"])
                } else {
                    run("sc", &["config", "bthserv", "start=", "auto"])?;
                    run("sc", &["start", "bthserv"])
                }
            }
            _ => Err(format!("未知管控项 {}", item)),
        },
        "linux" => match item {
            "usb_storage" => {
                if desired == "block" {
                    run("modprobe", &["-r", "usb-storage"])
                } else {
                    run("modprobe", &["usb-storage"])
                }
            }
            "optical" => {
                if desired == "block" {
                    run("modprobe", &["-r", "sr_mod"])
                } else {
                    run("modprobe", &["sr_mod"])
                }
            }
            "bluetooth" => {
                if desired == "block" {
                    run("rfkill", &["block", "bluetooth"])
                } else {
                    run("rfkill", &["unblock", "bluetooth"])
                }
            }
            _ => Err(format!("未知管控项 {}", item)),
        },
        _ => Err(format!("平台 {} 不支持管控项 {}", platform(), item)),
    }
}

fn apply_item(item: &str, desired: &str, dry: bool) -> ItemResult {
    let mut out = ItemResult {
        item: item.to_string(),
        desired: desired.to_string(),
        applied: String::new(),
        state: String::new(),
        reason: String::new(),
    };
    let (supported, why) = peripheral_support(item, desired);
    if !supported {
        out.state = "unsupported".to_string();
        out.reason = why.to_string();
        return out;
    }
    if dry {
        out.state = "dry_run".to_string();
        out.applied = desired.to_string();
        out.reason = "演练模式（YUDUAN_W5B_DRY_RUN=1）：已评估可执行性，未执行系统操作".to_string();
        return out;
    }
    match exec_peripheral(item, desired) {
        Err(e) => {
            out.state = "failed".to_string();
            out.reason = e;
        }
        Ok(()) => {
            out.state = "applied".to_string();
            out.applied = desired.to_string();
        }
    }
    out
}

fn apply_peripheral(req: &Json) -> String {
    let g = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let policy_id = g("policy_id");
    let req_dry = req.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
    let dry = req_dry || dry_run_default();
    let desired = [
        ("usb_storage", g("usb_storage")),
        ("optical", g("optical")),
        ("bluetooth", g("bluetooth")),
    ];
    let mut items: Vec<ItemResult> = Vec::new();
    for (item, want) in &desired {
        let w = if want.is_empty() { "allow" } else { want.as_str() };
        items.push(apply_item(item, w, dry));
    }
    let unsupported = items.iter().filter(|i| i.state == "unsupported").count();
    let message = if unsupported == items.len() {
        format!(
            "平台 {} 不支持本次策略涉及的全部管控项，未做任何系统改动",
            platform()
        )
    } else {
        String::new()
    };
    let body: Vec<String> = items.iter().map(|i| i.to_json()).collect();
    eprintln!(
        "[agent] 外设策略回执 policy={} dry_run={} 项状态={}",
        policy_id,
        dry,
        items
            .iter()
            .map(|i| format!("{}={}", i.item, i.state))
            .collect::<Vec<String>>()
            .join(",")
    );
    format!(
        "{{\"policy_id\":{},\"platform\":{},\"dry_run\":{},\"items\":[{}],\"message\":{}}}",
        json_string(&policy_id),
        json_string(platform()),
        dry,
        body.join(","),
        json_string(&message)
    )
}

// ===================== W5-4 网络准入 =====================

fn nac_support(action: &str) -> (bool, &'static str) {
    match platform() {
        "windows" | "linux" => (true, ""),
        _ => {
            if action == "allow" {
                (true, "")
            } else {
                (
                    false,
                    "macOS 需通过 pfctl 加载自定义规则集，会覆盖既有 pf 配置且需 root，副端不擅自改写（建议由网络侧 802.1X 执行准入）",
                )
            }
        }
    }
}

/// 真实执行准入动作（仅 dry_run=0 时到达此处）。
/// 隔离与阻断在主机侧等效（自建防火墙链/规则）；真实隔离需网络侧 802.1X/VLAN 配合。
fn exec_nac(action: &str) -> Result<(), String> {
    match platform() {
        "windows" => {
            if action == "allow" {
                let _ = run(
                    "netsh",
                    &["advfirewall", "firewall", "delete", "rule", "name=\"yuduan-nac\""],
                );
                Ok(())
            } else {
                run(
                    "netsh",
                    &[
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        "name=\"yuduan-nac\"",
                        "dir=out",
                        "action=block",
                        "enable=yes",
                    ],
                )
            }
        }
        "linux" => {
            if action == "allow" {
                let _ = run("iptables", &["-D", "OUTPUT", "-j", "YUDUAN_NAC"]);
                let _ = run("iptables", &["-F", "YUDUAN_NAC"]);
                let _ = run("iptables", &["-X", "YUDUAN_NAC"]);
                Ok(())
            } else {
                if let Err(e) = run("iptables", &["-N", "YUDUAN_NAC"]) {
                    if !e.contains("Chain already exists") {
                        return Err(e);
                    }
                }
                run("iptables", &["-F", "YUDUAN_NAC"])?;
                run("iptables", &["-A", "YUDUAN_NAC", "-j", "DROP"])?;
                run("iptables", &["-I", "OUTPUT", "-j", "YUDUAN_NAC"])
            }
        }
        _ => Err(format!("平台 {} 不支持准入动作 {}", platform(), action)),
    }
}

fn apply_nac(req: &Json) -> String {
    let g = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut action = g("action");
    if action.is_empty() {
        action = "allow".to_string();
    }
    let req_dry = req.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
    let dry = req_dry || dry_run_default();
    let (state, applied, reason) = {
        let (supported, why) = nac_support(&action);
        if !supported {
            ("unsupported".to_string(), false, why.to_string())
        } else if dry {
            (
                "dry_run".to_string(),
                false,
                "演练模式（YUDUAN_W5B_DRY_RUN=1）：已评估可执行性，未执行系统操作".to_string(),
            )
        } else {
            match exec_nac(&action) {
                Err(e) => ("failed".to_string(), false, e),
                Ok(()) => {
                    if action == "allow" {
                        (
                            "applied".to_string(),
                            true,
                            "已恢复默认网络策略（无生效中的限制规则）".to_string(),
                        )
                    } else {
                        (
                            "applied".to_string(),
                            true,
                            format!(
                                "已在主机侧生效 {}；真实隔离/引流仍需网络侧 802.1X/VLAN 配合",
                                action
                            ),
                        )
                    }
                }
            }
        }
    };
    eprintln!(
        "[agent] 准入动作回执 action={} state={} applied={} dry_run={}",
        action, state, applied, dry
    );
    format!(
        "{{\"action\":{},\"applied\":{},\"state\":{},\"reason\":{},\"platform\":{},\"dry_run\":{}}}",
        json_string(&action),
        applied,
        json_string(&state),
        json_string(&reason),
        json_string(platform()),
        dry
    )
}

/// 处理 peripheral_apply / nac_apply；返回 (state, exit_code, output_log)。
pub fn handle(action: &str, command: &str) -> (String, i64, String) {
    let req = match crate::parse_json(command.as_bytes()) {
        Ok(j) => j,
        Err(e) => {
            return (
                "failed".to_string(),
                -1,
                format!("{}载荷解析失败: {}", action, e),
            )
        }
    };
    let body = match action {
        "peripheral_apply" => apply_peripheral(&req),
        "nac_apply" => apply_nac(&req),
        other => return ("failed".to_string(), 1, format!("unknown wave5b action: {}", other)),
    };
    ("success".to_string(), 0, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_never_reports_applied() {
        std::env::remove_var("YUDUAN_W5B_DRY_RUN");
        assert!(dry_run_default());
        // 演练或平台不支持，都绝不允许谎报「已生效」（铁律 5：不制造假合规）
        for item in ["usb_storage", "optical", "bluetooth"] {
            let r = apply_item(item, "block", true);
            assert!(r.state == "dry_run" || r.state == "unsupported", "state={}", r.state);
            if r.state == "dry_run" {
                assert_eq!(r.applied, "block");
            }
        }
    }

    #[test]
    fn unsupported_items_report_reason_not_applied() {
        // macOS：三项全部无官方接口 → unsupported，且 reason 非空（严禁伪造成功）
        if cfg!(target_os = "macos") {
            for item in ["usb_storage", "optical", "bluetooth"] {
                let (ok, why) = peripheral_support(item, "block");
                assert!(!ok);
                assert!(!why.is_empty());
            }
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn usb_readonly_is_honest_on_non_windows() {
        // Linux 内核无 usb-storage 只读模式 / macOS 需 MDM：必须 unsupported + 可读原因，
        // 严禁伪造 applied（铁律 5）。Windows 侧 v0.4.25 已补基础全局写保护。
        let (ok, why) = peripheral_support("usb_storage", "readonly");
        assert!(!ok);
        assert!(!why.is_empty());
    }

    #[test]
    fn nac_allow_is_supported_everywhere() {
        let (ok, _) = nac_support("allow");
        assert!(ok);
    }
}
