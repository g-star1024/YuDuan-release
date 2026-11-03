package main

// wave5b.go —— 波次 5b 副端侧实现（W5-3 外设管控 / W5-4 网络准入）。
//
// 设计原则（与 Rust 生产副端同构）：
//  1. 尽力而为 + 诚实回告：平台不支持或执行失败的管控项一律回告 unsupported/failed
//     并附原因，严禁伪造成功（中枢据此展示真实生效状态，不制造「假合规」）。
//  2. 执行层与回执层分离：默认 YUDUAN_W5B_DRY_RUN=1（演练）——只评估可执行性并
//     回告计划值，不改动本机任何系统配置；生产需显式置 0 才真正执行。
//  3. 纯标准库、无第三方依赖；系统操作仅限平台原生工具（reg/sc/netsh/modprobe/rfkill）。

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

func init() { registerWaveAction(wave5bCommand) }

// w5bDryRun 是否为演练模式（默认 true）。
func w5bDryRun() bool { return os.Getenv("YUDUAN_W5B_DRY_RUN") != "0" }

// wave5bCommand 接管波次 5b 的指令动作；返回 true=已接管（必须自行 sendResult 回执）。
func wave5bCommand(conn *ws.Conn, c proto.CommandPayload) bool {
	switch c.Action {
	case proto.ActionPeripheralApply:
		var p proto.PeripheralApplyPayload
		if err := json.Unmarshal([]byte(c.Command), &p); err != nil {
			sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "failed",
				ExitCode: -1, OutputLog: "外设策略载荷解析失败: " + err.Error()})
			return true
		}
		res := w5bApplyPeripheral(p)
		out, _ := json.Marshal(res)
		log.Printf("[agent] 外设策略回执 policy=%s dry_run=%v 项状态=%s",
			p.PolicyID, res.DryRun, w5bItemStates(res.Items))
		sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "success", ExitCode: 0, OutputLog: string(out)})
		return true

	case proto.ActionNACApply:
		var p proto.NACApplyPayload
		if err := json.Unmarshal([]byte(c.Command), &p); err != nil {
			sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "failed",
				ExitCode: -1, OutputLog: "准入动作载荷解析失败: " + err.Error()})
			return true
		}
		res := w5bApplyNAC(p)
		out, _ := json.Marshal(res)
		log.Printf("[agent] 准入动作回执 action=%s state=%s applied=%v dry_run=%v",
			res.Action, res.State, res.Applied, res.DryRun)
		sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "success", ExitCode: 0, OutputLog: string(out)})
		return true
	}
	return false
}

// ==================== W5-3 外设管控执行层 ====================

// w5bApplyPeripheral 对三项外设逐一评估/执行，返回诚实回告。
func w5bApplyPeripheral(p proto.PeripheralApplyPayload) proto.PeripheralApplyResult {
	res := proto.PeripheralApplyResult{
		PolicyID: p.PolicyID,
		Platform: runtime.GOOS,
		DryRun:   p.DryRun || w5bDryRun(),
		Items:    make([]proto.PeripheralItemResult, 0, 3),
	}
	desired := map[string]string{
		proto.PeripheralUSBStorage: p.USBStorage,
		proto.PeripheralOptical:    p.Optical,
		proto.PeripheralBluetooth:  p.Bluetooth,
	}
	for _, item := range []string{proto.PeripheralUSBStorage, proto.PeripheralOptical, proto.PeripheralBluetooth} {
		want := desired[item]
		if want == "" {
			want = "allow" // 未指定即维持放行
		}
		res.Items = append(res.Items, w5bApplyPeripheralItem(item, want, res.DryRun))
	}
	nUnsupported := 0
	for _, it := range res.Items {
		if it.State == "unsupported" {
			nUnsupported++
		}
	}
	if nUnsupported == len(res.Items) {
		res.Message = fmt.Sprintf("平台 %s 不支持本次策略涉及的全部管控项，未做任何系统改动", runtime.GOOS)
	}
	return res
}

// w5bApplyPeripheralItem 处理单个管控项。
func w5bApplyPeripheralItem(item, desired string, dryRun bool) proto.PeripheralItemResult {
	out := proto.PeripheralItemResult{Item: item, Desired: desired}
	supported, why := w5bPeripheralSupport(item, desired)
	if !supported {
		out.State = "unsupported"
		out.Reason = why
		return out
	}
	if dryRun {
		out.State = "dry_run"
		out.Applied = desired
		out.Reason = "演练模式（YUDUAN_W5B_DRY_RUN=1）：已评估可执行性，未执行系统操作"
		return out
	}
	if err := w5bExecPeripheral(item, desired); err != nil {
		out.State = "failed"
		out.Reason = err.Error()
		return out
	}
	out.State = "applied"
	out.Applied = desired
	return out
}

// w5bPeripheralSupport 判定当前平台/取值是否可执行，不可执行时给出可读原因。
func w5bPeripheralSupport(item, desired string) (bool, string) {
	switch runtime.GOOS {
	case "windows":
		switch item {
		case proto.PeripheralUSBStorage:
			if desired == "readonly" {
				return false, "Windows 原生不提供 USB 存储只读管控（需第三方 DLP/过滤驱动），未实现"
			}
			return true, ""
		case proto.PeripheralOptical:
			return true, ""
		case proto.PeripheralBluetooth:
			return true, ""
		}
	case "linux":
		switch item {
		case proto.PeripheralUSBStorage:
			if desired == "readonly" {
				return false, "Linux 内核 usb-storage 模块无只读模式，需 udev/udisks 策略或第三方方案，未实现"
			}
			return true, ""
		case proto.PeripheralOptical:
			return true, ""
		case proto.PeripheralBluetooth:
			return true, ""
		}
	default: // darwin 及其它
		switch item {
		case proto.PeripheralUSBStorage:
			return false, "macOS 无官方接口管控 USB 大容量存储（需 MDM 配置描述文件或授权系统扩展 + root），副端不擅自改写系统"
		case proto.PeripheralOptical:
			return false, "macOS 未提供光驱管控接口（现代机型无内置光驱，外接光驱无法在系统层禁用）"
		case proto.PeripheralBluetooth:
			return false, "macOS 蓝牙电源状态受系统守护进程托管，无受支持的命令行管控接口（需 MDM），未实现"
		}
	}
	return false, "未知管控项: " + item
}

// w5bExecPeripheral 真实执行系统变更（仅 dry_run=0 时到达此处）。
func w5bExecPeripheral(item, desired string) error {
	switch runtime.GOOS {
	case "windows":
		switch item {
		case proto.PeripheralUSBStorage:
			start := "3" // allow
			if desired == "block" {
				start = "4"
			}
			return w5bRun("reg", "add", `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`,
				"/v", "Start", "/t", "REG_DWORD", "/d", start, "/f")
		case proto.PeripheralOptical:
			start := "1"
			if desired == "block" {
				start = "4"
			}
			return w5bRun("reg", "add", `HKLM\SYSTEM\CurrentControlSet\Services\cdrom`,
				"/v", "Start", "/t", "REG_DWORD", "/d", start, "/f")
		case proto.PeripheralBluetooth:
			if desired == "block" {
				if err := w5bRun("sc", "stop", "bthserv"); err != nil {
					return err
				}
				return w5bRun("sc", "config", "bthserv", "start=", "disabled")
			}
			if err := w5bRun("sc", "config", "bthserv", "start=", "auto"); err != nil {
				return err
			}
			return w5bRun("sc", "start", "bthserv")
		}
	case "linux":
		switch item {
		case proto.PeripheralUSBStorage:
			if desired == "block" {
				return w5bRun("modprobe", "-r", "usb-storage")
			}
			return w5bRun("modprobe", "usb-storage")
		case proto.PeripheralOptical:
			if desired == "block" {
				return w5bRun("modprobe", "-r", "sr_mod")
			}
			return w5bRun("modprobe", "sr_mod")
		case proto.PeripheralBluetooth:
			if desired == "block" {
				return w5bRun("rfkill", "block", "bluetooth")
			}
			return w5bRun("rfkill", "unblock", "bluetooth")
		}
	}
	return fmt.Errorf("平台 %s 不支持管控项 %s", runtime.GOOS, item)
}

// ==================== W5-4 网络准入执行层 ====================

func w5bApplyNAC(p proto.NACApplyPayload) proto.NACApplyResult {
	res := proto.NACApplyResult{
		Action:   p.Action,
		Platform: runtime.GOOS,
		DryRun:   p.DryRun || w5bDryRun(),
	}
	if p.Action == "" {
		p.Action = "allow"
		res.Action = "allow"
	}
	supported, why := w5bNACSupport(p.Action)
	if !supported {
		res.State = "unsupported"
		res.Reason = why
		res.Applied = false
		return res
	}
	if res.DryRun {
		res.State = "dry_run"
		res.Applied = false
		res.Reason = "演练模式（YUDUAN_W5B_DRY_RUN=1）：已评估可执行性，未执行系统操作"
		return res
	}
	if err := w5bExecNAC(p.Action); err != nil {
		res.State = "failed"
		res.Reason = err.Error()
		res.Applied = false
		return res
	}
	res.State = "applied"
	res.Applied = true
	if p.Action == "allow" {
		res.Reason = "已恢复默认网络策略（无生效中的限制规则）"
	} else {
		res.Reason = fmt.Sprintf("已在主机侧生效 %s；真实隔离/引流仍需网络侧 802.1X/VLAN 配合", p.Action)
	}
	return res
}

// w5bNACSupport 判定准入动作在本平台是否可执行。
func w5bNACSupport(action string) (bool, string) {
	switch runtime.GOOS {
	case "windows":
		return true, ""
	case "linux":
		return true, ""
	default: // darwin
		if action == "allow" {
			return true, ""
		}
		return false, "macOS 需通过 pfctl 加载自定义规则集，会覆盖既有 pf 配置且需 root，副端不擅自改写（建议由网络侧 802.1X 执行准入）"
	}
}

// w5bExecNAC 真实执行准入动作（仅 dry_run=0 时到达此处）。
// 隔离与阻断在主机侧等效（自建防火墙链/规则）；真实隔离（放通仅修复资源）需网络侧配合。
func w5bExecNAC(action string) error {
	switch runtime.GOOS {
	case "windows":
		if action == "allow" {
			_ = w5bRun("netsh", "advfirewall", "firewall", "delete", "rule", `name="yuduan-nac"`)
			return nil
		}
		return w5bRun("netsh", "advfirewall", "firewall", "add", "rule", `name="yuduan-nac"`,
			"dir=out", "action=block", "enable=yes")
	case "linux":
		if action == "allow" {
			_ = w5bRun("iptables", "-D", "OUTPUT", "-j", "YUDUAN_NAC")
			_ = w5bRun("iptables", "-F", "YUDUAN_NAC")
			_ = w5bRun("iptables", "-X", "YUDUAN_NAC")
			return nil
		}
		if err := w5bRun("iptables", "-N", "YUDUAN_NAC"); err != nil {
			// 链已存在时继续（非致命）
			if !strings.Contains(err.Error(), "Chain already exists") {
				return err
			}
		}
		if err := w5bRun("iptables", "-F", "YUDUAN_NAC"); err != nil {
			return err
		}
		if err := w5bRun("iptables", "-A", "YUDUAN_NAC", "-j", "DROP"); err != nil {
			return err
		}
		return w5bRun("iptables", "-I", "OUTPUT", "-j", "YUDUAN_NAC")
	}
	return fmt.Errorf("平台 %s 不支持准入动作 %s", runtime.GOOS, action)
}

// ==================== 小工具 ====================

// w5bRun 执行一条系统命令；失败时返回带 stderr 的错误（供回执说明原因）。
func w5bRun(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("%s 执行失败: %s", name, msg)
	}
	return nil
}

func w5bItemStates(items []proto.PeripheralItemResult) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, it.Item+"="+it.State)
	}
	return strings.Join(parts, ",")
}
