// Windows 平台合规项采集（W5-1）。
// 数据来源：注册表（HKLM/HKCU，syscall 原生 API）+ 系统命令（sc / netsh / manage-bde）。
// 采集不到的项一律回告 unknown（如「待安装补丁数」需 Windows Update COM 接口，本版不伪造）。
//
//go:build windows

package collect

import (
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"yuduan/internal/proto"
)

func platformCompliance() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	out = append(out, winPatchItems()...)
	out = append(out, winAVItems()...)
	out = append(out, winFirewallItem())
	out = append(out, winScreenItems()...)
	out = append(out, winEncryptItem())
	return out
}

// ---- 系统补丁 / 更新 ----

func winPatchItems() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	const auPolicy = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
	const auLegacy = `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update`

	// 自动检查：策略优先（NoAutoUpdate=0 表示启用自动更新），回退 AUOptions
	detail := ""
	on := false
	known := false
	if v := regQueryString(auPolicy, "NoAutoUpdate"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			on, known = n == 0, true
			detail = "HKLM\\" + auPolicy + "\\NoAutoUpdate=" + v
		}
	}
	if !known {
		if v := regQueryString(auLegacy, "AUOptions"); v != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				on, known = n >= 2, true // 2=下载前通知，3=自动下载，4=自动安装
				detail = "HKLM\\" + auLegacy + "\\AUOptions=" + v
			}
		}
	}
	if known {
		out = append(out, cPassFail(KeyPatchAutoCheck, "系统更新自动检查", proto.ComplianceCategoryPatch,
			on, cOnOff(on), "on", detail))
	} else {
		out = append(out, cUnknown(KeyPatchAutoCheck, "系统更新自动检查", proto.ComplianceCategoryPatch,
			"on", "无 WindowsUpdate 策略/AUOptions 注册表项"))
	}

	// 自动下载：AUOptions>=3
	if v := regQueryString(auLegacy, "AUOptions"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			dl := n >= 3
			out = append(out, cPassFail(KeyPatchAutoDownload, "补丁自动下载", proto.ComplianceCategoryPatch,
				dl, cOnOff(dl), "on", "AUOptions="+v))
		}
	} else {
		out = append(out, cUnknown(KeyPatchAutoDownload, "补丁自动下载", proto.ComplianceCategoryPatch,
			"on", "无 AUOptions 注册表项"))
	}

	// 待安装补丁数：需 Windows Update Agent COM 接口，本版不实现（诚实回告 unknown）
	out = append(out, cUnknown(KeyPatchPending, "待安装补丁数", proto.ComplianceCategoryPatch,
		"0", "Windows 未实现该采集项（需 WUA COM 接口；诚实回告，不伪造）"))
	return out
}

// ---- 杀毒 / EDR ----

func winAVItems() []proto.ComplianceItem {
	var installed []string
	for _, s := range Software() {
		installed = append(installed, s.Name)
	}
	// Windows Defender 是系统内置组件，未必出现在卸载清单中
	if regQueryString(`SOFTWARE\Microsoft\Windows Defender`, "InstallLocation") != "" ||
		regQueryString(`SOFTWARE\Microsoft\Windows Defender\Scan`, "DisableAntiSpyware") != "" ||
		regQueryString(`SOFTWARE\Microsoft\Windows Defender`, "ProductName") != "" {
		installed = append(installed, "Windows Defender")
	}
	// 运行中：Defender 服务状态 + 进程表
	var running []string
	if s, ok := cRun("sc", "query", "WinDefend"); ok && strings.Contains(strings.ToUpper(s), "RUNNING") {
		running = append(running, "WinDefend")
	}
	if s, ok := cRun("tasklist", "/FO", "CSV", "/NH"); ok {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			f := strings.Split(line, ",")
			if len(f) > 0 {
				running = append(running, strings.Trim(f[0], "\""))
			}
		}
	}
	return cAVItems(installed, running, "卸载清单 + Windows Defender 注册表 + sc/tasklist")
}

// ---- 防火墙 ----

func winFirewallItem() proto.ComplianceItem {
	const std = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`
	const dom = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`
	for _, sk := range []string{std, dom} {
		if v := regQueryString(sk, "EnableFirewall"); v != "" {
			if on, ok := cTruthy(v); ok {
				return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall,
					on, cOnOff(on), "on", "HKLM\\"+sk+"\\EnableFirewall="+v)
			}
		}
	}
	if s, ok := cRun("netsh", "advfirewall", "show", "allprofiles", "state"); ok {
		up := strings.ToUpper(s)
		if strings.Contains(up, "OFF") && !strings.Contains(up, "ON") {
			return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall, false, "off", "on", "netsh: 全部配置档关闭")
		}
		if strings.Contains(up, "ON") {
			return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall, true, "on", "on", "netsh: 存在开启的配置档")
		}
	}
	return cUnknown(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall, "on", "注册表与 netsh 均不可用")
}

// ---- 屏保 / 锁屏 ----

func winScreenItems() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	const desk = `Control Panel\Desktop`
	active := regQueryHKCU(desk, "ScreenSaveActive")
	timeout := regQueryHKCU(desk, "ScreenSaveTimeOut")
	secure := regQueryHKCU(desk, "ScreenSaverIsSecure")

	if on, ok := cTruthy(active); ok {
		out = append(out, cPassFail(KeyScreenSaverOn, "屏保已启用", proto.ComplianceCategoryScreensaver,
			on, cOnOff(on), "on", "HKCU\\"+desk+"\\ScreenSaveActive="+active))
	} else {
		out = append(out, cUnknown(KeyScreenSaverOn, "屏保已启用", proto.ComplianceCategoryScreensaver,
			"on", "无 ScreenSaveActive 注册表项"))
	}
	if n, err := strconv.Atoi(strings.TrimSpace(timeout)); err == nil && n > 0 {
		out = append(out, cPassFail(KeyScreenSaverIdle, "屏保超时(秒)", proto.ComplianceCategoryScreensaver,
			true, strconv.Itoa(n), "", "ScreenSaveTimeOut="+timeout+"（阈值由中枢基线判定）"))
	} else {
		out = append(out, cUnknown(KeyScreenSaverIdle, "屏保超时(秒)", proto.ComplianceCategoryScreensaver,
			"", "无 ScreenSaveTimeOut 或未启用屏保"))
	}
	if on, ok := cTruthy(secure); ok {
		out = append(out, cPassFail(KeyScreenLockOn, "屏保恢复需口令", proto.ComplianceCategoryScreensaver,
			on, cOnOff(on), "on", "HKCU\\"+desk+"\\ScreenSaverIsSecure="+secure))
	} else {
		out = append(out, cUnknown(KeyScreenLockOn, "屏保恢复需口令", proto.ComplianceCategoryScreensaver,
			"on", "无 ScreenSaverIsSecure 注册表项"))
	}
	return out
}

// ---- 磁盘加密（BitLocker）----

func winEncryptItem() proto.ComplianceItem {
	s, ok := cRun("manage-bde", "-status")
	if !ok {
		return cUnknown(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, "on", "manage-bde 不可用（家庭版或权限不足）")
	}
	up := strings.ToUpper(s)
	switch {
	case strings.Contains(up, "PROTECTION ON"):
		return cPassFail(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, true, "on", "on", "BitLocker Protection On")
	case strings.Contains(up, "PROTECTION OFF"):
		return cPassFail(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, false, "off", "on", "BitLocker Protection Off")
	}
	return cUnknown(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, "on", "manage-bde 输出无法解析")
}

// regQueryHKCU 读取 HKCU 下子键的字符串值（屏保策略位于 HKCU）。
func regQueryHKCU(subkey, valueName string) string {
	return cRegQuery(hkeyCurrentUser, subkey, valueName)
}

// cRegQuery 读取指定根键下的字符串值（syscall 原生，零依赖）。
func cRegQuery(root uintptr, subkey, valueName string) string {
	subPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return ""
	}
	namePtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return ""
	}
	var h syscall.Handle
	if e := syscall.RegOpenKeyEx(syscall.Handle(root), subPtr, 0, keyRead, &h); e != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)
	var typ uint32
	var size uint32
	if e := syscall.RegQueryValueEx(h, namePtr, nil, &typ, nil, &size); e != nil {
		return ""
	}
	if typ != regSZ || size == 0 {
		return ""
	}
	buf := make([]uint16, size/2+1)
	if e := syscall.RegQueryValueEx(h, namePtr, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); e != nil {
		return ""
	}
	return syscall.UTF16ToString(buf)
}
