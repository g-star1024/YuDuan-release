// 非 Windows 平台的合规项采集（macOS / Linux）。
//
//go:build !windows

package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"yuduan/internal/proto"
)

func platformCompliance() []proto.ComplianceItem {
	if runtime.GOOS == "darwin" {
		return darwinCompliance()
	}
	return linuxCompliance()
}

// ---- macOS ----

const suDomain = "/Library/Preferences/com.apple.SoftwareUpdate"

func darwinCompliance() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	out = append(out, darwinPatchItems()...)
	out = append(out, darwinAVItems()...)
	out = append(out, darwinFirewallItem())
	out = append(out, darwinScreenItems()...)
	out = append(out, darwinEncryptItem())
	return out
}

// darwinPatchItems 采集系统补丁/更新状态（自动检查 / 自动下载 / 待安装数量）。
func darwinPatchItems() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	// 自动检查更新
	if s, ok := cRun("defaults", "read", suDomain, "AutomaticCheckEnabled"); ok {
		if on, ok2 := cTruthy(s); ok2 {
			out = append(out, cPassFail(KeyPatchAutoCheck, "系统更新自动检查", proto.ComplianceCategoryPatch,
				on, cOnOff(on), "on", "defaults read "+suDomain+" AutomaticCheckEnabled="+s))
		}
	} else {
		out = append(out, cUnknown(KeyPatchAutoCheck, "系统更新自动检查", proto.ComplianceCategoryPatch,
			"on", "defaults 读取失败（无偏好项或权限不足）"))
	}
	// 自动下载补丁（键名随系统版本不同，两种都试）
	if s, ok := cRunAny(
		[]string{"defaults", "read", suDomain, "AutomaticDownload"},
		[]string{"defaults", "read", suDomain, "AutomaticDownloadEnabled"},
	); ok {
		if on, ok2 := cTruthy(s); ok2 {
			out = append(out, cPassFail(KeyPatchAutoDownload, "补丁自动下载", proto.ComplianceCategoryPatch,
				on, cOnOff(on), "on", "AutomaticDownload="+s))
		}
	} else {
		out = append(out, cUnknown(KeyPatchAutoDownload, "补丁自动下载", proto.ComplianceCategoryPatch,
			"on", "无 AutomaticDownload 偏好项"))
	}
	// 待安装补丁数（最近一次检查的结论：LastUpdatesAvailable）
	if s, ok := cRun("defaults", "read", suDomain, "LastUpdatesAvailable"); ok {
		if n, ok2 := cInt(s); ok2 {
			out = append(out, cPassFail(KeyPatchPending, "待安装补丁数", proto.ComplianceCategoryPatch,
				n == 0, strconv.Itoa(n), "0", "LastUpdatesAvailable="+s))
		}
	} else {
		out = append(out, cUnknown(KeyPatchPending, "待安装补丁数", proto.ComplianceCategoryPatch,
			"0", "无 LastUpdatesAvailable 偏好项（未执行过更新检查）"))
	}
	return out
}

// darwinAVItems 采集杀毒/EDR 安装与运行态：扫 /Applications 与 /Library/Application Support。
func darwinAVItems() []proto.ComplianceItem {
	var installed []string
	dirs := []string{"/Applications", "/System/Applications", "/Library/Application Support"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			installed = append(installed, strings.TrimSuffix(e.Name(), ".app"))
		}
	}
	return cAVItems(installed, cRunningProcs(), "扫描 /Applications + /Library/Application Support + 进程表")
}

// darwinFirewallItem 采集应用层防火墙开关（alf globalstate：0=关，1/2=开）。
func darwinFirewallItem() proto.ComplianceItem {
	const detail = "defaults read /Library/Preferences/com.apple.alf globalstate"
	if s, ok := cRun("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"); ok {
		if n, ok2 := cInt(s); ok2 {
			return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall,
				n >= 1, cOnOff(n >= 1), "on", detail+"="+s)
		}
	}
	if s, ok := cRun("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); ok {
		low := strings.ToLower(s)
		if strings.Contains(low, "state = 0") || strings.Contains(low, "disabled") {
			return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall,
				false, "off", "on", "socketfilterfw: "+s)
		}
		if strings.Contains(low, "state = 1") || strings.Contains(low, "state = 2") || strings.Contains(low, "enabled") {
			return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall,
				true, "on", "on", "socketfilterfw: "+s)
		}
	}
	return cUnknown(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall, "on", "alf/socketfilterfw 均不可用")
}

// darwinScreenItems 采集屏保启用/超时/锁屏口令。
func darwinScreenItems() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	idle := -1
	if s, ok := cRunAny(
		[]string{"defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime"},
		[]string{"defaults", "read", "com.apple.screensaver", "idleTime"},
	); ok {
		if n, ok2 := cInt(s); ok2 {
			idle = n
		}
	}
	if idle >= 0 {
		out = append(out, cPassFail(KeyScreenSaverOn, "屏保已启用", proto.ComplianceCategoryScreensaver,
			idle > 0, cOnOff(idle > 0), "on", "idleTime="+strconv.Itoa(idle)+"s"))
		if idle > 0 {
			out = append(out, cPassFail(KeyScreenSaverIdle, "屏保超时(秒)", proto.ComplianceCategoryScreensaver,
				true, strconv.Itoa(idle), "", "idleTime="+strconv.Itoa(idle)+"s（阈值由中枢基线判定）"))
		} else {
			out = append(out, cUnknown(KeyScreenSaverIdle, "屏保超时(秒)", proto.ComplianceCategoryScreensaver,
				"", "屏保未启用（idleTime=0）"))
		}
	} else {
		out = append(out,
			cUnknown(KeyScreenSaverOn, "屏保已启用", proto.ComplianceCategoryScreensaver, "on", "无 idleTime 偏好项"),
			cUnknown(KeyScreenSaverIdle, "屏保超时(秒)", proto.ComplianceCategoryScreensaver, "", "无 idleTime 偏好项"))
	}
	// 唤醒/屏保恢复是否要求口令
	if s, ok := cRunAny(
		[]string{"defaults", "read", "com.apple.screensaver", "askForPassword"},
		[]string{"defaults", "-currentHost", "read", "com.apple.screensaver", "askForPassword"},
	); ok {
		if on, ok2 := cTruthy(s); ok2 {
			out = append(out, cPassFail(KeyScreenLockOn, "屏保恢复需口令", proto.ComplianceCategoryScreensaver,
				on, cOnOff(on), "on", "askForPassword="+s))
		}
	} else {
		out = append(out, cUnknown(KeyScreenLockOn, "屏保恢复需口令", proto.ComplianceCategoryScreensaver,
			"on", "无 askForPassword 偏好项"))
	}
	return out
}

// darwinEncryptItem 采集 FileVault 全盘加密状态。
func darwinEncryptItem() proto.ComplianceItem {
	s, ok := cRun("fdesetup", "status")
	if !ok {
		return cUnknown(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, "on", "fdesetup 不可用")
	}
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "filevault is on"):
		return cPassFail(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, true, "on", "on", s)
	case strings.Contains(low, "filevault is off"):
		return cPassFail(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, false, "off", "on", s)
	}
	return cUnknown(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, "on", "fdesetup 输出无法解析: "+s)
}

// ---- Linux ----

func linuxCompliance() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	out = append(out, linuxPatchItems()...)
	out = append(out, linuxAVItems()...)
	out = append(out, linuxFirewallItem())
	out = append(out, linuxScreenItems()...)
	out = append(out, linuxEncryptItem())
	return out
}

func linuxPatchItems() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	// 待安装补丁数：apt（Debian 系）优先
	if s, ok := cRun("sh", "-c", "apt list --upgradable 2>/dev/null | tail -n +2 | grep -c upgradable"); ok {
		if n, ok2 := cInt(s); ok2 {
			out = append(out, cPassFail(KeyPatchPending, "待安装补丁数", proto.ComplianceCategoryPatch,
				n == 0, strconv.Itoa(n), "0", "apt list --upgradable"))
		}
	} else {
		out = append(out, cUnknown(KeyPatchPending, "待安装补丁数", proto.ComplianceCategoryPatch,
			"0", "apt 不可用（仅支持 Debian 系；RPM 系待扩展）"))
	}
	// 自动更新：unattended-upgrades / dnf-automatic
	if s, ok := cRunAny(
		[]string{"systemctl", "is-enabled", "unattended-upgrades"},
		[]string{"systemctl", "is-enabled", "dnf-automatic"},
	); ok {
		on := strings.TrimSpace(s) == "enabled"
		out = append(out, cPassFail(KeyPatchAutoCheck, "系统更新自动检查", proto.ComplianceCategoryPatch,
			on, cOnOff(on), "on", "systemctl is-enabled="+s))
	} else {
		out = append(out, cUnknown(KeyPatchAutoCheck, "系统更新自动检查", proto.ComplianceCategoryPatch,
			"on", "未检测到 unattended-upgrades/dnf-automatic"))
	}
	out = append(out, cUnknown(KeyPatchAutoDownload, "补丁自动下载", proto.ComplianceCategoryPatch,
		"on", "Linux 未实现该采集项（诚实回告，不伪造）"))
	return out
}

func linuxAVItems() []proto.ComplianceItem {
	var installed []string
	if s, ok := cRun("sh", "-c", "systemctl list-units --all --no-legend 2>/dev/null | cut -d' ' -f1"); ok {
		for _, line := range strings.Split(s, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				installed = append(installed, line)
			}
		}
	}
	return cAVItems(installed, cRunningProcs(), "扫描 systemd 单元 + 进程表")
}

func linuxFirewallItem() proto.ComplianceItem {
	if s, ok := cRun("ufw", "status"); ok {
		low := strings.ToLower(s)
		if strings.Contains(low, "status: active") {
			return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall, true, "on", "on", "ufw status: active")
		}
		if strings.Contains(low, "status: inactive") {
			return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall, false, "off", "on", "ufw status: inactive")
		}
	}
	if s, ok := cRun("systemctl", "is-active", "firewalld"); ok {
		on := strings.TrimSpace(s) == "active"
		return cPassFail(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall, on, cOnOff(on), "on", "firewalld="+s)
	}
	return cUnknown(KeyFirewallEnabled, "防火墙已开启", proto.ComplianceCategoryFirewall, "on", "ufw/firewalld 均不可用")
}

func linuxScreenItems() []proto.ComplianceItem {
	var out []proto.ComplianceItem
	if _, err := exec.LookPath("gsettings"); err != nil {
		out = append(out,
			cUnknown(KeyScreenSaverOn, "屏保已启用", proto.ComplianceCategoryScreensaver, "on", "无 gsettings（非 GNOME/无图形会话）"),
			cUnknown(KeyScreenSaverIdle, "屏保超时(秒)", proto.ComplianceCategoryScreensaver, "", "无 gsettings"),
			cUnknown(KeyScreenLockOn, "屏保恢复需口令", proto.ComplianceCategoryScreensaver, "on", "无 gsettings"))
		return out
	}
	if s, ok := cRun("gsettings", "get", "org.gnome.desktop.session", "idle-delay"); ok {
		// 形如 "uint32 600"
		f := strings.Fields(s)
		if n, err := strconv.Atoi(f[len(f)-1]); err == nil {
			out = append(out,
				cPassFail(KeyScreenSaverOn, "屏保已启用", proto.ComplianceCategoryScreensaver, n > 0, cOnOff(n > 0), "on", "idle-delay="+s),
				cPassFail(KeyScreenSaverIdle, "屏保超时(秒)", proto.ComplianceCategoryScreensaver, true, strconv.Itoa(n), "", "idle-delay="+s+"（阈值由中枢基线判定）"))
		}
	} else {
		out = append(out,
			cUnknown(KeyScreenSaverOn, "屏保已启用", proto.ComplianceCategoryScreensaver, "on", "idle-delay 不可读"),
			cUnknown(KeyScreenSaverIdle, "屏保超时(秒)", proto.ComplianceCategoryScreensaver, "", "idle-delay 不可读"))
	}
	if s, ok := cRun("gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"); ok {
		if on, ok2 := cTruthy(s); ok2 {
			out = append(out, cPassFail(KeyScreenLockOn, "屏保恢复需口令", proto.ComplianceCategoryScreensaver, on, cOnOff(on), "on", "lock-enabled="+s))
		}
	} else {
		out = append(out, cUnknown(KeyScreenLockOn, "屏保恢复需口令", proto.ComplianceCategoryScreensaver, "on", "lock-enabled 不可读"))
	}
	return out
}

func linuxEncryptItem() proto.ComplianceItem {
	if b, err := os.ReadFile("/etc/crypttab"); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		return cPassFail(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, true, "on", "on", "/etc/crypttab 非空")
	}
	if s, ok := cRun("sh", "-c", "lsblk -o TYPE 2>/dev/null | grep -c crypt"); ok {
		if n, ok2 := cInt(s); ok2 && n > 0 {
			return cPassFail(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, true, "on", "on", "lsblk 检测到 crypt 设备")
		}
		return cUnknown(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, "on", "未检测到 crypt 设备/容器")
	}
	return cUnknown(KeyDiskEncryptOn, "磁盘加密已开启", proto.ComplianceCategoryEncrypt, "on", "lsblk 不可用")
}
