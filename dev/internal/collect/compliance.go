// 合规项采集（W5-1，PRD 5.6 终端安全合规）。
//
// 设计要点：
//  1. 三平台实现（macOS 走 defaults/fdesetup/pmset；Windows 走注册表 + sc/netsh；
//     Linux 走 systemctl/ufw/gsettings/apt），平台不支持或命令失败一律回告
//     state=unknown，绝不伪造 pass（铁律：可观测即可信）。
//  2. 只依赖 Go 标准库与系统命令，零第三方依赖。
//  3. 采集项以稳定 Key 标识（如 firewall.enabled），中枢基线按 Key 比对。
//
// 文件划分：compliance.go（公共入口与工具）/ compliance_other.go（darwin+linux）
// / compliance_windows.go（windows）。
package collect

import (
	"os/exec"
	"strconv"
	"strings"

	"yuduan/internal/proto"
)

// 合规项 Key 常量（副端与中枢基线共用；新增项只需两端各自扩展）。
const (
	KeyPatchAutoCheck    = "patch.automatic_check"   // 系统更新自动检查
	KeyPatchAutoDownload = "patch.auto_download"     // 补丁自动下载
	KeyPatchPending      = "patch.pending_updates"   // 待安装补丁数
	KeyAVInstalled       = "antivirus.installed"     // 杀毒/EDR 安装
	KeyAVRunning         = "antivirus.running"       // 杀毒/EDR 进程运行
	KeyFirewallEnabled   = "firewall.enabled"        // 防火墙开启
	KeyScreenSaverOn     = "screensaver.enabled"     // 屏保启用
	KeyScreenSaverIdle   = "screensaver.timeout_sec" // 屏保超时（秒）
	KeyScreenLockOn      = "screensaver.lock"        // 锁屏/唤醒需口令
	KeyDiskEncryptOn     = "disk_encrypt.enabled"    // 磁盘加密
)

// Compliance 采集当前主机合规项（每次调用重新采集：合规状态随策略变化，不应进程级缓存）。
func Compliance() []proto.ComplianceItem {
	return platformCompliance()
}

// ---- 采集工具 ----

// cItem 构造一条合规项。
func cItem(key, name, category, state, actual, expected, detail string) proto.ComplianceItem {
	return proto.ComplianceItem{
		Key: key, Name: name, Category: category,
		State: state, Actual: actual, Expected: expected, Detail: detail,
	}
}

// cRun 执行命令并返回 (trimmed stdout, ok)；非零退出/不存在返回 ("", false)。
func cRun(name string, args ...string) (string, bool) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// cRunAny 依次尝试多条命令，返回首个成功的输出。
func cRunAny(cmds ...[]string) (string, bool) {
	for _, c := range cmds {
		if len(c) == 0 {
			continue
		}
		if out, ok := cRun(c[0], c[1:]...); ok && out != "" {
			return out, true
		}
	}
	return "", false
}

// cPassFail 按布尔结论构造合规项（actual 由调用方给出可读值）。
func cPassFail(key, name, category string, ok bool, actual, expected, detail string) proto.ComplianceItem {
	state := proto.ComplianceStateFail
	if ok {
		state = proto.ComplianceStatePass
	}
	return cItem(key, name, category, state, actual, expected, detail)
}

// cUnknown 构造「平台不支持/采集失败」的诚实回告项。
func cUnknown(key, name, category, expected, detail string) proto.ComplianceItem {
	return cItem(key, name, category, proto.ComplianceStateUnknown, "", expected, detail)
}

// cOnOff 布尔转 "on"/"off"（基线期望值统一用 on/off 表达开关类项）。
func cOnOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// cTruthy 解析系统命令输出的开关值：1/true/yes/on/enabled/active → true。
func cTruthy(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on", "enabled", "active", "enabled.", "running":
		return true, true
	case "0", "false", "no", "off", "disabled", "inactive", "stopped", "unknown":
		return false, true
	}
	return false, false
}

// cInt 解析整数输出。
func cInt(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return n, true
}

// avVendors 已知杀毒/EDR 厂商关键字（小写匹配；覆盖国内外主流产品）。
var avVendors = []string{
	"symantec", "norton", "mcafee", "crowdstrike", "falcon", "sentinelone", "sentinel",
	"kaspersky", "bitdefender", "eset", "nod32", "trend micro", "trendmicro", "sophos",
	"avast", "avg ", "carbon black", "cylance", "malwarebytes", "clamav", "clam",
	"microsoft defender", "windows defender", "defender", "xprotect", "jamf protect",
	"360", "qihoo", "huorong", "火绒", "江民", "瑞星", "金山毒霸", "深信服", "edr",
}

// cMatchVendor 在候选名称列表中匹配已知杀毒/EDR 厂商，返回首个命中（未命中返回 ""）。
func cMatchVendor(names []string) string {
	for _, n := range names {
		low := strings.ToLower(n)
		for _, v := range avVendors {
			if strings.Contains(low, v) {
				return n
			}
		}
	}
	return ""
}

// cAVItems 依据「已安装候选名」与「运行中进程名」产出杀毒/EDR 两个采集项。
// 未检出时回告 fail（明确「未安装」），而非 unknown（采集本身是成功的）。
func cAVItems(installed, running []string, detail string) []proto.ComplianceItem {
	hit := cMatchVendor(installed)
	if hit == "" {
		hit = cMatchVendor(running)
	}
	instOK := hit != ""
	instActual := "none"
	if instOK {
		instActual = hit
	}
	runHit := cMatchVendor(running)
	runOK := runHit != ""
	runActual := "none"
	if runOK {
		runActual = runHit
	}
	return []proto.ComplianceItem{
		cPassFail(KeyAVInstalled, "杀毒/EDR 已安装", proto.ComplianceCategoryAntivirus,
			instOK, instActual, "installed", detail),
		cPassFail(KeyAVRunning, "杀毒/EDR 运行中", proto.ComplianceCategoryAntivirus,
			runOK, runActual, "running", detail),
	}
}

// cRunningProcs 返回当前运行进程的可执行名/命令行（小写），用于 EDR 运行态判定。
func cRunningProcs() []string {
	out, ok := cRunAny(
		[]string{"ps", "-ax", "-o", "comm="},
		[]string{"ps", "-e", "-o", "comm="},
	)
	if !ok {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.LastIndex(line, "/"); i >= 0 {
			line = line[i+1:]
		}
		names = append(names, strings.ToLower(line))
	}
	return names
}
