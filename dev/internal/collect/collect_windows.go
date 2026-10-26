// Windows 平台资产采集：优先使用原生 Win32 API（注册表 + 全局内存 + 卷容量），
// 仅在原生路径不可用时回退到 wmic。
//
// 背景：Windows 11 起 WMIC 已被系统移除（仅作为可选功能包 FEATURE_WMIC on Demand 提供），
// 依赖 `wmic` 的采集实现在新系统上会静默返回空值——设备台账出现 cpu/memory/disk 全空。
// 本文件用稳定可用的 Win32 API 覆盖同样字段，确保三平台同构的采集契约在 Windows 上成立。
//
// 依据：
//   - CPU 名称/序列号/系统版本：注册表（HKLM\HARDWARE\DESCRIPTION\System\...）
//   - 物理内存：GlobalMemoryStatusEx（kernel32）
//   - 磁盘容量：GetDiskFreeSpaceExW（kernel32），按固定盘逐卷累加
//
//go:build windows

package collect

import (
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// ---- 注册表读取（syscall 自带，无需外部依赖）----

const (
	hkeyLocalMachine = 0x80000002
	keyRead          = 0x20019
	regSZ            = 1
)

// regQueryString 读取 HKLM 下某子键的字符串值。
// 读取失败返回空串（调用方据此决定是否回退 wmic）。
func regQueryString(subkey, valueName string) string {
	var h syscall.Handle
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return ""
	}
	namePtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return ""
	}
	if e := syscall.RegOpenKeyEx(hkeyLocalMachine, subkeyPtr, 0, keyRead, &h); e != nil {
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

// ---- Win32 API（syscall.NewLazyDLL，延迟加载）----

var (
	modKernel32     = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMem   = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFree = modKernel32.NewProc("GetDiskFreeSpaceExW")
)

// memoryStatusEx 对应 Win32 MEMORYSTATUSEX 结构。
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// winMemoryGB 用 GlobalMemoryStatusEx 取物理内存总量（字节）→ GB。
func winMemoryGB() (int, bool) {
	var st memoryStatusEx
	st.dwLength = uint32(unsafe.Sizeof(st))
	r, _, _ := procGlobalMem.Call(uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return 0, false
	}
	return int(st.ullTotalPhys / (1024 * 1024 * 1024)), true
}

// winDiskGB 遍历固定盘累加容量（字节）→ GB。
//
// 逐卷查询而非只查系统盘：文档预期「disk」为整机磁盘容量口径。
// 盘符枚举用 A–Z 逐个探测 GetDriveTypeW（不依赖 GetLogicalDriveStringsW——
// 后者第二个参数是「字符数」而非字节数，传错会导致缓冲区越界写崩）。
func winDiskGB() (int, bool) {
	procDriveType := modKernel32.NewProc("GetDriveTypeW")
	var total uint64
	counted := 0
	for c := 'A'; c <= 'Z'; c++ {
		root, err := syscall.UTF16PtrFromString(string(c) + ":\\")
		if err != nil {
			continue
		}
		dt, _, _ := procDriveType.Call(uintptr(unsafe.Pointer(root)))
		if dt != 3 { // DRIVE_FIXED
			continue
		}
		var freeToCaller, totalBytes, totalFree uint64
		ok, _, _ := procGetDiskFree.Call(
			uintptr(unsafe.Pointer(root)),
			uintptr(unsafe.Pointer(&freeToCaller)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFree)),
		)
		if ok == 0 {
			continue
		}
		total += totalBytes
		counted++
	}
	if counted == 0 {
		return 0, false
	}
	return int(total / (1024 * 1024 * 1024)), true
}

// ---- 对外：Windows 专用采集实现（优先原生，回退 wmic）----

// winOSVersion 取系统版本。
//
// 注意：注册表 ProductName 恒为 "Windows 10 ..."（微软在 Win11 上不更新该值），
// 因此以 CurrentBuildNumber 判定实际版本（22000+ = Win11，10240~21999 = Win10）。
// DisplayVersion 给出 "23H2"/"24H2" 等版本号（Insider 预览版可能为 "Dev"）。
func winOSVersion() string {
	build := regQueryString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentBuildNumber")
	display := regQueryString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "DisplayVersion")
	edition := regQueryString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "EditionID")

	name := "Windows"
	switch {
	case build == "":
		// 无 Build 信息时回退 wmic
		if s := strings.TrimPrefix(runCmd("wmic", "os", "get", "version", "/value"), "Version="); s != "" {
			return strings.TrimSpace(s)
		}
		return ""
	case strings.Compare(build, "22000") >= 0:
		name = "Windows 11"
	case strings.Compare(build, "10240") >= 0:
		name = "Windows 10"
	default:
		name = "Windows"
	}

	parts := []string{name}
	if display != "" {
		parts = append(parts, display)
	}
	if build != "" {
		parts = append(parts, "build "+build)
	}
	if edition != "" {
		parts = append(parts, edition)
	}
	return strings.Join(parts, " ")
}

// winCPU 取 CPU 型号。优先注册表 ProcessorNameString，回退 wmic。
func winCPU() string {
	if s := regQueryString(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString"); s != "" {
		return s
	}
	return strings.TrimSpace(strings.TrimPrefix(runCmd("wmic", "cpu", "get", "name", "/value"), "Name="))
}

// winSerialNo 取整机唯一标识。
//
// 优先 BIOS 序列号（部分 OEM/虚拟化环境不写该键），缺失时回退 MachineGuid
// （Windows 安装级唯一 GUID，跨重启稳定）。再回退 wmic。
func winSerialNo() string {
	if s := regQueryString(`HARDWARE\DESCRIPTION\System\BIOS`, "SystemSerialNumber"); s != "" {
		return s
	}
	if s := regQueryString(`SOFTWARE\Microsoft\Cryptography`, "MachineGuid"); s != "" {
		return s
	}
	return strings.TrimSpace(strings.TrimPrefix(runCmd("wmic", "bios", "get", "serialnumber", "/value"), "SerialNumber="))
}

// winMemoryGB_ 供 collect.go 调用：原生 API 优先，wmic 回退。
func winMemoryGB_() int {
	if v, ok := winMemoryGB(); ok && v > 0 {
		return v
	}
	s := strings.TrimPrefix(runCmd("wmic", "OS", "get", "TotalVisibleMemorySize", "/value"), "TotalVisibleMemorySize=")
	if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
		return int(n / 1e6)
	}
	return 0
}

// winDiskGB_ 供 collect.go 调用：原生 API 优先，wmic 回退。
func winDiskGB_() int {
	if v, ok := winDiskGB(); ok && v > 0 {
		return v
	}
	s := runCmd("wmic", "logicaldisk", "get", "size", "/value")
	var total int64
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Size=") {
			if n, err := strconv.ParseInt(strings.TrimPrefix(line, "Size="), 10, 64); err == nil {
				total += n
			}
		}
	}
	return int(total / 1e9)
}
