// Windows 平台软件清单采集（W1-1，PRD 5.1 B2）。
// 枚举注册表 Uninstall 三根键（HKLM 原生 / WOW6432Node 32 位 / HKCU），
// 读取 DisplayName / DisplayVersion / Publisher / InstallLocation。
// 仅依赖 syscall 自带注册表 API，零外部依赖。
//
//go:build windows

package collect

import (
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"yuduan/internal/proto"
)

const (
	hkeyCurrentUser = 0x80000001
)

var uninstallRoots = []struct {
	root uintptr
	sub  string
	src  string
}{
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "registry:hklm"},
	{hkeyLocalMachine, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "registry:hklm32"},
	{hkeyCurrentUser, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, "registry:hkcu"},
}

func platformSoftware() []proto.InstalledSoftware {
	seen := map[string]bool{}
	var out []proto.InstalledSoftware
	for _, r := range uninstallRoots {
		appendUninstallRoot(r.root, r.sub, r.src, &out, seen)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// appendUninstallRoot 枚举一个 Uninstall 根键下的所有子键并读取卸载项。
func appendUninstallRoot(root uintptr, sub, src string, out *[]proto.InstalledSoftware, seen map[string]bool) {
	subPtr, err := syscall.UTF16PtrFromString(sub)
	if err != nil {
		return
	}
	var h syscall.Handle
	if e := syscall.RegOpenKeyEx(syscall.Handle(root), subPtr, 0, keyRead, &h); e != nil {
		return
	}
	defer syscall.RegCloseKey(h)

	for i := uint32(0); ; i++ {
		var nameBuf [256]uint16
		nameLen := uint32(len(nameBuf))
		// RegEnumKeyEx 返回 ERROR_NO_MORE_ITEMS=259 时结束。
		//（Go 1.27 起 syscall 不再导出该常量，用字面 Errno(259) 保持零依赖且新旧版本均可编译。）
		if e := syscall.RegEnumKeyEx(h, i, &nameBuf[0], &nameLen, nil, nil, nil, nil); e != nil {
			if e == syscall.Errno(259) {
				return
			}
			continue
		}
		subkeyName := syscall.UTF16ToString(nameBuf[:nameLen])
		displayName := regQueryAny(h, subkeyName, "DisplayName")
		if strings.TrimSpace(displayName) == "" {
			continue // 空 DisplayName = 系统补丁/框架，非用户可见应用
		}
		key := strings.ToLower(displayName)
		if seen[key] {
			continue
		}
		seen[key] = true
		*out = append(*out, proto.InstalledSoftware{
			Name:      displayName,
			Version:   regQueryAny(h, subkeyName, "DisplayVersion"),
			Source:    src,
			Publisher: regQueryAny(h, subkeyName, "Publisher"),
		})
	}
}

// regQueryAny 读取指定根键下子键 subkeyName 的字符串值 valueName。
// 复用 regQueryString 的语义，但允许传入任意根句柄（RegOpenKeyEx 打开子键）。
func regQueryAny(parent syscall.Handle, subkeyName, valueName string) string {
	subPtr, err := syscall.UTF16PtrFromString(subkeyName)
	if err != nil {
		return ""
	}
	namePtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return ""
	}
	var h syscall.Handle
	if e := syscall.RegOpenKeyEx(parent, subPtr, 0, keyRead, &h); e != nil {
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
