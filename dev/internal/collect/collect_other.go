// 非 Windows 平台的采集实现占位。
//
// Windows 的原生采集（注册表 + Win32 API）位于 collect_windows.go，
// 由 build tag 隔离；其余平台走 collect.go 内的 unix 分支。
// 此文件仅提供同名桩函数，保证 collect.go 无需平台条件编译即可引用。
//
//go:build !windows

package collect

// winOSVersion 非 Windows 平台恒为空（unix 分支自行实现）。
func winOSVersion() string { return "" }

// winCPU 非 Windows 平台恒为空（unix 分支自行实现）。
func winCPU() string { return "" }

// winSerialNo 非 Windows 平台恒为空（unix 分支自行实现）。
func winSerialNo() string { return "" }

// winMemoryGB_ 非 Windows 平台恒为 0（unix 分支自行实现）。
func winMemoryGB_() int { return 0 }

// winDiskGB_ 非 Windows 平台恒为 0（unix 分支自行实现）。
func winDiskGB_() int { return 0 }
