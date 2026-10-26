// Package collect 负责跨平台资产采集（M3 资产管理）。
// 设计对齐 dev/agent/INTERFACES.md 的采集接口契约：所有平台返回同一 Asset 结构，
// 平台差异被收敛在内部分支中，便于后续以 Rust 重写时一一对应。
package collect

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Asset 是归一化后的设备资产快照。
type Asset struct {
	Hostname     string
	OS           string // windows / macos / linux
	OSVersion    string
	Arch         string // x86_64 / arm64
	CPU          string
	MemoryGB     int
	DiskGB       int
	SerialNo     string
	MAC          string
	IP           string
	AgentVersion string
}

func osName() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	default:
		return runtime.GOOS
	}
}

func archName() string {
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}

func runCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Gather 采集当前主机的全部基础资产信息。
func Gather(agentVersion string) Asset {
	host, _ := os.Hostname()
	a := Asset{
		Hostname:     host,
		OS:           osName(),
		Arch:         archName(),
		AgentVersion: agentVersion,
	}
	a.OSVersion = osVersion()
	a.CPU = cpu()
	a.MemoryGB = memoryGB()
	a.DiskGB = diskGB()
	a.SerialNo = serialNo()
	a.MAC = macAddr()
	a.IP = outboundIP()
	return a
}

func osVersion() string {
	switch runtime.GOOS {
	case "darwin":
		return runCmd("sw_vers", "-productVersion")
	case "linux":
		if b, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				}
			}
		}
		return ""
	case "windows":
		// Windows 11 已移除 wmic，原生 Win32 路径优先，wmic 仅作回退。
		// 见 collect_windows.go。
		return winOSVersion()
	}
	return ""
}

func cpu() string {
	switch runtime.GOOS {
	case "darwin":
		return runCmd("sysctl", "-n", "machdep.cpu.brand_string")
	case "linux":
		if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "model name") {
					if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
		return ""
	case "windows":
		// Windows 11 已移除 wmic，原生 Win32 路径优先，wmic 仅作回退。
		return winCPU()
	}
	return ""
}

func memoryGB() int {
	switch runtime.GOOS {
	case "darwin":
		if s := runCmd("sysctl", "-n", "hw.memsize"); s != "" {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				return int(n / 1e9)
			}
		}
	case "linux":
		if b, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "MemTotal:") {
					f := strings.Fields(line)
					if len(f) >= 2 {
						if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
							return int(kb / 1e6)
						}
					}
				}
			}
		}
	case "windows":
		// Windows 11 已移除 wmic，原生 GlobalMemoryStatusEx 优先，wmic 仅作回退。
		return winMemoryGB_()
	}
	return 0
}

func diskGB() int {
	if runtime.GOOS == "windows" {
		// Windows 11 已移除 wmic，原生 GetDiskFreeSpaceExW 优先，wmic 仅作回退。
		return winDiskGB_()
	}
	if b, err := exec.Command("df", "-k", "/").Output(); err == nil {
		lines := strings.Split(string(b), "\n")
		if len(lines) >= 2 {
			f := strings.Fields(lines[1])
			if len(f) >= 2 {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return int(kb / 1e6)
				}
			}
		}
	}
	return 0
}

func serialNo() string {
	switch runtime.GOOS {
	case "darwin":
		s := runCmd("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, "IOPlatformSerialNumber") {
				f := strings.Fields(line)
				if len(f) >= 3 {
					return strings.Trim(f[len(f)-1], "\"")
				}
			}
		}
		return ""
	case "linux":
		if b, err := os.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
			return strings.TrimSpace(string(b))
		}
		return ""
	case "windows":
		// Windows 11 已移除 wmic，注册表优先，wmic 仅作回退。
		return winSerialNo()
	}
	return ""
}

func macAddr() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
			return i.HardwareAddr.String()
		}
	}
	return ""
}

func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// Load 返回 1 分钟平均负载（Windows 返回 0）。
func Load() float64 {
	switch runtime.GOOS {
	case "darwin":
		s := runCmd("sysctl", "-n", "vm.loadavg") // "{ 1.23 0.45 0.67 }"
		return parseLoad(s)
	case "linux":
		if b, err := os.ReadFile("/proc/loadavg"); err == nil {
			return parseLoad(string(b))
		}
		return 0
	default:
		return 0
	}
}

// parseLoad 从 "1.23 0.45 0.67" 或 "{ 1.23 0.45 0.67 }" 中解析 1 分钟负载。
func parseLoad(s string) float64 {
	fields := strings.Fields(s)
	for _, f := range fields {
		f = strings.Trim(f, "{}")
		if v, err := strconv.ParseFloat(f, 64); err == nil {
			return v
		}
	}
	return 0
}
